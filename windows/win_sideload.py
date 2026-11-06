"""win_sideload.py — 极载 ZEEload · Windows 版侧载工具（beta）

原理与 macOS 版一致：
  车机 → Windows 热点 → 本工具把 443 流量重定向到本地 → mitmproxy 解密 →
  注入假更新 + 替换下载内容 → 车机商店把目标 APK 当更新装上。

Windows 没有 pf，透明转发用 WinDivert（pydivert）实现：
  1. 只拦截「进入本机」的发往 443 的包，把目的地址改写成「热点网卡 IP:18081」，并记录原始目的地址；
  2. 本地 SNI 分流器（18081）读出客户端要访问的域名，用 HTTP CONNECT 喂给 mitmproxy；
  3. 分流器发出的回程包把源地址改回原始目的地址，客户端无感。

依赖（版本有硬性要求）：
  Python >= 3.12（实测 3.12.7）
  mitmproxy >= 12.3（实测 12.3.1，--emudhra 从 12.3 起提供）
  pydivert >= 4.0（实测 4.0.1）
  必须以管理员身份运行（WinDivert 需要加载驱动）

用法：
  python win_sideload.py --apk "C:\\path\\app.apk"
  python win_sideload.py --apk app.apk --pkg com.zeekr.media.podcast
  python win_sideload.py --apk app.apk --proxy-only   # 只起代理，不做透明重定向
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time

IS_WINDOWS = sys.platform.startswith("win")
FROZEN = bool(getattr(sys, "frozen", False))
MIN_PY = (3, 12)          # mitmproxy 12.3+ 要求 Python >= 3.12
MIN_MITM = (12, 3)        # --emudhra 从 mitmproxy 12.3 开始提供
SHIM_PORT = 18081
PROXY_PORT = 18080

def resource_path(rel: str) -> str:
    """打包成 exe 后从 _MEIPASS 取资源，源码运行时从脚本目录取。"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


ADDON = resource_path(os.path.join("addons", "zeekr_log.py"))


def if_index_for_ip(ip: str) -> int:
    """取某个本机 IPv4 地址所属网卡的接口索引（注入包时要填对 IfIdx）。

    用 GetIpAddrTable 而不是 WMI，免依赖、免 COM。
    """
    if not IS_WINDOWS:
        return 0
    import ctypes
    import struct

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [
            ("dwAddr", ctypes.c_uint32),
            ("dwIndex", ctypes.c_uint32),
            ("dwMask", ctypes.c_uint32),
            ("dwBCastAddr", ctypes.c_uint32),
            ("dwReasmSize", ctypes.c_uint32),
            ("unused1", ctypes.c_uint16),
            ("wType", ctypes.c_uint16),
        ]

    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.c_ulong(0)
        iphlpapi.GetIpAddrTable(None, ctypes.byref(size), 0)
        if size.value <= 4:
            return 0
        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), 0) != 0:
            return 0
        n = ctypes.c_uint32.from_buffer(buf).value
        want = struct.unpack("<I", socket.inet_aton(ip))[0]
        off = ctypes.sizeof(ctypes.c_uint32)
        row_size = ctypes.sizeof(MIB_IPADDRROW)
        for i in range(n):
            row = MIB_IPADDRROW.from_buffer(buf, off + i * row_size)
            if row.dwAddr == want:
                return int(row.dwIndex)
    except Exception:
        return 0
    return 0


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_hotspot_ip() -> str:
    """找 Windows 热点（ICS）网卡地址。ICS 默认网段是 192.168.137.0/24。"""
    candidates = []
    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
    except Exception:
        out = ""
    for line in out.splitlines():
        line = line.strip()
        if ("IPv4" in line or "IPv4 地址" in line) and ":" in line:
            ip = line.split(":")[-1].strip()
            try:
                ipaddress.IPv4Address(ip)
            except Exception:
                continue
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            candidates.append(ip)
    for ip in candidates:
        if ip.startswith("192.168.137."):
            return ip
    for ip in candidates:
        if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.2", "172.30.", "172.31.")):
            return ip
    return ""


def parse_sni(data: bytes) -> str | None:
    """从一段可能不完整的 TLS ClientHello 里解析 SNI。"""
    if len(data) < 5 or data[0] != 0x16:
        return None
    try:
        # 只处理单条 handshake 记录
        if data[5] != 0x01:
            return None
        p = 9  # 记录头5 + 握手头4
        p += 2 + 32  # version + random
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(data[p : p + 2], "big")
        p += 2 + cs_len
        cm_len = data[p]
        p += 1 + cm_len
        ext_total = int.from_bytes(data[p : p + 2], "big")
        p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(data[p : p + 2], "big")
            elen = int.from_bytes(data[p + 2 : p + 4], "big")
            p += 4
            if p + elen > len(data):
                return None
            if etype == 0:  # server_name
                q = p + 2
                name_type = data[q]
                name_len = int.from_bytes(data[q + 1 : q + 3], "big")
                if name_type == 0:
                    raw = data[q + 3 : q + 3 + name_len]
                    try:
                        return raw.decode("idna")
                    except Exception:
                        # Python 3.12 的 idna 编解码器不支持 ignore，且非法标签会抛错
                        return raw.decode("ascii", "ignore")
            p += elen
    except Exception:
        return None
    return None


class Shim(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, mapping):
        self.mapping = mapping
        self.hits = 0
        super().__init__(addr, handler)


class ShimHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        self.server.hits = getattr(self.server, "hits", 0) + 1
        log(f"[分流器] 收到 {self.client_address[0]}:{self.client_address[1]} 的连接")
        client.settimeout(10)
        buf = b""
        try:
            while len(buf) < 4096:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) >= 5 and buf[0] == 0x16:
                    if parse_sni(buf):
                        break
        except Exception:
            return
        client.settimeout(None)

        sni = parse_sni(buf)
        key = self.client_address[:2]
        orig = self.server.mapping.get(key)
        target = sni or (orig[0] if orig else None)
        if not target:
            log(f"无法确定 {key} 的目标域名，放弃")
            return
        port = orig[1] if orig else 443
        log(f"[分流器] 车机连接 {key[0]}:{key[1]}  SNI={sni or '(未解析出)'}  -> {target}:{port}")

        upstream = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)
        try:
            # 建连成功后必须把超时放宽：这一等是在等 mitmproxy 回 CONNECT 响应，
            # 而 eager 情况下它要先连上上游 CDN 才回 200，实测能到 20 秒。
            # 还用 create_connection 的 10 秒超时的话，这里会直接超时导致车机握手失败。
            upstream.settimeout(45)
            connect = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n\r\n".encode()
            upstream.sendall(connect)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = upstream.recv(1)
                if not chunk:
                    return
                resp += chunk
            if b" 200 " not in resp.split(b"\r\n")[0]:
                log(f"mitmproxy 拒绝 CONNECT {target}: {resp[:80]!r}")
                return
            upstream.settimeout(None)
            if buf:
                upstream.sendall(buf)
            _pipe_both(client, upstream)
        finally:
            try:
                upstream.close()
            except Exception:
                pass


def _pipe_both(a: socket.socket, b: socket.socket) -> None:
    def _fwd(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t = threading.Thread(target=_fwd, args=(a, b), daemon=True)
    t.start()
    _fwd(b, a)
    t.join(timeout=1)


def find_mitmdump() -> list[str]:
    """定位 mitmdump：打包后由 exe 自身接管；源码运行则找 Scripts / PATH / 内联。"""
    if FROZEN:
        return [sys.executable, "--mitmdump-inner"]
    cands: list[str] = []
    if IS_WINDOWS:
        exe_dir = os.path.dirname(sys.executable)
        appdata = os.environ.get("APPDATA", "")
        ver = f"Python{sys.version_info.major}{sys.version_info.minor}"
        cands += [
            os.path.join(exe_dir, "Scripts", "mitmdump.exe"),   # 常规安装
            os.path.join(exe_dir, "mitmdump.exe"),
            os.path.join(appdata, "Python", ver, "Scripts", "mitmdump.exe"),  # pip --user
            os.path.join(appdata, "Python", "Scripts", "mitmdump.exe"),
        ]
    cands += [shutil.which("mitmdump"), shutil.which("mitmdump.exe") or ""]
    for c in cands:
        if c and os.path.isfile(c):
            return [c]
    # 兜底：用当前解释器直接调用 mitmproxy 的入口（mitmdump 的入口在 tools.main）
    return [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; raise SystemExit(mitmdump())"]


def mitmproxy_version(exe: list[str]) -> tuple[int, int] | None:
    try:
        r = subprocess.run(exe + ["--version"], capture_output=True, text=True, timeout=30)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"Mitmproxy:\s*(\d+)\.(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return None


def start_mitmdump(apk: str, pkg: str, sha: str, md5: str, outdir: str,
                   emudhra_old: bool = False) -> subprocess.Popen:
    base = find_mitmdump()
    if base[0] == sys.executable and not FROZEN:
        # 回退到当前解释器时，先确认它装了 mitmproxy
        chk = subprocess.run(
            [sys.executable, "-c", "import mitmproxy"], capture_output=True, text=True
        )
        if chk.returncode != 0:
            log("当前 Python 没有安装 mitmproxy。")
            log("PowerShell 里执行：")
            log(f'  & "{sys.executable}" -m pip install -U mitmproxy')
            log("cmd 里执行：")
            log(f'  "{sys.executable}" -m pip install -U mitmproxy')
            if sys.stdin and sys.stdin.isatty():
                ans = input("现在自动安装？直接回车安装，输入 n 跳过：").strip().lower()
                if ans != "n":
                    if subprocess.call([sys.executable, "-m", "pip", "install", "-U", "mitmproxy"]) == 0:
                        chk = subprocess.run([sys.executable, "-c", "import mitmproxy"], capture_output=True)
                    if chk.returncode != 0:
                        raise SystemExit(6)
            else:
                raise SystemExit(6)
    log(f"mitmdump: {'（exe 内置 mitmproxy）' if FROZEN else (base[0] if base[0] != sys.executable else '（当前解释器内联调用）')}")
    ver = None if FROZEN else mitmproxy_version(base)
    if ver is None and FROZEN:
        log("mitmproxy 版本：（内置）")
    elif ver is None:
        log("无法读取 mitmproxy 版本，请确认 mitmproxy 安装正常。")
    elif ver < MIN_MITM:
        log(f"mitmproxy 版本过低：{ver[0]}.{ver[1]}，需要 12.3+（--emudhra 从 12.3 开始提供）。")
        log("请执行：python -m pip install -U mitmproxy")
        raise SystemExit(8)
    else:
        log(f"mitmproxy 版本：{ver[0]}.{ver[1]}")

    cmd = base + [
        "--mode", f"regular@{PROXY_PORT}",
        "--set", f"confdir={os.path.join(outdir, 'mitm-config')}",
        # ★ 车机只信任 eMudhra 链：必须让 mitmproxy 用 eMudhra 中间 CA 私钥签发证书，
        #   否则车机会直接 TLS alert certificate unknown（实测就是这样挂的）。
        "--set", "emudhra_old=true" if emudhra_old else "emudhra=true",
        # lazy：先回 CONNECT 200、后连上游。eager 时要等上游连上才回 200，
        # 上游慢的时候车机会在 TLS 握手阶段等到超时。
        "--set", "connection_strategy=lazy",
        "--set", "stream_large_bodies=2m",
        "--set", f"zeekr_out={outdir}",
        "--set", f"zeekr_inject_pkg={pkg}",
        "--set", f"zeekr_replace_apk={apk}",
        "--set", f"zeekr_override_sha256={sha}",
        "--set", f"zeekr_override_md5={md5}",
        "-s", os.path.abspath(ADDON),
    ]
    try:
        return subprocess.Popen(cmd, cwd=outdir)
    except FileNotFoundError:
        log("找不到 mitmdump。请先执行：python -m pip install -U mitmproxy")
        log(f"已尝试：{base}")
        raise


def _py312_launcher() -> list[str] | None:
    """找一个 >=3.12 的解释器启动器（py -3.12 / py -3 / python3.12）。"""
    for launcher in (["py", "-3.12"], ["py", "-3"], ["python3.12"]):
        try:
            r = subprocess.run(
                launcher + ["-c", "import sys;print('%d.%d' % sys.version_info[:2])"],
                capture_output=True, text=True, timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            m = re.search(r"(\d+)\.(\d+)", r.stdout or "")
            if m and (int(m.group(1)), int(m.group(2))) >= MIN_PY:
                return launcher
    return None


def ensure_python() -> int | None:
    """Python 版本不足时，尝试用 3.12+ 重新运行自己。返回 None 表示可以继续。"""
    if FROZEN or sys.version_info >= MIN_PY:
        return None
    cur = "%d.%d.%d" % sys.version_info[:3]
    launcher = _py312_launcher()
    if launcher:
        log(f"当前 Python {cur} 低于 3.12，自动切换到 {' '.join(launcher)} 重新运行…")
        return subprocess.call(launcher + [os.path.abspath(__file__)] + sys.argv[1:])
    log(f"需要 Python 3.12 或更高（当前 {cur}）。")
    log("mitmproxy 12.3+（本工具依赖的 --emudhra）不支持 3.10 / 3.11。")
    log("请安装 Python 3.12+（python.org），然后执行：")
    log("  py -3.12 -m pip install -U mitmproxy")
    return 7


def run_divert(hotspot_ip: str, block_quic: bool = True) -> None:
    """透明重定向。

    ★ 关键：车机流量是经 ICS **转发**过来的，而 WinDivert 默认的 NETWORK 层
      看不到转发包（实测：手机能正常上网，NETWORK 层抓到 0 个包，见
      https://github.com/basil00/WinDivert/issues/54 ）。转发包只在
      WINDIVERT_LAYER_NETWORK_FORWARD 层可见。

    所以这里用三个句柄：
      * fwd      —— FORWARD 层抓车机的 443 包（抓不到就退化为 NETWORK 层）；
      * injector —— NETWORK 层，只用来把改写后的包注入本机（送进 18081 分流器）；
      * back     —— NETWORK 层，把分流器回包的源地址改回原 CDN 地址。
    """
    import pydivert
    from pydivert.consts import Direction, Layer

    mapping: dict[tuple, tuple] = {}
    shim = Shim((hotspot_ip, SHIM_PORT), ShimHandler, mapping)
    threading.Thread(target=shim.serve_forever, daemon=True).start()
    log(f"SNI 分流器已监听 {hotspot_ip}:{SHIM_PORT}")
    hot_ifidx = if_index_for_ip(hotspot_ip)
    log(f"热点网卡接口索引：{hot_ifidx or '未取到'}")

    # 只处理热点网段内的客户端（车机），否则会把本机 mitmproxy 自己的上游连接也劫持成环
    base = hotspot_ip.rsplit(".", 1)[0]
    lo, hi = f"{base}.2", f"{base}.254"
    fwd_flt = f"(tcp.DstPort == 443 and ip.SrcAddr >= {lo} and ip.SrcAddr <= {hi})"
    if block_quic:
        # 商店如果走 HTTP/3（QUIC = UDP 443），TCP 规则一条都匹配不到；把 QUIC 丢掉，
        # 客户端会按设计回退到 TCP 443，然后才轮到我们解密改写。
        fwd_flt += f" or (udp.DstPort == 443 and ip.SrcAddr >= {lo} and ip.SrcAddr <= {hi})"
    back_flt = f"(tcp.SrcPort == {SHIM_PORT} and ip.SrcAddr == {hotspot_ip})"

    injector = pydivert.WinDivert("false", layer=Layer.NETWORK)   # 只用于 send()
    injector.open()
    back = pydivert.WinDivert(back_flt, layer=Layer.NETWORK)
    back.open()
    try:
        fwd = pydivert.WinDivert(fwd_flt, layer=Layer.NETWORK_FORWARD)
        fwd.open()
        fwd_layer = "NETWORK_FORWARD"
    except Exception as exc:
        log(f"FORWARD 层打不开（{exc}），退回 NETWORK 层（非 ICS 场景仍可用）")
        fwd = pydivert.WinDivert(fwd_flt, layer=Layer.NETWORK)
        fwd.open()
        fwd_layer = "NETWORK"
    log(f"抓包层：{fwd_layer}")
    log(f"抓车机包过滤器：{fwd_flt}")

    stats = {"rewritten": 0, "quic": 0, "back": 0, "inject_fail": 0}
    errs = {"n": 0}

    def _note_err(exc) -> None:
        errs["n"] += 1
        if errs["n"] <= 5:
            log(f"WinDivert 处理包失败: {exc}")
        elif errs["n"] == 6:
            log("（后续同类错误不再逐条打印）")

    def _forward_loop() -> None:
        # 句柄已在主线程 open()，这里直接迭代（不要用 with，否则会重复 open）
        for packet in fwd:
            try:
                if packet.ipv4 is None:
                    continue
                # QUIC（HTTP/3）：直接丢掉，逼客户端回退 TCP 443，否则永远轮不到我们解密
                if block_quic and packet.udp is not None and packet.udp.dst_port == 443:
                    stats["quic"] += 1
                    if stats["quic"] == 1:
                        log("检测到 QUIC（UDP 443）：已丢弃，迫使商店回退到 TCP。")
                    continue
                if packet.tcp is None or packet.tcp.dst_port != 443:
                    continue
                if packet.ipv4.dst_addr == hotspot_ip:
                    continue
                key = (packet.ipv4.src_addr, packet.tcp.src_port)
                orig = (packet.ipv4.dst_addr, packet.tcp.dst_port)
                captured_ifidx = packet.interface[0]
                mapping[key] = orig
                packet.ipv4.dst_addr = hotspot_ip
                packet.tcp.dst_port = SHIM_PORT
                # 注入到本机时按「进入本机」处理，否则会被当成发出去的包
                packet.direction = Direction.INBOUND
                # ★ 必须把地址里的 Layer 改成 NETWORK：这个包是在 NETWORK_FORWARD 层抓的，
                #   pydivert 会把原地址原样交给 WinDivertSend，Layer 对不上就会静默失败
                #   （pydivert 不检查 WinDivertSend 的返回值，所以之前一个错都不报）。
                packet.wd_addr.Layer = int(Layer.NETWORK)
                # ★ 接口索引也要改：转发层抓到的是「往哪转发」的那个接口，
                #   直接拿去当来源接口注入，内核会当成来自错误接口而丢弃。
                #   这里强制改成热点网卡自己的索引，包才会被投递给本机 18081。
                if hot_ifidx:
                    packet.wd_addr.Network.IfIdx = hot_ifidx
                    packet.wd_addr.Network.SubIfIdx = 0
                sent = injector.send(packet)
                if not sent:
                    stats["inject_fail"] += 1
                    if stats["inject_fail"] <= 3:
                        log(f"注入失败（WinDivertSend 返回 0）：{key[0]}:{key[1]} -> {orig[0]}:{orig[1]}")
                    continue
                stats["rewritten"] += 1
                if stats["rewritten"] == 1:
                    log(f"已捕获并改写第一个车机包：{key[0]}:{key[1]} -> 原目标 {orig[0]}:{orig[1]}")
                    log(f"  抓包时接口索引={captured_ifidx}，注入时用热点网卡索引={hot_ifidx}")
            except Exception as exc:  # 单个包失败不应中断整体
                _note_err(exc)

    def _back_loop() -> None:
        for packet in back:
            try:
                if packet.tcp is not None and packet.ipv4 is not None:
                    orig = mapping.get((packet.ipv4.dst_addr, packet.tcp.dst_port))
                    if orig:
                        packet.ipv4.src_addr = orig[0]
                        packet.tcp.src_port = orig[1]
                back.send(packet)
                stats["back"] += 1
            except Exception as exc:
                _note_err(exc)
                try:
                    back.send(packet)
                except Exception:
                    pass

    def _watchdog() -> None:
        for _ in range(4):
            time.sleep(3)
            if stats["rewritten"] or stats["quic"]:
                return
        log("提示：12 秒内没有捕获到任何车机 443 包。")
        log("      → 先确认车机确实连的是本机热点、并且商店走的是 Wi-Fi（不是车内自带 4G）；")
        log("      → 再确认上面那个 IP 就是热点网卡（本机有 ZeroTier 等虚拟网卡时容易猜错）；")
        log("      → 都没有问题的话，点界面上的「抓包诊断」，看车机到底有没有包经过这台机器。")

    def _delivery_check() -> None:
        # 车机可能重传 SYN、也可能先试别的地址再换一个连接，所以不能只等几秒就喊失败
        # （实测：第一个包改写后 12 秒，分流器才收到连接，链路其实是通的）。
        while stats["rewritten"] == 0 and not stats["inject_fail"]:
            time.sleep(0.5)
        time.sleep(10)
        if shim.hits:
            return
        log(f"提示：已改写 {stats['rewritten']} 个车机包，但还没收到车机连上分流器。")
        log("      （车机通常会重传或换连接，再等十几秒看看；下面还有一次确认。）")
        time.sleep(20)
        if shim.hits:
            log("      → 已收到分流器连接，链路正常。")
            return
        log("警告：改写 30 秒后，分流器仍然没收到任何车机连接。")
        log(f"      → 注入层=NETWORK、方向=INBOUND、接口索引={hot_ifidx}；")
        log("      → 把这段日志发出来，这基本就是内核没接受注入包的证据。")

    def _stats_loop() -> None:
        last = (0, 0, 0, 0)
        while True:
            time.sleep(20)
            cur = (stats["rewritten"], stats["back"], stats["quic"], stats["inject_fail"])
            if cur != last and any(cur):
                log(f"[统计] 改写 {cur[0]} / 回程 {cur[1]} / 丢QUIC {cur[2]} / 注入失败 {cur[3]}")
                last = cur

    threading.Thread(target=_forward_loop, daemon=True).start()
    threading.Thread(target=_back_loop, daemon=True).start()
    threading.Thread(target=_watchdog, daemon=True).start()
    threading.Thread(target=_delivery_check, daemon=True).start()
    threading.Thread(target=_stats_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log(f"收到中断：改写 {stats['rewritten']} 个车机包 / 丢弃 QUIC {stats['quic']} 个 / 回程 {stats['back']} 个")
        raise


def sniff_clients(hotspot_ip: str, seconds: int = 30) -> int:
    """抓包诊断：同时在 FORWARD 层和 NETWORK 层统计热点网段的 IPv4 流量。

    用 SNIFF 模式（只复制、不拦截），所以不会影响车机上网。
    ICS 转发的流量只在 FORWARD 层可见 —— 这个诊断能直接把这一点验证出来。
    """
    import pydivert
    from pydivert.consts import Flag, Layer

    base = hotspot_ip.rsplit(".", 1)[0]
    lo, hi = f"{base}.2", f"{base}.254"
    flt = f"ip.SrcAddr >= {lo} and ip.SrcAddr <= {hi}"
    log(f"抓包诊断：监听 {seconds} 秒（SNIFF 模式，只统计不干预）")
    log(f"过滤器：{flt}")
    log("这段时间请在车机上打开应用商店、点开一个应用的详情页，最好再刷新几下。")

    results: dict[str, dict] = {}

    def _worker(handle, bucket) -> None:
        while True:
            try:
                packet = handle.recv()
            except BaseException:
                return
            bucket["n"] += 1
            try:
                if packet.tcp is not None:
                    key = ("TCP", packet.tcp.dst_port)
                elif packet.udp is not None:
                    key = ("UDP", packet.udp.dst_port)
                else:
                    key = ("IP", 0)
            except BaseException:
                key = ("?", 0)
            bucket["flows"][key] = bucket["flows"].get(key, 0) + 1

    for tag, layer in (("FORWARD 层", Layer.NETWORK_FORWARD), ("NETWORK 层", Layer.NETWORK)):
        try:
            handle = pydivert.WinDivert(flt, layer=layer, flags=Flag.SNIFF)
            handle.open()
        except Exception as exc:
            log(f"  {tag} 打开失败：{exc}")
            continue
        bucket = {"n": 0, "flows": {}}
        results[tag] = bucket
        threading.Thread(target=_worker, args=(handle, bucket), daemon=True).start()

    time.sleep(seconds)

    total = sum(b["n"] for b in results.values())
    for tag, b in results.items():
        log(f"  {tag}：{b['n']} 个包")
    log(f"抓包结束：这 {seconds} 秒里，热点网段一共 {total} 个包。")

    if total == 0:
        log("→ 两层都没有包：车机/手机根本没在这台机器上发流量。")
        log("  1) 设备连的是不是这个热点？（其他 Wi-Fi / 手机热点都不算）")
        log("  2) 设备 Wi-Fi 是不是显示「已连接，无法访问互联网」——那样会自己切走；")
        log("  3) 车机可能把商店流量走到了车载 4G。")
    else:
        for tag, b in results.items():
            if not b["n"]:
                continue
            log(f"  [{tag}] 端口分布：")
            for (proto, port), n in sorted(b["flows"].items(), key=lambda kv: -kv[1])[:10]:
                log(f"      {proto}/{port}  {n} 个包")
        if any(k[0] == "UDP" and k[1] == 443 for b in results.values() for k in b["flows"]):
            log("注意：看到 UDP/443（QUIC）。透明重定向默认会把 QUIC 丢掉，逼它回退 TCP。")
        if results.get("FORWARD 层", {}).get("n") and not results.get("NETWORK 层", {}).get("n"):
            log("说明：流量只在 FORWARD 层可见 —— 这正是 ICS 转发的正常现象。")
    sys.stdout.flush()
    return 0


def run_embedded_mitmdump(args: list[str]) -> int:
    """打包后的 exe 以 --mitmdump-inner 启动时，直接跑 mitmproxy 的 mitmdump。"""
    from mitmproxy.tools.main import mitmdump

    return mitmdump(args) or 0


def main() -> int:
    if "--mitmdump-inner" in sys.argv[1:]:
        idx = sys.argv.index("--mitmdump-inner")
        return run_embedded_mitmdump(sys.argv[idx + 1 :])

    rc = ensure_python()
    if rc is not None:
        return rc

    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default="", help="要安装的 APK 路径")
    ap.add_argument("--pkg", default="ALL", help="注入目标包名，或 ALL")
    ap.add_argument("--out", default="logs", help="日志/flow 输出目录")
    ap.add_argument("--proxy-only", action="store_true", help="只起 HTTP 代理，不做透明重定向")
    ap.add_argument("--hotspot-ip", default="", help="手动指定热点网卡 IP（默认自动探测；有虚拟网卡时可用来兜底）")
    ap.add_argument("--sniff", type=int, default=0, metavar="SECONDS",
                    help="抓包诊断：统计热点网段流量 SECONDS 秒后退出（需要管理员，不需要 --apk）")
    ap.add_argument("--allow-quic", action="store_true",
                    help="不丢弃 QUIC(UDP 443)。默认丢弃，好让商店回退到可解密的 TCP")
    ap.add_argument("--emudhra-old", action="store_true",
                    help="用 eMudhra 的 Sectigo 交叉签名链（老信任库的车机可能需要）")
    args = ap.parse_args()

    if args.sniff:
        manual_ip = (args.hotspot_ip or "").strip()
        hotspot_ip = manual_ip or find_hotspot_ip()
        if not hotspot_ip:
            log("找不到热点网卡 IP；请先开启「移动热点」，或用 --hotspot-ip 指定。")
            return 5
        log(f"热点网卡 IP：{hotspot_ip or '未找到'}{'（手动指定）' if manual_ip else '（自动探测）'}")
        if not is_admin():
            log("抓包诊断需要管理员权限：请右键「以管理员身份运行」。")
            return 3
        return sniff_clients(hotspot_ip, max(5, args.sniff))

    if not args.apk:
        log("缺少 --apk：请指定要安装的 APK 路径（或直接双击运行图形界面）。")
        return 2
    apk = os.path.abspath(args.apk)
    if not os.path.isfile(apk):
        log(f"APK 不存在：{apk}")
        return 2
    with open(apk, "rb") as fh:
        blob = fh.read()
    size = len(blob)
    sha = hashlib.sha256(blob).hexdigest()
    md5 = hashlib.md5(blob).hexdigest()
    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)

    log("=" * 60)
    log("极载 ZEEload · Windows 版")
    log(f"Python: {sys.version.split()[0]}  |  解释器: {sys.executable}")
    log(f"APK   : {apk}")
    log(f"大小  : {size} 字节（{size / 1048576:.2f} MiB）")
    log(f"sha256: {sha}")
    log(f"md5   : {md5}")
    log(f"注入包: {args.pkg}")
    log("=" * 60)

    if not IS_WINDOWS:
        log("这不是 Windows 环境；仅做参数校验。")
        return 0

    if not args.proxy_only and not is_admin():
        log("需要管理员权限：请右键「以管理员身份运行」PowerShell 后再执行本脚本。")
        return 3

    mitm = start_mitmdump(apk, args.pkg, sha, md5, outdir, emudhra_old=args.emudhra_old)
    time.sleep(3)
    if mitm.poll() is not None:
        log("mitmproxy 启动失败，请确认 mitmproxy 安装正常（pip install -U mitmproxy）。")
        return 4
    log(f"mitmproxy 已启动，监听 127.0.0.1:{PROXY_PORT}")

    manual_ip = (args.hotspot_ip or "").strip()
    hotspot_ip = manual_ip or find_hotspot_ip()
    log(f"热点网卡 IP：{hotspot_ip or '未找到'}{'（手动指定）' if manual_ip else '（自动探测）'}")

    try:
        if args.proxy_only:
            log(f"代理模式：在车机网络里把该 Windows 机器设为 HTTP 代理 0.0.0.0:{PROXY_PORT}")
            while True:
                time.sleep(1)
        if not hotspot_ip:
            log("找不到热点网卡 IP；请先在 Windows 设置里开启「移动热点」并让车机连上。")
            return 5
        log("开始透明重定向（Ctrl-C 停止）")
        run_divert(hotspot_ip, block_quic=not args.allow_quic)
    except KeyboardInterrupt:
        log("收到中断，正在退出")
    finally:
        try:
            mitm.terminate()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
