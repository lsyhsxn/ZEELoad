#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极载 · ZEEload — macOS 图形界面
把 ~/Applications/ZEELoad 里的侧载脚本包成一个窗口程序：
  APK 拖放 → 环境检查 → 开始/停止 → 实时日志

不改变原有脚本的逻辑，只是调用 scripts/transparent-test.sh（引擎脚本）并解析它的输出。
"""

import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import zipfile

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ---------------------------------------------------------------- 路径
GUI_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(GUI_DIR)                       # ~/Applications/ZEELoad
ENGINE = os.path.join(BASE, "scripts", "transparent-test.sh")
CHECKENV = os.path.join(BASE, "scripts", "check-environment.sh")
LOGS = os.path.join(BASE, "logs")
VENV_PY = os.path.join(BASE, "venv", "bin", "python")
CFG_DIR = os.path.expanduser("~/Library/Application Support/ZEELoad")
CFG_FILE = os.path.join(CFG_DIR, "gui.json")

VERSION = "v1.0.1"

# ---------------------------------------------------------------- 配色
BG = "#F4F2EE"
CARD = "#FFFFFF"
BORDER = "#E2DED6"
TEXT = "#1B1A17"
MUTED = "#7C7669"
ACCENT = "#C08A2E"
ACCENT_D = "#A6731F"
OK = "#2E7D53"
WARN = "#B4791F"
ERR = "#BE3A2B"

LOG_BG = "#16140F"
LOG_FG = "#D8D2C4"
LOG_MUTED = "#8B8474"
LOG_OK = "#84D2A4"
LOG_WARN = "#F2C55C"
LOG_ERR = "#FF8F80"
LOG_GOLD_BG = "#E3B04B"

F_CN = "PingFang SC"
F_MONO = "Menlo"


def font(size=12, weight="normal", family=F_CN):
    return (family, size, weight)


# ---------------------------------------------------------------- APK 解析
def _aapt_path():
    """返回随包自带 build-tools 的 aapt 可执行文件路径，找不到返回 None。"""
    jdk_bin = os.path.join(BASE, "tools", "jdk-17.0.21+9", "Contents", "Home", "bin")
    aapt = os.path.join(jdk_bin, "aapt")
    return aapt if os.path.exists(aapt) else None


def inspect_apk(path):
    """读出 APK 的架构、真实包名、大小。

    优先用 aapt（权威解析二进制 AndroidManifest.xml），
    aapt 不可用或失败时退回 zip 启发式（仅读架构，包名置空，避免误报）。
    """
    info = {"size": os.path.getsize(path), "abis": [], "pkg": None,
            "label": None, "entries": 0, "zip_ok": False, "note": ""}
    if not zipfile.is_zipfile(path):
        info["note"] = "不是有效的 zip/APK"
        return info
    info["zip_ok"] = True

    # 1) 优先用 aapt 读真实包名 + 应用名 + 原生架构
    aapt = _aapt_path()
    if aapt:
        try:
            proc = subprocess.run(
                [aapt, "dump", "badging", path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                out = proc.stdout
                m = re.search(r"^package:\s*name='([^']+)'", out, re.M)
                if m:
                    info["pkg"] = m.group(1)
                m = re.search(r"^application-label:'([^']*)'", out, re.M)
                if m:
                    info["label"] = m.group(1)
                m = re.search(r"^native-code:\s*'([^']+)'", out, re.M)
                if m:
                    info["abis"] = sorted(set(m.group(1).split()))
                info["note"] = "aapt"
        except Exception:                            # noqa: BLE001
            pass

    # 2) 兜底：zip 里直接列 lib/ 目录推断架构（aapt 没给出时）
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            info["entries"] = len(names)
            if not info["abis"]:
                abis = set()
                for n in names:
                    if n.startswith("lib/") and n.count("/") >= 2:
                        abis.add(n.split("/")[1])
                info["abis"] = sorted(abis)
    except Exception as exc:                        # noqa: BLE001
        info["note"] = info["note"] or f"读取失败：{exc}"

    return info


def human_size(n):
    return f"{n / 1048576:.2f} MiB" if n >= 1048576 else f"{n / 1024:.0f} KiB"


class FlatButton(tk.Frame):
    """macOS 下 tk.Button 的底色会被系统主题吃掉，这里用 Frame+Label 拼一个扁平按钮。"""

    PALETTE = {
        "primary": (ACCENT, ACCENT_D, "#FFFFFF", "#E7E2D6"),
        "ghost": (("#F3F0E9"), "#E8E2D5", TEXT, "#EFECE4"),
    }

    def __init__(self, parent, text, command, kind="ghost"):
        bg, hover, fg, dis_bg = self.PALETTE.get(kind, self.PALETTE["ghost"])
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0)
        self._command = command
        self._bg, self._hover, self._fg, self._dis_bg = bg, hover, fg, dis_bg
        self._state = "normal"
        self.label = tk.Label(
            self, text=text, bg=bg, fg=fg,
            font=font(12, "bold" if kind == "primary" else "normal"),
            padx=0 if kind == "primary" else 13, pady=9, cursor="pointinghand")
        self.label.pack(fill="both", expand=True)
        for w in (self, self.label):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", self._enter)
            w.bind("<Leave>", self._leave)

    def _click(self, _e=None):
        if self._state != "disabled" and self._command:
            self._command()

    def _enter(self, _e=None):
        if self._state == "normal":
            self.configure(bg=self._hover)
            self.label.configure(bg=self._hover)

    def _leave(self, _e=None):
        if self._state == "normal":
            self.configure(bg=self._bg)
            self.label.configure(bg=self._bg)

    def set_state(self, state):
        self._state = state
        if state == "disabled":
            self.configure(bg=self._dis_bg)
            self.label.configure(bg=self._dis_bg, fg="#B7B1A3", cursor="arrow")
        else:
            self.configure(bg=self._bg)
            self.label.configure(bg=self._bg, fg=self._fg, cursor="pointinghand")

    def set_text(self, text):
        self.label.configure(text=text)


# ---------------------------------------------------------------- 主窗口
class ZeeloadApp:
    def __init__(self, root):
        self.root = root
        self.proc = None
        self.q = queue.Queue()
        self.apk_path = None
        self.apk_info = None
        self._drag_ok = False
        self._pw = None
        self._saw = {"listen": False, "request": False, "inject": False,
                     "replace": False, "raw": False}
        self._hashes = None
        self._hash_token = 0
        self._advanced_visible = False
        self._stop_pending = False
        self._force_cleaned = False

        self.root.title("极载 · ZEEload")
        self.root.configure(bg=BG)
        self.root.geometry("1180x860")
        self.root.minsize(1040, 800)

        self._init_style()
        self._build_header()
        self._build_body()
        self._load_cfg()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(80, self._drain_queue)
        # 抢焦点：Tkinter 窗口在 macOS 上常被放到后台或其它 Space，这里主动置顶 + 抢焦点
        self.root.after(120, self._force_front)

        self._log("极载 · ZEEload 已就绪，使用流程如下：", "ok")
        self._log("")
        self._log("① 选择 APK", "head")
        self._log("   把 .apk 文件拖进左上角的虚线框，或点击选择；", "muted")
        self._log("   选好后会显示大小、架构、包名、MD5 / SHA256。", "muted")
        self._log("")
        self._log("② 检查环境", "head")
        self._log("   先开 Mac 的「互联网共享」，让车机连上热点，", "muted")
        self._log("   再点「重新检查」，转发组件、共享接口、车机都变绿即可。", "muted")
        self._log("")
        self._log("③ 开始侧载", "head")
        self._log("   点「开始侧载」，顶部会显示四个阶段的进度；", "muted")
        self._log("   看到「注入更新」后，去车机打开应用商店点「更新 / 安装」。", "muted")
        self._log("")
        self._log("详细操作与限制见右上角「更多 → 打开说明文档」。", "muted")

    def _force_front(self):
        try:
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after(400, lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
        except Exception:                            # noqa: BLE001
            pass
        # 若窗口仍不可见（可能在别的 Space），用 AppleScript 把本进程 app 拉到前台
        if self.root.state() == "withdrawn" or not self.root.winfo_viewable():
            try:
                subprocess.run(
                    ["osascript", "-e",
                     'tell application "System Events" to set frontmost of '
                     '(first process whose unix id is %d) to true' % os.getpid()],
                    capture_output=True)
            except Exception:                        # noqa: BLE001
                pass

    # ------------------------------------------------------------ 样式
    def _init_style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("TCombobox", fieldbackground=CARD, background=CARD,
                     bordercolor=BORDER, arrowcolor=MUTED, padding=4,
                     foreground=TEXT)
        st.configure("TEntry", fieldbackground=CARD, bordercolor=BORDER, padding=4)
        st.configure("Slim.Horizontal.TProgressbar", troughcolor="#E7E3DA",
                     background=ACCENT, borderwidth=0, thickness=4)

    # ------------------------------------------------------------ 页头
    def _build_header(self):
        head = tk.Frame(self.root, bg=CARD)
        head.pack(fill="x", side="top")

        left = tk.Frame(head, bg=CARD)
        left.pack(side="left", padx=20, pady=14)
        tk.Label(left, text="极载 · ZEEload", bg=CARD, fg=TEXT,
                 font=font(17, "bold")).pack(anchor="w")
        tk.Label(left, text=f"车机 APK 侧载工具 · macOS 图形界面 {VERSION}",
                 bg=CARD, fg=MUTED, font=font(11)).pack(anchor="w", pady=(2, 0))

        right = tk.Frame(head, bg=CARD)
        right.pack(side="right", padx=20, pady=22)
        self.state_dot = tk.Canvas(right, width=10, height=10, bg=CARD,
                                   highlightthickness=0)
        self.state_dot.pack(side="left", padx=(0, 7))
        self._dot = self.state_dot.create_oval(1, 1, 9, 9, fill="#B9B3A5", width=0)
        self.state_lbl = tk.Label(right, text="就绪", bg=CARD, fg=MUTED, font=font(12))
        self.state_lbl.pack(side="left")

        more = tk.Menubutton(right, text="更多 ▾", bg=CARD, fg=MUTED,
                             activebackground="#EFEBE3", activeforeground=TEXT,
                             relief="flat", font=font(11), cursor="pointinghand")
        more.pack(side="left", padx=(18, 0))
        m = tk.Menu(more, tearoff=0)
        m.add_command(label="打开日志目录", command=self.open_logs)
        m.add_command(label="打开说明文档 (README)", command=self.open_readme)
        m.add_command(label="重新检查环境", command=self.check_env)
        m.add_separator()
        m.add_command(label="退出", command=self.on_close)
        more.configure(menu=m)

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="top")

    # ------------------------------------------------------------ 主体
    def _build_body(self):
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=14)

        # 左侧：套一个 Canvas + 滚动条，高级选项展开后也能滚到「开始侧载」按钮
        left_holder = tk.Frame(body, bg=BG, width=404)
        left_holder.pack(side="left", fill="y")
        left_holder.pack_propagate(False)

        self.left_canvas = tk.Canvas(left_holder, bg=BG, highlightthickness=0,
                                     width=404)
        self.left_scroll = tk.Scrollbar(left_holder, orient="vertical",
                                        command=self.left_canvas.yview)
        self.left_canvas.configure(yscrollcommand=self.left_scroll.set)
        self.left_canvas.pack(side="left", fill="both", expand=True)
        # 滚动条用 place 固定在右侧，避免被 canvas 的 expand 抢占空间；
        # 默认隐藏，内容超高时由 _sync_scrollbar 显示

        left = tk.Frame(self.left_canvas, bg=BG)
        self._left_window = self.left_canvas.create_window(
            (0, 0), window=left, anchor="nw")

        def _on_left_conf(_e=None):
            self.left_canvas.configure(scrollregion=self.left_canvas.bbox("all"))
            self._sync_scrollbar()
        left.bind("<Configure>", _on_left_conf)
        self.left_canvas.bind("<Configure>",
                              lambda _e: self.left_canvas.itemconfigure(
                                  self._left_window, width=self.left_canvas.winfo_width()))

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(14, 0))

        self._build_apk_card(left)
        self._build_env_card(left)
        self._build_run_card(left)
        self._build_log(right)
        self._bind_wheel(left)

    def _sync_scrollbar(self):
        """内容没超过可视区就隐藏滚动条，避免空滚动条占位。"""
        if not self.left_canvas.bbox("all"):
            return
        _, _, _, bottom = self.left_canvas.bbox("all")
        h = self.left_canvas.winfo_height()
        if bottom <= h:
            self.left_scroll.place_forget()
        else:
            self.left_scroll.place(relx=1.0, rely=0, relheight=1.0,
                                   anchor="ne", width=12)

    def _bind_wheel(self, widget):
        """递归给左侧所有控件绑定滚轮，让鼠标停在任何控件上都能滚动。"""
        def _wheel(_e):
            self.left_canvas.yview_scroll(-1 * (_e.delta // 120), "units")
        for w in self._iter_children(widget):
            w.bind("<MouseWheel>", _wheel)
            w.bind("<Button-4>", lambda _e: self.left_canvas.yview_scroll(-1, "units"))
            w.bind("<Button-5>", lambda _e: self.left_canvas.yview_scroll(1, "units"))

    @staticmethod
    def _iter_children(widget):
        stack = [widget]
        while stack:
            w = stack.pop()
            yield w
            stack.extend(w.winfo_children())

    def _card(self, parent, title, hint=""):
        wrap = tk.Frame(parent, bg=CARD, highlightbackground=BORDER,
                        highlightthickness=1)
        wrap.pack(fill="x", pady=(0, 10))
        bar = tk.Frame(wrap, bg=CARD)
        bar.pack(fill="x", padx=14, pady=(11, 0))
        tk.Label(bar, text=title, bg=CARD, fg=TEXT, font=font(12, "bold")).pack(side="left")
        if hint:
            tk.Label(bar, text=hint, bg=CARD, fg=MUTED, font=font(10)).pack(side="right")
        inner = tk.Frame(wrap, bg=CARD)
        inner.pack(fill="x", padx=14, pady=(9, 13))
        return inner

    # ------------------------------------------------------------ 卡片 1：APK
    def _build_apk_card(self, parent):
        inner = self._card(parent, "① 选择 APK", "支持拖入")

        self.drop = tk.Frame(inner, bg="#FBF9F5", highlightbackground="#DDD6C8",
                             highlightthickness=1, height=58, cursor="pointinghand")
        self.drop.pack(fill="x")
        self.drop.pack_propagate(False)
        self.drop_lbl = tk.Label(self.drop, text="拖入 .apk 文件，或点击这里选择",
                                 bg="#FBF9F5", fg=MUTED, font=font(12))
        self.drop_lbl.pack(expand=True)
        for w in (self.drop, self.drop_lbl):
            w.bind("<Button-1>", lambda _e: self.pick_apk())

        info = tk.Frame(inner, bg=CARD)
        info.pack(fill="x", pady=(9, 0))
        self.lbl_name = tk.Label(info, text="未选择文件", bg=CARD, fg=MUTED,
                                 font=font(11), anchor="w", justify="left",
                                 wraplength=340)
        self.lbl_name.pack(fill="x")
        self.lbl_meta = tk.Label(info, text="", bg=CARD, fg=MUTED,
                                 font=font(10, family=F_MONO), anchor="w",
                                 justify="left", wraplength=340)
        self.lbl_meta.pack(fill="x", pady=(3, 0))

        self.lbl_hash = tk.Label(info, text="", bg=CARD, fg=MUTED,
                                 font=font(10, family=F_MONO), anchor="w",
                                 justify="left", cursor="pointinghand")
        self.lbl_hash.pack(fill="x", pady=(2, 0))
        self.lbl_hash.bind("<Button-1>", lambda _e: self._copy_hashes())
        self.lbl_hash.bind("<Enter>", lambda _e: self.lbl_hash.configure(fg=ACCENT))
        self.lbl_hash.bind("<Leave>", lambda _e: self.lbl_hash.configure(
            fg=TEXT if self._hashes else MUTED))

        self._enable_dnd()

    def _enable_dnd(self):
        try:
            from tkinterdnd2 import DND_FILES  # noqa: F401
            self.drop.drop_target_register(DND_FILES)
            self.drop.dnd_bind("<<Drop>>", self._on_drop)
            self._drag_ok = True
        except Exception:                            # noqa: BLE001
            self._drag_ok = False

    def _on_drop(self, event):
        raw = event.data.strip()
        paths = re.findall(r"\{([^}]*)\}|(\S+)", raw)
        cand = None
        for a, b in paths:
            p = a or b
            if p.lower().endswith(".apk"):
                cand = p
                break
        if cand:
            self.set_apk(cand)
        else:
            messagebox.showwarning("不是 APK", "请拖入 .apk 文件。")

    def pick_apk(self):
        p = filedialog.askopenfilename(
            title="选择要侧载的 APK",
            initialdir=(os.path.dirname(self.apk_path) if self.apk_path else os.path.expanduser("~/Downloads")),
            filetypes=[("Android 应用", "*.apk"), ("所有文件", "*.*")])
        if p:
            self.set_apk(p)

    def set_apk(self, path):
        if not os.path.isfile(path):
            return
        info = inspect_apk(path)
        self.apk_path = path
        self.apk_info = info
        name = os.path.basename(path)
        self.lbl_name.configure(text=name, fg=TEXT, font=font(12, "bold"))
        self._hashes = None
        self.lbl_hash.configure(text="md5  计算中…", fg=MUTED)
        bits = [human_size(info["size"])]
        if info["abis"]:
            bits.append("架构 " + " / ".join(info["abis"]))
        else:
            bits.append("架构 通用(无 native 库)")
        if info["label"]:
            bits.append("应用名 " + info["label"])
        if info["pkg"]:
            bits.append("包名 " + info["pkg"])
        if not info["zip_ok"]:
            bits.append("⚠︎ " + (info["note"] or "文件异常"))
        self.lbl_meta.configure(text="\n".join(bits),
                                fg=TEXT if info["zip_ok"] else ERR)
        self.drop_lbl.configure(text="✓ 已选择，可重新拖入替换", fg=OK)
        self._log(f"已选择 APK：{path}", "muted")
        self._log(f"  大小 {info['size']} 字节 · 架构 {', '.join(info['abis']) or '通用'} · 包名 {info['pkg'] or '未识别'}", "muted")
        if not info["zip_ok"]:
            self._hint("这个文件不像有效的 APK，请确认没有把 .command 或压缩包当 APK。", "err")
        else:
            self._hash_token += 1
            threading.Thread(target=self._compute_hashes,
                             args=(path, self._hash_token), daemon=True).start()

    def _compute_hashes(self, path, token):
        """后台算 md5 / sha256，算完再回填界面（大文件不卡窗口）。"""
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    md5.update(chunk)
                    sha.update(chunk)
            self.q.put(("hash", (token, path, md5.hexdigest(), sha.hexdigest())))
        except Exception as exc:                     # noqa: BLE001
            self.q.put(("hash", (token, path, "", f"读取失败：{exc}")))

    def _apply_hashes(self, token, path, md5, sha):
        if token != self._hash_token or path != self.apk_path:
            return                                   # 已经换了文件，丢弃旧结果
        if not md5:
            self.lbl_hash.configure(text=sha, fg=ERR)
            return
        self._hashes = (md5, sha)
        self.lbl_hash.configure(text=f"md5    {md5}\nsha256 {sha[:16]}…", fg=TEXT)
        self._log(f"  md5    {md5}", "muted")
        self._log(f"  sha256 {sha}", "muted")

    def _copy_hashes(self):
        if not self._hashes:
            return
        md5, sha = self._hashes
        txt = f"文件：{self.apk_path}\nmd5={md5}\nsha256={sha}"
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self.lbl_hash.configure(text=f"已复制 md5 + sha256 ✓", fg=OK)
        self.root.after(1400, lambda: self.lbl_hash.configure(
            text=f"md5    {md5}\nsha256 {sha[:16]}…", fg=TEXT))

    # ------------------------------------------------------------ 卡片 2：环境
    def _build_env_card(self, parent):
        inner = self._card(parent, "② 检查环境", "开热点后点这里")
        self.rows = {}
        for key, label in (("proxy", "转发组件"), ("iface", "共享接口"), ("car", "车机")):
            row = tk.Frame(inner, bg=CARD)
            row.pack(fill="x", pady=1)
            c = tk.Canvas(row, width=8, height=8, bg=CARD, highlightthickness=0)
            c.pack(side="left", pady=4)
            dot = c.create_oval(0, 0, 8, 8, fill="#D6D0C2", width=0)
            tk.Label(row, text=label, bg=CARD, fg=MUTED, font=font(11),
                     width=6, anchor="w").pack(side="left", padx=(8, 0))
            val = tk.Label(row, text="—", bg=CARD, fg=MUTED, font=font(11),
                           anchor="w", justify="left", wraplength=250)
            val.pack(side="left", fill="x", expand=True)
            self.rows[key] = (c, dot, val)

        btns = tk.Frame(inner, bg=CARD)
        btns.pack(fill="x", pady=(8, 0))
        self.btn_check = self._btn(btns, "重新检查", self.check_env, kind="ghost")
        self.btn_check.pack(side="left")
        self.lbl_env_tip = tk.Label(btns, text="", bg=CARD, fg=MUTED, font=font(10))
        self.lbl_env_tip.pack(side="left", padx=8)

    def _set_row(self, key, state, value):
        canvas, dot, lbl = self.rows[key]
        color = {"ok": OK, "warn": WARN, "err": ERR, "idle": "#D6D0C2"}[state]
        canvas.itemconfigure(dot, fill=color)
        lbl.configure(text=value, fg=TEXT if state in ("ok", "warn") else MUTED)

    # ------------------------------------------------------------ 卡片 3：运行
    def _build_run_card(self, parent):
        inner = self._card(parent, "③ 开始侧载", "运行时需要管理员权限")

        # —— 注入目标
        row = tk.Frame(inner, bg=CARD)
        row.pack(fill="x")
        tk.Label(row, text="注入目标", bg=CARD, fg=MUTED, font=font(11),
                 width=6, anchor="w").pack(side="left")
        self.cmb_pkg = ttk.Combobox(row, values=["ALL（所有已装应用都显示可更新）"],
                                    font=font(11), state="normal")
        self.cmb_pkg.set("ALL")
        self.cmb_pkg.pack(side="left", fill="x", expand=True)

        tip = tk.Label(inner, text="一般保持 ALL；只在注入不生效时，填一个车机上已装应用的包名。",
                       bg=CARD, fg=MUTED, font=font(10), anchor="w",
                       justify="left", wraplength=350)
        tip.pack(fill="x", pady=(4, 0))

        # —— 高级选项折叠区
        adv_bar = tk.Frame(inner, bg=CARD)
        adv_bar.pack(fill="x", pady=(9, 0))
        self.lbl_adv = tk.Label(adv_bar, text="▸ 高级选项", bg=CARD, fg=ACCENT,
                                font=font(11), cursor="pointinghand")
        self.lbl_adv.pack(side="left")
        self.lbl_adv.bind("<Button-1>", lambda _e: self._toggle_advanced())
        self.lbl_adv.bind("<Enter>", lambda _e: self.lbl_adv.configure(fg=ACCENT_D))
        self.lbl_adv.bind("<Leave>", lambda _e: self.lbl_adv.configure(fg=ACCENT))
        self.lbl_adv_hint = tk.Label(adv_bar, text="排错时打开", bg=CARD, fg=MUTED,
                                     font=font(10))
        self.lbl_adv_hint.pack(side="left", padx=6)

        self.adv = tk.Frame(inner, bg=CARD)

        # 拦截模式（--all-443）
        r1 = tk.Frame(self.adv, bg=CARD)
        r1.pack(fill="x", pady=(4, 0))
        tk.Label(r1, text="拦截范围", bg=CARD, fg=MUTED, font=font(11),
                 width=6, anchor="w").pack(side="left")
        self.var_mode = tk.StringVar(value="targets")
        for txt, val in (("仅极氪域名", "targets"), ("所有 443", "all443")):
            rb = tk.Radiobutton(r1, text=txt, variable=self.var_mode, value=val,
                                bg=CARD, fg=TEXT, activebackground=CARD,
                                activeforeground=TEXT, font=font(11),
                                selectcolor=CARD, anchor="w",
                                command=self._on_mode_change)
            rb.pack(side="left", padx=(0, 8))

        # 全量解密（--intercept-all）
        r2 = tk.Frame(self.adv, bg=CARD)
        r2.pack(fill="x", pady=(4, 0))
        self.var_intall = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(r2, text="全量解密（--intercept-all，可能让证书固定的应用暂时异常）",
                            variable=self.var_intall, bg=CARD, fg=TEXT,
                            activebackground=CARD, activeforeground=TEXT,
                            font=font(10), selectcolor=CARD, anchor="w")
        cb.pack(side="left")

        # 域名后缀（--hosts）
        r3 = tk.Frame(self.adv, bg=CARD)
        r3.pack(fill="x", pady=(4, 0))
        tk.Label(r3, text="域名后缀", bg=CARD, fg=MUTED, font=font(11),
                 width=6, anchor="w").pack(side="left")
        self.ent_hosts = tk.Entry(r3, font=font(11), relief="solid", bd=1,
                                  highlightthickness=0, bg=CARD, fg=TEXT)
        self.ent_hosts.insert(0, "zeekrlife.com")
        self.ent_hosts.pack(side="left", fill="x", expand=True)

        # 目标域名（--domains）
        r4 = tk.Frame(self.adv, bg=CARD)
        r4.pack(fill="x", pady=(4, 0))
        tk.Label(r4, text="目标域名", bg=CARD, fg=MUTED, font=font(11),
                 width=6, anchor="w").pack(side="left")
        self.ent_domains = tk.Entry(r4, font=font(11), relief="solid", bd=1,
                                    highlightthickness=0, bg=CARD, fg=TEXT)
        self.ent_domains.insert(0, "snc-api-gw.zeekrlife.com snc-download-cdn.zeekrlife.com")
        self.ent_domains.pack(side="left", fill="x", expand=True)

        tip2 = tk.Label(self.adv, text="后缀：只解密这些域名的流量；目标：pf 重定向的域名。"
                                       "「所有 443」时目标域名仅用于挡 IPv6。",
                        bg=CARD, fg=MUTED, font=font(10), anchor="w",
                        justify="left", wraplength=350)
        tip2.pack(fill="x", pady=(5, 0))

        # —— 开始 / 停止
        self.btns_row = tk.Frame(inner, bg=CARD)
        self.btns_row.pack(fill="x", pady=(11, 0))
        self.btn_start = self._btn(self.btns_row, "开始侧载", self.start, kind="primary")
        self.btn_start.pack(side="left", fill="x", expand=True)
        self.btn_stop = self._btn(self.btns_row, "停止并恢复", self.stop, kind="ghost")
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.btn_stop.set_state("disabled")

        self.prog = ttk.Progressbar(inner, mode="indeterminate",
                                    style="Slim.Horizontal.TProgressbar")
        self.prog.pack(fill="x", pady=(10, 0))

    def _toggle_advanced(self):
        self._advanced_visible = not self._advanced_visible
        if self._advanced_visible:
            self.lbl_adv.configure(text="▾ 高级选项")
            self.adv.pack(fill="x", before=self.btns_row)
        else:
            self.lbl_adv.configure(text="▸ 高级选项")
            self.adv.pack_forget()
        # 折叠/展开会改变左侧内容高度，刷新滚动区与滚动条
        self.root.after(30, self._refresh_left_scroll)

    def _refresh_left_scroll(self):
        self.left_canvas.configure(scrollregion=self.left_canvas.bbox("all"))
        self._sync_scrollbar()

    def _on_mode_change(self):
        # 「所有 443」时目标域名不再用于 pf 重定向，仅用于 IPv6 回退；不必禁用输入。
        pass

    # ------------------------------------------------------------ 日志区
    def _build_log(self, parent):
        wrap = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(fill="both", expand=True)

        bar = tk.Frame(wrap, bg=CARD)
        bar.pack(fill="x", padx=14, pady=(11, 0))
        tk.Label(bar, text="运行日志", bg=CARD, fg=TEXT, font=font(12, "bold")).pack(side="left")
        for txt, cmd in (("打开目录", self.open_logs), ("清空", self.clear_log)):
            b = tk.Label(bar, text=txt, bg=CARD, fg=MUTED, font=font(10),
                         cursor="pointinghand")
            b.pack(side="right", padx=(10, 0))
            b.bind("<Button-1>", lambda _e, c=cmd: c())
            b.bind("<Enter>", lambda _e, w=b: w.configure(fg=ACCENT))
            b.bind("<Leave>", lambda _e, w=b: w.configure(fg=MUTED))

        # —— 四阶段步骤指示器 ——
        steps_wrap = tk.Frame(wrap, bg=CARD)
        steps_wrap.pack(fill="x", padx=14, pady=(9, 0))
        self._step_labels = []
        self._step_dots = []
        self._step_circle_ids = []
        STEP_NAMES = ("启动监听", "拦截请求", "注入更新", "替换下发")
        for i, name in enumerate(STEP_NAMES):
            cell = tk.Frame(steps_wrap, bg=CARD)
            cell.pack(side="left", expand=True, fill="x")
            dot = tk.Canvas(cell, width=14, height=14, bg=CARD, highlightthickness=0)
            dot.pack(side="left", padx=(0, 6))
            circ = dot.create_oval(2, 2, 12, 12, fill="#DDD8CD", width=0)
            lbl = tk.Label(cell, text=name, bg=CARD, fg=MUTED, font=font(11))
            lbl.pack(side="left")
            if i < len(STEP_NAMES) - 1:
                tk.Label(cell, text="›", bg=CARD, fg="#D0CBC0",
                         font=font(13)).pack(side="right", padx=(0, 4))
            self._step_dots.append(dot)
            self._step_labels.append(lbl)
            self._step_circle_ids.append(circ)

        # —— 提示行（具体引导）——
        self.banner = tk.Label(wrap, text="选择 APK 后点击「开始侧载」，引擎会先监听车机请求。",
                               bg="#F1EDE4", fg=MUTED, font=font(11), anchor="w",
                               padx=12, pady=7, justify="left", wraplength=640)
        self.banner.pack(fill="x", padx=14, pady=(7, 0))

        holder = tk.Frame(wrap, bg=LOG_BG)
        holder.pack(fill="both", expand=True, padx=14, pady=(9, 14))

        self.txt = tk.Text(holder, bg=LOG_BG, fg=LOG_FG, insertbackground=LOG_FG,
                           font=font(11, family=F_MONO), relief="flat",
                           padx=12, pady=10, wrap="word", state="disabled",
                           selectbackground="#4A4233")
        sb = tk.Scrollbar(holder, command=self.txt.yview, width=12)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)

        self.txt.tag_configure("ok", foreground=LOG_OK)
        self.txt.tag_configure("err", foreground=LOG_ERR)
        self.txt.tag_configure("warn", foreground=LOG_WARN)
        self.txt.tag_configure("muted", foreground=LOG_MUTED)
        self.txt.tag_configure("head", foreground="#A99C7C")
        self.txt.tag_configure("inject", foreground="#12100C", background=LOG_GOLD_BG)
        self.txt.tag_configure("replace", foreground="#12100C", background="#84D2A4")

    # ------------------------------------------------------------ 通用控件
    def _btn(self, parent, text, cmd, kind="ghost"):
        return FlatButton(parent, text, cmd, kind=kind)

    # ------------------------------------------------------------ 日志
    def _log(self, text, tag=None):
        self.txt.configure(state="normal")
        if tag is None:
            if "[inject-update]" in text:
                tag = "inject"
            elif "[replace-apk]" in text:
                tag = "replace"
            elif text.startswith("[ok]") or "✓" in text:
                tag = "ok"
            elif "警告" in text or text.startswith("⚠"):
                tag = "warn"
            elif "错误" in text or "失败" in text or "Sorry" in text:
                tag = "err"
            elif text.startswith("==") or text.startswith("----"):
                tag = "head"
        self.txt.insert("end", text.rstrip() + "\n", tag or ())
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def clear_log(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")

    def _hint(self, text, kind="idle"):
        palette = {
            "idle": ("#F1EDE4", MUTED),
            "work": ("#FBF3E1", WARN),
            "action": ("#F4E7C8", "#6B4A0C"),
            "good": ("#E6F2EA", OK),
            "err": ("#FBE9E6", ERR),
        }
        bg, fg = palette.get(kind, palette["idle"])
        self.banner.configure(text=text, bg=bg, fg=fg)

    def _set_step(self, idx, state):
        """驱动四阶段步骤指示器。state: 0 未开始 / 1 进行中 / 2 已完成。"""
        colors = {0: "#DDD8CD", 1: ACCENT, 2: OK}
        fg = {0: MUTED, 1: TEXT, 2: TEXT}
        for i in range(len(self._step_labels)):
            if i < idx:
                s = 2
            elif i == idx:
                s = state
            else:
                s = 0
            self._step_dots[i].itemconfigure(self._step_circle_ids[i],
                                             fill=colors[s])
            self._step_labels[i].configure(fg=fg[s])
        # 进行中的阶段用加粗强调
        for i in range(len(self._step_labels)):
            self._step_labels[i].configure(
                font=font(11, "bold" if i == idx and state == 1 else "normal"))

    # ------------------------------------------------------------ 配置
    def _load_cfg(self):
        try:
            with open(CFG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
            if cfg.get("pkg"):
                self.cmb_pkg.set(cfg["pkg"])
            if cfg.get("mode") in ("targets", "all443"):
                self.var_mode.set(cfg["mode"])
            self.var_intall.set(bool(cfg.get("intercept_all")))
            if cfg.get("hosts"):
                self.ent_hosts.delete(0, "end")
                self.ent_hosts.insert(0, cfg["hosts"])
            if cfg.get("domains"):
                self.ent_domains.delete(0, "end")
                self.ent_domains.insert(0, cfg["domains"])
        except Exception:                            # noqa: BLE001
            pass

    def _save_cfg(self):
        try:
            os.makedirs(CFG_DIR, exist_ok=True)
            with open(CFG_FILE, "w", encoding="utf-8") as f:
                json.dump({"pkg": self.cmb_pkg.get().strip() or "ALL",
                           "mode": self.var_mode.get(),
                           "intercept_all": self.var_intall.get(),
                           "hosts": self.ent_hosts.get().strip(),
                           "domains": self.ent_domains.get().strip()},
                          f, ensure_ascii=False)
        except Exception:                            # noqa: BLE001
            pass

    # ------------------------------------------------------------ 环境检查
    def check_env(self):
        if self.proc:
            return
        self.btn_check.set_state("disabled")
        self._set_row("proxy", "idle", "检查中…")
        self._set_row("iface", "idle", "检查中…")
        self._set_row("car", "idle", "检查中…")
        self._hint("正在检查网络与组件…", "work")

        def work():
            try:
                p = subprocess.run(["bash", CHECKENV], cwd=BASE,
                                   capture_output=True, text=True, timeout=90)
                out = (p.stdout or "") + (p.stderr or "")
            except Exception as exc:                 # noqa: BLE001
                out = f"错误：{exc}"
            self.q.put(("env", out))

        threading.Thread(target=work, daemon=True).start()

    def _apply_env(self, out):
        self._log("")
        self._log("── 环境检查 ──", "head")
        for line in out.splitlines():
            if line.strip():
                self._log(line)

        m = re.search(r"\[ok\] mitmdump:\s*(.+)", out)
        if m:
            self._set_row("proxy", "ok", m.group(1).replace("Mitmproxy:", "mitmproxy"))
        elif "找不到" in out:
            self._set_row("proxy", "err", "缺少 mitmdump")
        else:
            self._set_row("proxy", "warn", "未确认")

        m = re.search(r"^\s+(bridge\d+)\s+->\s+([0-9.]+)\s*$", out, re.M)
        if m:
            self._set_row("iface", "ok", f"{m.group(1)} · {m.group(2)}")
        else:
            self._set_row("iface", "err", "未开启互联网共享")

        car = re.search(r"\[ok\] ping ([0-9.]+) 通", out) or \
              re.search(r"\[ok\] ARP：([0-9.]+)", out)
        if car:
            self._set_row("car", "ok", f"已连接 · {car.group(1)}")
        else:
            self._set_row("car", "err", "未发现车机")

        self.btn_check.set_state("normal")

        if self.rows["iface"][2].cget("text").startswith("bridge"):
            if car:
                self._hint("环境就绪：可以直接开始侧载。", "good")
            else:
                self._hint("共享接口已开但没发现车机：请让车机连上这个热点，再点「重新检查」。", "work")
        else:
            self._hint("还没开热点：系统设置 → 通用 → 共享 → 互联网共享，共享到 Wi-Fi，"
                       "再让车机连上这个热点。", "work")

    # ------------------------------------------------------------ 启动
    def _ask_password(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("需要管理员权限")
        dlg.configure(bg=CARD)
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("+%d+%d" % (self.root.winfo_rootx() + 340,
                                 self.root.winfo_rooty() + 250))
        tk.Label(dlg, text="配置 pf 转发规则需要管理员权限", bg=CARD, fg=TEXT,
                 font=font(13, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
        tk.Label(dlg, text="密码只用于本次授权，不会保存到任何文件。",
                 bg=CARD, fg=MUTED, font=font(10)).pack(anchor="w", padx=18)
        ent = tk.Entry(dlg, show="•", width=30, font=font(12), relief="solid",
                       bd=1, highlightthickness=0)
        ent.pack(padx=18, pady=12, ipady=4)
        ent.focus_set()
        res = {"v": None}

        def ok(_e=None):
            res["v"] = ent.get()
            dlg.destroy()

        bf = tk.Frame(dlg, bg=CARD)
        bf.pack(fill="x", padx=18, pady=(0, 16))
        self._btn(bf, "取消", dlg.destroy).pack(side="right")
        b = self._btn(bf, "授权", ok, kind="primary")
        b.pack(side="right", padx=(0, 8), ipadx=14)
        ent.bind("<Return>", ok)
        dlg.wait_window()
        return res["v"]

    def _ensure_sudo(self):
        """已缓存则用 -n；否则问一次密码，并在本次运行里用 -S 直接喂给 sudo。"""
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            self._pw = None
            return True
        for _ in range(3):
            pw = self._ask_password()
            if pw is None:
                return False
            p = subprocess.run(["sudo", "-S", "-p", "", "-v"],
                               input=pw + "\n", capture_output=True, text=True)
            if p.returncode == 0:
                self._pw = pw
                return True
            messagebox.showerror("密码不对", "管理员密码验证失败，请重试。")
        return False

    def _sudo_argv(self, *args):
        """构造 sudo 命令：有密码走 -S 从 stdin 喂，否则 -n。"""
        if self._pw:
            return ["sudo", "-S", "-p", ""] + list(args)
        return ["sudo", "-n"] + list(args)

    def _build_cmd(self):
        """把界面上的选项组装成完整命令行（不含 sudo，方便测试与复用）。

        直接调用引擎脚本 transparent-test.sh（支持 --all-443/--intercept-all/
        --hosts/--domains 等全部参数），并补上侧载必需的 --inject-update/--replace-apk。
        不经过 zeekr-sideload.sh，因为它写死了 --all-443 --intercept-all 且不认这些参数。
        """
        pkg = self.cmb_pkg.get().strip() or "ALL"
        if pkg.startswith("ALL"):
            pkg = "ALL"
        cmd = ["bash", ENGINE,
               "--inject-update", pkg,
               "--replace-apk", self.apk_path]
        if self.var_mode.get() == "all443":
            cmd += ["--all-443"]
        if self.var_intall.get():
            cmd += ["--intercept-all"]
        hosts = (self.ent_hosts.get() or "").strip()
        domains = (self.ent_domains.get() or "").strip()
        if hosts:
            cmd += ["--hosts", hosts.replace(" ", ",")]
        if domains:
            cmd += ["--domains", domains]
        return cmd, pkg

    def start(self):
        if self.proc:
            return
        self._saw = {"listen": False, "request": False, "inject": False,
                     "replace": False, "raw": False}
        self._stop_pending = False
        self._force_cleaned = False
        if not self.apk_path or not os.path.isfile(self.apk_path):
            messagebox.showwarning("还没选 APK", "请先拖入或选择一个 .apk 文件。")
            return
        if not (self.apk_info or {}).get("zip_ok"):
            if not messagebox.askyesno("文件可疑", "这个文件不像有效的 APK，仍要继续吗？"):
                return
        if not os.access(ENGINE, os.R_OK):
            messagebox.showerror("找不到脚本", f"缺少 {ENGINE}")
            return
        if self.rows["iface"][2].cget("text").startswith("未"):
            if not messagebox.askyesno(
                    "还没检测到热点",
                    "当前没有检测到互联网共享的 bridge 接口，脚本大概率会直接失败。\n\n仍要尝试开始吗？"):
                return
        if not self._ensure_sudo():
            self._hint("已取消：没有拿到管理员权限。", "err")
            return

        self._save_cfg()

        # —— 组装参数（把高级选项映射到引擎脚本）——
        cmd, pkg = self._build_cmd()
        # 引擎脚本需要管理员权限配置 pf，包一层 sudo（有密码走 -S 从 stdin 喂）
        cmd = self._sudo_argv(*cmd)

        self._log("")
        self._log("── 开始侧载 ──", "head")
        self._log(f"  注入目标 {pkg} · 拦截范围 {self.var_mode.get()} · 全量解密 {self.var_intall.get()}",
                  "muted")
        hosts = (self.ent_hosts.get() or "").strip()
        domains = (self.ent_domains.get() or "").strip()
        if hosts:
            self._log(f"  域名后缀 {hosts}", "muted")
        if domains:
            self._log(f"  目标域名 {domains}", "muted")
        self._log("$ " + " ".join(cmd), "muted")
        try:
            kw = dict(cwd=BASE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                      text=True, bufsize=1, start_new_session=True)
            if self._pw:
                kw["stdin"] = subprocess.PIPE
            else:
                kw["stdin"] = subprocess.DEVNULL
            self.proc = subprocess.Popen(cmd, **kw)
            if self._pw:
                try:
                    self.proc.stdin.write(self._pw + "\n")
                    self.proc.stdin.flush()
                except Exception:                    # noqa: BLE001
                    pass
                self._pw = None                      # 不在内存里留密码
        except Exception as exc:                     # noqa: BLE001
            self._log(f"启动失败：{exc}", "err")
            self.proc = None
            return

        self.btn_start.set_state("disabled")
        self.btn_stop.set_state("normal")
        self.prog.start(14)
        self._set_state("运行中", WARN)
        self._set_step(0, 1)
        self._hint("正在启动监听…等下方日志出现「mitmdump 已启动」，再去车机打开应用商店。", "work")

        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()

    def _reader(self, proc):
        try:
            for line in proc.stdout:
                self.q.put(("log", line.rstrip("\n")))
                # —— 阶段推进（单调）——
                if not self._saw["listen"] and ("mitmdump 已启动" in line or "监听" in line):
                    self._saw["listen"] = True
                    self.q.put(("step", 0))
                if not self._saw["request"] and ("zeekr_log:" in line or "[inject-update]" in line
                                                or "[replace-apk]" in line):
                    self._saw["request"] = True
                    self.q.put(("step", 1))
                if "[inject-update]" in line and not self._saw["inject"]:
                    self._saw["inject"] = True
                    self.q.put(("step", 2))
                if "[replace-apk]" in line and "替换下载" in line and not self._saw["replace"]:
                    self._saw["replace"] = True
                    self.q.put(("step", 3))
                if "该下载" in line and "按原样透传" in line:
                    self._saw["raw"] = True
                    self.q.put(("hint", ("注入没生效（下载的是官方内容）：回到车机点开应用详情页重新触发，"
                                         "或强行停止应用商店后再试。", "work")))
        finally:
            code = proc.wait()
            self.q.put(("done", code))

    def _on_done(self, code):
        # 如果强制清理已经把 UI 复位了，这里不再重复处理
        if getattr(self, "_force_cleaned", False):
            return
        self.proc = None
        self.prog.stop()
        self.btn_start.set_state("normal")
        self.btn_stop.set_state("disabled")
        saw = self._saw
        if code == 0:
            self._set_state("已完成", OK)
            if saw["raw"] and not saw["replace"]:
                self._hint("已结束，但车机下载的是官方内容（替换没发生）。"
                           "回到车机点开应用详情页重新触发，或强行停止应用商店后再试。", "err")
            elif saw["replace"]:
                self._hint("已完成：APK 已下发给车机。若桌面没出现图标，重启车机或从「设置 → 应用」里打开。", "good")
            elif saw["inject"]:
                self._hint("已结束：注入成功过，但没看到替换下载——车机可能没点「更新」，或点了别的应用。", "work")
            else:
                self._hint("已结束，但全程没有 [inject-update]：商店用的是缓存元数据。"
                           "请强行停止应用商店或重启车机后重试。", "work")
        elif code in (130, -2):
            self._set_state("已停止", MUTED)
            self._hint("已停止并恢复转发规则。", "idle")
        else:
            self._set_state("异常退出", ERR)
            self._hint(f"异常退出（状态码 {code}），看日志尾部找原因；必要时点「停止并恢复」。", "err")

    def stop(self):
        if not self.proc:
            self._log("执行兜底清理：卸载 pf 规则、停止残留 mitmdump…", "warn")
            self._hint("正在清理…", "work")
            self.btn_stop.set_state("disabled")
            if not self._ensure_sudo():
                self._hint("已取消：兜底清理需要管理员权限。", "err")
                self.btn_stop.set_state("normal")
                return
            cmd = self._sudo_argv("bash", os.path.join(BASE, "scripts", "stop-transparent.sh"))
            kw = dict(capture_output=True, text=True, timeout=60, cwd=BASE)
            if self._pw:
                kw["input"] = self._pw + "\n"
            try:
                p = subprocess.run(cmd, **kw)
                out = (p.stdout or "") + (p.stderr or "")
                for line in out.splitlines():
                    if line.strip():
                        self._log(line)
                self._set_state("就绪", MUTED)
                self._hint("已执行兜底清理，转发规则已卸载。", "good")
            except Exception as exc:                 # noqa: BLE001
                self._log(f"清理失败：{exc}", "err")
                self._hint("清理失败，可手动执行：sudo bash scripts/stop-transparent.sh", "err")
            finally:
                self._pw = None
            return

        # 防止重复点击：先禁用按钮，等真正结束后由 _on_done 恢复
        self.btn_stop.set_state("disabled")
        self._log("收到停止指令，正在向引擎发送中断信号（SIGINT）…", "warn")
        self._hint("正在停止并恢复转发规则…", "work")
        self._stop_pending = True
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
        except Exception:                            # noqa: BLE001
            try:
                self.proc.terminate()
            except Exception:                        # noqa: BLE001
                pass
        # 超时兜底：3 秒内若进程仍未退出，升级为强制清理
        self.root.after(3000, self._force_stop_if_alive)

    def _force_stop_if_alive(self):
        """SIGINT 后进程仍未退出时，用 stop-transparent.sh 强制清理。"""
        if self.proc is None or self.proc.poll() is not None:
            return
        self._log("进程未响应中断信号，改用强制清理…", "warn")
        try:
            self.proc.terminate()
        except Exception:                            # noqa: BLE001
            pass
        self._ensure_sudo()
        cmd = self._sudo_argv("bash", os.path.join(BASE, "scripts", "stop-transparent.sh"))
        kw = dict(capture_output=True, text=True, timeout=60, cwd=BASE)
        if self._pw:
            kw["input"] = self._pw + "\n"
        try:
            p = subprocess.run(cmd, **kw)
            out = (p.stdout or "") + (p.stderr or "")
            for line in out.splitlines():
                if line.strip():
                    self._log(line)
        except Exception as exc:                     # noqa: BLE001
            self._log(f"强制清理失败：{exc}", "err")
        finally:
            self._pw = None
            # 强制清理后直接复位 UI，不再依赖 _on_done
            try:
                if self.proc and self.proc.poll() is None:
                    self.proc.kill()
            except Exception:                        # noqa: BLE001
                pass
            self.proc = None
            self.prog.stop()
            self.btn_start.set_state("normal")
            self.btn_stop.set_state("disabled")
            self._set_state("已停止", MUTED)
            self._hint("已强制停止并恢复转发规则。", "idle")
            self._force_cleaned = True

    # ------------------------------------------------------------ 状态
    def _set_state(self, text, color):
        self.state_lbl.configure(text=text, fg=color if color != MUTED else MUTED)
        self.state_dot.itemconfigure(self._dot, fill=color)

    # ------------------------------------------------------------ 队列
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "env":
                    self._apply_env(payload)
                elif kind == "hint":
                    self._hint(*payload)
                elif kind == "step":
                    self._on_step(payload)
                elif kind == "hash":
                    self._apply_hashes(*payload)
                elif kind == "done":
                    self._on_done(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _on_step(self, idx):
        """阶段推进时更新指示器，并给出该阶段的等待提示。"""
        tips = {
            0: ("正在监听车机请求…现在去车机：打开应用商店，点开任意一个应用详情页。", "work"),
            1: ("已捕获车机流量。商店正在请求应用数据，等待注入元数据…", "work"),
            2: ("已伪装更新，去车机点「更新 / 安装」。", "action"),
            3: ("正在下发 APK，等车机进度走完即可安装。", "good"),
        }
        self._set_step(idx, 2)
        self._set_step(idx + 1, 1)
        if idx in tips:
            text, kind = tips[idx]
            self._hint(text, kind)

    # ------------------------------------------------------------ 其他
    def open_logs(self):
        os.makedirs(LOGS, exist_ok=True)
        subprocess.run(["open", LOGS])

    def open_readme(self):
        p = os.path.join(BASE, "README.md")
        if os.path.isfile(p):
            subprocess.run(["open", "-e", p])

    def on_close(self):
        if self.proc:
            if not messagebox.askyesno("正在运行", "侧载还在运行，退出会中断并清理转发规则。确定退出吗？"):
                return
            self.stop()
            import time
            for _ in range(40):
                if self.proc is None:
                    break
                time.sleep(0.1)
        self._save_cfg()
        self.root.destroy()


def main():
    # 优先用 tkinterdnd2（支持拖放），失败则退回普通 Tk
    root = None
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:                                # noqa: BLE001
        root = tk.Tk()
    ZeeloadApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
