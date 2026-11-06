# 极载 · ZEEload

> # 🛑 Research Preview · 请勿公开分发
>
> ### **仅限口口相传，请勿发帖、请勿宣传。**
>
> **请不要**把本项目发到微博、小红书、知乎、B 站、抖音、X（推特）、V2EX、贴吧、微信群、Telegram 群、公众号、短视频或任何论坛；
> 也**不要**提交到导航站、聚合站、Awesome 列表或开源推荐号。
>
> **原因**：本项目是**学术研究与技术探讨**性质的课题，用于观察车机应用商店的更新机制与证书信任链设计，面向的是小范围的交流与复现。
> 公开传播容易被断章取义、被当成「破解工具」转发，既偏离研究初衷，也容易带来不必要的误解与风险。
>
> 想交流的话，**私下告诉有研究兴趣的朋友就好**，并提醒对方不要外传。

![ZEEload](assets/banner.png)

在没有 root、没有 adb、车机不允许安装未知来源应用的情况下，**把任意 APK 装进极氪车机**。

原理是让车机自己的应用商店把它当成一次「应用更新」安装下去：透明解密商店流量 → 注入一条假更新 → 把下载内容换掉。全程不修改车机系统、不往车机装证书，退出即恢复。

> 当前版本：**v1.0.2**（2026-11-03）· macOS 版已在极氪 7X 实测成功（DiPlay、ES 文件浏览器、MT管理器）；**Windows 版也已实测可用**
> 技术原理与安全分析见 [docs/技术路径-车机APK侧载.md](docs/技术路径-车机APK侧载.md)
> 本项目是 **AI 辅助编程项目**：需求、方案与实测由作者主导，代码与文档在 AI 协助下完成，可能存在未知缺陷，请自行审阅与评估。

---

## 目录

- [下载（发布包）](#下载发布包)
- [适用条件](#适用条件)
- [环境要求（版本）](#环境要求版本)
- [原理](#原理)
- [两个漏洞的组合](#两个漏洞的组合)
- [快速开始（macOS）](#快速开始macos)
- [图形界面（GUI）](#图形界面gui)
- [改包名工具（研究用）](#改包名工具研究用)
- [Windows](#windows)
- [结果判读](#结果判读)
- [常见问题](#常见问题)
- [让 AI 帮你配置](#让-ai-帮你配置)
- [已知限制](#已知限制)
- [安全与合规](#安全与合规)
- [文件结构](#文件结构)

## 下载（发布包）

到 [Releases](https://github.com/mamage123/ZEELoad/releases) 下载对应平台的压缩包：

| 平台 | 发布包 | 解压后 |
|---|---|---|
| Windows 10 / 11 x64 | `ZEELoad-Windows-x64.zip`（约 30 MB，**解压即用**） | 双击 `ZEELoad\ZEELoad.exe`（会弹 UAC），图形界面里选 APK → 点「开始」 |
| macOS 13+ | `ZEELoad-macOS.zip`（约 0.4 MB） | 先装 mitmproxy（见下），再双击 `ZEELoad\一键侧载安装.command`，把 APK 拖上去 |

> ⚠️ Windows 包必须**整个 `ZEELoad` 文件夹一起解压使用**。只把 `ZEELoad.exe` 拖出来会报
> `Failed to load Python DLL ... _internal\python312.dll`——程序依赖同目录的 `_internal\`。
>
> 🍎 macOS 包是脚本集合（已带 Unix 权限、LF 换行），**不含 mitmproxy**：
> `pip3 install mitmproxy`（或 `python3 -m venv venv && ./venv/bin/pip install mitmproxy`，脚本会自动识别包内 `venv/`）。
> 从浏览器下载后若提示「无法验证开发者」，右键 →「打开」，或执行 `xattr -dr com.apple.quarantine ZEELoad`。
>
> 两个包都不含任何第三方 APK，也不联网上传数据；日志只写在本机。

## 适用条件

| 项目 | 要求 |
|---|---|
| 车机 | Android 车机，且系统 **仍信任 emSign 根证书**（国内车机大多没有 GMS，未收到封禁列表；2026-10-22 之后更新过信任库的车机可能失效） |
| 电脑 | macOS（已验证）或 Windows 10/11 x64（已验证） |
| 网络 | 电脑给车机开热点/互联网共享，车机连上后能上网 |
| 权限 | 电脑需要一次管理员权限（配置 pf / 加载 WinDivert 驱动） |
| 车机侧 | 无需任何设置、无需装证书、无需开未知来源 |

**只用于你自己的车辆。** 详见[安全与合规](#安全与合规)。

## 环境要求（版本）

| 组件 | 最低要求 | 本项目实测 | 说明 |
|---|---|---|---|
| Python | **3.12** | 3.12.7 | mitmproxy 12.3+ 的硬性要求；3.10 / 3.11 装不到支持 `--emudhra` 的版本 |
| mitmproxy | **12.3** | 12.3.1 | `--emudhra` 从 12.3 起提供 |
| pydivert（仅 Windows） | 3.1+ | 3.1.3 | WinDivert 的 Python 绑定，自带驱动；版本由 mitmproxy 12.3 的约束解析（它锁 `pydivert<=3.1.3`） |
| pip | 任意较新版本 | 24.x | `python -m pip install -U pip` |
| macOS | 13+ | 15.6.1（arm64） | 依赖系统自带的 `pf`、互联网共享 |
| Windows | 10 / 11 x64 | 10 21H2（19044）实测通过 | 需要管理员权限 + 移动热点（ICS） |

检查命令：

```bash
python3 --version
mitmdump --version            # 需要 Mitmproxy 12.3+
python3 -m pip show mitmproxy pydivert | grep -E "^(Name|Version)"
```

> Windows 上如果默认 `python` 是 3.10/3.11，请显式用 `py -3.12`；工具检测到低版本时会自动尝试 `py -3.12` 重新运行。

## 原理

```text
车机 ──> 电脑热点
          ├─ 透明转发：车机到 *.zeekrlife.com 的 443 全部转到本机（macOS: pf，Windows: WinDivert）
          ├─ 解密：mitmproxy --emudhra，车机信任这条链，所以能解开 TLS
          ├─ 注入：商店「检查更新」时，把已安装应用的版本改成更高、哈希/大小指向目标 APK
          └─ 替换：商店真正下载时，把响应体换成目标 APK（按 Range 正确切分）
车机商店：哈希校验通过 → 请求签名（服务端对非官方哈希返回 null，商店不拦）→ 安装器按「新应用」装上
```

四个关键点（都在实测中确认过）：

1. 车机接受 mitmproxy 内置的 eMudhra 链，**不需要往车机装任何证书**；
2. 商店的哈希校验基准来自 appList 元数据，而元数据走同一条可解密的 TLS，可以一起改写；
3. 服务端只给官方哈希签名（非官方返回 `sign:null`），但**商店/安装器不因 null 中止**；
4. 包名不同会被安装器当成**新应用**安装 —— 所以只能装新包，不能覆盖已装应用。

## 两个漏洞的组合

本方法**不是单点突破**，而是把两个独立的安全问题串起来用——缺一不可：

| | 漏洞 | 在本项目里的作用 |
|---|---|---|
| **A. CA 证书链不可信** | eMudhra 中间 CA 私钥泄露（2026-10-17 披露），车机系统仍信任该链 | 让网关能够**解密并改写**商店的 HTTPS（元数据、下载内容） |
| **B. 商店安装授权逻辑不一致** | 直接安装路径要求有效 `sign`；而「更新已安装应用」路径**不校验** `sign`——服务端返回 `sign: null` 仍继续下载并安装 | 让改写后的第三方 APK 以「更新」名义**绕过安装授权** |

```text
A：解密 + 改写 TLS
   └─ 把「安装任意 APK」伪装成「某个已安装应用有新版本」
        └─ B：更新路径不校验 sign
             └─ 目标 APK 以「更新」名义被安装
```

单独利用任何一个都不够：

- **只有 A**：能看能改，但任意 APK 拿不到有效签名，卡在授权；
- **只有 B**：需要能改写商店流量才能把「更新」指向自己的 APK，而 HTTPS 挡住了；
- **A + B**：才能把「任意 APK」送进安装流程。

实测证据（2026-10-30）：服务端对非官方哈希返回 `sign: null`，商店仍完成下载并安装 DiPlay 0.2.22。完整论证、A/B 对照与厂商修复建议见 [docs/技术路径-车机APK侧载.md §4.5](docs/技术路径-车机APK侧载.md#45-两个漏洞的组合核心结论)。

> 这不是「破解签名」：APK 签名和服务端签名服务本身都没被攻破，被绕过的是校验点。

## 快速开始（macOS）

### 1. 安装 mitmproxy

脚本会自动在以下位置找 `mitmdump`，任选一种即可：

```bash
# 方式 A：系统/Python 环境
pip3 install mitmproxy

# 方式 B：包内虚拟环境（推荐，不污染系统）
python3 -m venv venv && ./venv/bin/pip install mitmproxy
```

### 2. 开热点、连车机

系统设置 → 通用 → 共享 → **互联网共享**，共享来源选你的上网接口，共享到 Wi-Fi；车机连上这个热点。

### 3. 一键侧载

把要装的 APK **拖到 `一键侧载安装.command` 上**（或双击后输入路径），输入 Mac 密码。

脚本会自动完成：探测共享接口（`bridge*`）→ 从 DHCP 租约识别车机 → 配置 pf 独立 anchor → 启动 mitmdump → 注入 + 替换。

### 4. 车机侧操作

1. 打开应用商店 → **点开任意一个应用的详情页**（详情页会实时请求元数据，这是注入生效的关键入口）；
2. 看电脑终端出现：

   ```
   [inject-update] 已为 ALL 注入新版本（N 个下载地址已武装）
   ```

3. 在详情页点「更新 / 安装」，接着应出现：

   ```
   [replace-apk] 以 xxx.apk (NNNN 字节) 替换下载，Range=...
   ```

4. 进度走完即安装完成，按 **Ctrl-C** 结束（会自动卸载 pf 规则）。

装完如果图标没出现，重启车机或等桌面刷新；部分应用需要额外硬件（如 DiPlay 需要 CarPlay 转换盒）。

### 手动 / 高级用法

```bash
# 指定 APK 与注入目标（默认 ALL：所有已安装应用都伪装成可更新）
sudo bash scripts/zeekr-sideload.sh --apk /path/app.apk
sudo bash scripts/zeekr-sideload.sh --apk app.apk --pkg com.zeekr.media.podcast

# 只看会执行什么，不改系统（无需密码）
bash scripts/transparent-test.sh --check-only --all-443

# 环境自检
bash scripts/check-environment.sh
```

可用环境变量覆盖自动探测：`ZEEKR_IFACE`、`ZEEKR_CAR_IP`、`ZEEKR_CAR_MAC`、`ZEEKR_VENV`、`ZEEKR_DOMAINS`、`ZEEKR_HOSTS`。

## 图形界面（GUI）

macOS 另提供一个 Tkinter 图形界面 `gui/zeeload_gui.py`，把侧载流程做成了可视化操作：

```bash
./venv/bin/python gui/zeeload_gui.py
```

界面包含：四阶段进度指示（启动监听 → 拦截请求 → 注入更新 → 替换下发）、APK 拖入解析、拦截范围（仅极氪域名 / 全部 443）、注入目标（默认 `ALL`）、高级选项（域名 / 后缀 / 环境变量覆盖）等。

解析 APK 时会调用 build-tools 自带的 `aapt dump badging` 读出**权威包名、应用名、原生架构**（不再是启发式猜测）。

> GUI 依赖 Tkinter（macOS 系统 Python 自带）。如果用的 venv 没有 tkinter，退回 `一键侧载安装.command` 命令行入口即可。

## 改包名工具（研究用）

`tools/repack-sign.sh` 用于把任意 APK 的包名改成极氪应用市场上架的包名、并重新签名（v1+v2+v3），是研究「仅支持上架应用」白名单边界时用到的辅助脚本：

```bash
./tools/repack-sign.sh <原始APK> <新包名> [输出文件名]
# 例：./tools/repack-sign.sh 酷我.apk com.netease.cloudmusic.iot 伪装包.apk
```

脚本依赖 `apktool.jar`、免安装 JDK17（含 `apksigner`/`zipalign`）、`sign.jks` 签名密钥，这些二进制均不入库，需自行放到 `tools/` 下（脚本内有说明）。

> ⚠️ **重要结论**：改包名**不能**绕过「仅支持上架应用」这道校验。白名单校验的是「包名 + 服务端 `sign` 授权」的完整链路——非上架应用既不在包名白名单里，也拿不到服务端签名（`sign:null`），改包名只会撞上「签名证书不一致」或「全新安装需 sign」这两堵墙。详见[已知限制](#已知限制)。

## Windows

`windows/` 是自包含版本，用 **WinDivert** 代替 pf，用本地 **SNI 分流器**把流量喂给 mitmproxy（Windows 没有 pf，mitmproxy 透明模式不可用）。

### 用发布包（推荐）

解压 `ZEELoad-Windows-x64.zip` → 双击 `ZEELoad\ZEELoad.exe`（弹 UAC 点「是」）→ 选 APK → 点「开始」。界面里还有「放行防火墙」「抓包诊断」「诊断」几个按钮，排障时很有用。

### 从源码运行

```powershell
cd windows
python -m pip install -U mitmproxy pydivert

# 以管理员身份运行
python win_sideload.py --apk "C:\path\app.apk"
```

或直接双击 `windows\一键侧载-Windows.bat` 并拖入 APK（会自动申请管理员权限）。

常用参数：`--proxy-only`（只起 HTTP 代理，不需要管理员）、`--hotspot-ip`（手动指定热点网卡）、`--sniff 30`（抓包诊断）、`--emudhra-old`（老信任库车机）。

详细说明、排错与限制见 [windows/README.md](windows/README.md)。

## 结果判读

| 终端 / 车机现象 | 含义 | 处理 |
|---|---|---|
| `[inject-update] ... 已武装` | 元数据注入成功 | 可以去点更新了 |
| 没有 `[inject-update]` | 商店用了缓存，没重新拉元数据 | **点开应用详情页**；仍不行就重启车机 |
| `[replace-apk] 以 xxx.apk 替换下载` | 替换成功 | 等安装完成 |
| `[replace-apk] 该下载...按原样透传` | 注入没生效，下载的是官方内容 | 同上，先让注入成功 |
| 商店报「下载失败」 | 内容哈希与元数据对不上（替换没发生） | 检查上面的日志与机型 |
| 安装报「包名冲突」 | 目标 APK 与已安装应用同名 | 换包名不同的 APK |
| 装上了但桌面没图标 | 车机桌面过滤了非白名单应用 | 重启车机；从「设置 → 应用」里直接打开 |

## 常见问题

**Q：会不会把车机弄坏？**
不会。全程只改电脑上的转发规则和发给车机的响应内容，不写车机系统、不装证书、不改分区。退出脚本即恢复；车机断网就关掉脚本或跑 `停止并恢复.command`。

**Q：能覆盖/升级已安装的应用吗？**
不能。安装器要求更新包与原应用包名、签名一致；本方法装的是**新包**。

**Q：为什么一定要点「应用详情页」？**
商店对列表/更新结果做了缓存，改缓存里的哈希不会生效；详情页是少数会实时请求元数据的入口。日志里出现 `[inject-update]` 就说明注入到位。

**Q：为什么服务端返回 `sign:null` 也能装？**
实测商店与安装器都不校验这个签名（或只作透传）。这是本方法成立的关键前提之一，商店/车机 OTA 更新后可能改变。

**Q：macOS 提示找不到 mitmdump？**
按[快速开始](#快速开始macos)装好；或在包内建 `venv/`，脚本会自动用它。

**Q：Windows 上 443 被循环劫持？**
已处理：WinDivert 过滤器只匹配热点网段（`x.x.x.2–254`），不会把本机 mitmproxy 的上游连接也劫持。若你改了热点网段，请同步改 `windows/win_sideload.py` 里的判断。

**Q：Windows 发布包需要装 Python 吗？**
不需要。`ZEELoad-Windows-x64.zip` 里已经内置 Python 3.12、mitmproxy、WinDivert 驱动，解压双击即可。只有从源码运行才需要 Python 3.12+。

**Q：Windows 版双击没反应 / 一闪而过？**
按顺序检查：① 是不是只把 `ZEELoad.exe` 拖出来了（必须整个 `ZEELoad` 文件夹一起解压）；② UAC 弹窗有没有点「是」（透明模式要管理员）；③ 看 `ZEELoad\logs\gui-run-*.log`，或点界面里的「诊断」。

## 让 AI 帮你配置

把项目地址 **https://github.com/mamage123/ZEELoad** 直接交给 AI，让它自己完成环境配置并把工具跑起来。

## 已知限制

- **只能装新包**，不能替换已安装应用；
- **「仅支持上架应用」白名单无法通过改包名绕过**：商店放行的前提是「包名在上架名单 + 服务端签发有效 `sign`」。非上架应用（如酷我音乐 `cn.kuwo.player`）既不在名单里、也拿不到官方哈希对应的 `sign`（服务端恒返回 `null`）；改包名成上架包名后，要么因「签名证书不一致」被拒（该包名已安装），要么退回「全新安装」路径仍需有效 `sign`。这是机制性边界，非参数问题；
- **仅 IPv4 透明转发**（CDN 有 AAAA，macOS 版会用 `block return` 把目标域名的 IPv6 挡掉、逼回 IPv4；Windows 版依赖 ICS 不给客户端 IPv6）；
- 全量解密（`--intercept-all`）可能让个别做了证书固定的车机应用暂时异常，退出脚本即恢复；
- 商店「检查更新」有缓存，必须靠**详情页**触发新元数据；
- 车机 OTA / 商店更新后，信任库或校验逻辑可能变化，需要重新验证；
- **Windows 版**：必须用管理员运行（WinDivert 加载内核驱动），且依赖「移动热点」的 ICS 转发；车机如果自动切回蜂窝网络、或商店只走 QUIC，会拦截不到（工具会丢弃 QUIC 逼它回退 TCP，日志里有提示）。

## 安全与合规

> **本项目仅限自有车辆的研究与自用，严禁用于任何商业用途**：不得收费代装、不得作为付费服务、不得随产品捆绑、不得用于付费培训或咨询，以及任何形式的变现。

- 仅用于**你名下的车辆**；请勿用于他人车辆，或用于规避付费与授权；
- **质保风险自行辨别、自行承担**：向车机安装非官方应用可能被厂商 / 4S 店认定为影响质保，进而拒绝保修或拒赔；是否操作、能否接受，请自行判断，相关后果由使用者自行承担；
- 安装的 APK 由使用者自行负责来源与合法性；仓库与发布包均不附带任何第三方 APK；
- 工具不收集、不上传任何数据，所有日志只落在本机 `logs/`；
- 使用前请确认当地法律法规与车辆保修条款；因使用本项目产生的一切法律与财产风险由使用者自行承担；
- 本项目仅做技术探讨，代码未经第三方安全审计，不提供任何形式的担保，**不得用于盈利用途**。

## 文件结构

```text
zeeload/
├── README.md                    本文档
├── 一键侧载安装.command          ★ 主入口（拖入 APK）
├── 停止并恢复.command            兜底：卸载规则、停代理
├── 检查环境.command              只读诊断
├── scripts/
│   ├── zeekr-sideload.sh         侧载入口（算哈希、调引擎）
│   ├── transparent-test.sh       引擎：pf 转发 + mitmdump 生命周期（自动探测接口/车机）
│   ├── stop-transparent.sh       卸载规则
│   ├── check-environment.sh      环境自检
│   └── inspect-pf.sh             只读导出 pf 规则（排障用）
├── addons/zeekr_log.py           mitmproxy 插件（注入 / 替换 / 记录）
├── gui/zeeload_gui.py            macOS 图形界面（Tkinter）
├── tools/repack-sign.sh          改包名 + 重签名辅助脚本（研究用，二进制依赖不入库）
├── windows/                      Windows 版（WinDivert + SNI 分流 + 图形界面）
├── assets/                       Logo 与宣传图（svg / png / icns / ico）
├── docs/
│   └── 技术路径-车机APK侧载.md    原理、漏洞分析、证据、接口字段
├── release/                      本地存放待上传的发布包（zip，不入库）
├── lab/                          本机实验脚本（未纳入版本库）
├── artifacts/                    本机下载的 APK（未纳入版本库）
├── evidence/                     实测证据（未纳入版本库）
└── logs/                         每次运行的输出（未纳入版本库）
```

## 版本

### v1.0.2（2026-11-03）

macOS 图形界面与改包名研究工具：

- **macOS 图形界面** `gui/zeeload_gui.py`：四阶段进度、APK 拖入解析、拦截范围与注入目标可选、高级选项
- **APK 解析改用 `aapt`**：读出权威包名 / 应用名 / 原生架构，替代原来的二进制 manifest 启发式猜测（旧逻辑会把主题资源名 `Theme.Emui.Translucent` 误判为包名）
- **修复 appList 注入崩溃**：`addons/zeekr_log.py` 的 `_inject_update` 兼容 `data` 直接为数组（list）的情况，不再抛 `'list' object has no attribute 'get'`
- **扩充车机探测关键词**：`check-environment.sh` / `transparent-test.sh` 加入 `sa8155/sa515m/qcm/sm6350` 等；ping 无响应改为正常提示（车机通常屏蔽 ICMP）
- **改包名工具** `tools/repack-sign.sh`：反编译 → 改包名 → 同步 namespace → 重打包 → zipalign + apksigner（v1+v2+v3），规避 `jarsigner` 只签 v1 导致 targetSdk≥30 应用「安装失败」的问题
- 明确结论：改包名无法绕过「仅支持上架应用」白名单（见[已知限制](#已知限制)）

### v1.0.1（2026-10-31）

Windows 版从 beta 转为可用，并补上图形界面：

- **Windows 图形界面**：双击 `ZEELoad.exe` 即用（黑金配色，与 logo 同一套视觉），选 APK → 点「开始」；带参数时仍走原来的命令行
- **修通 ICS 透明劫持**：车机流量经 ICS 转发，只在 WinDivert 的 `NETWORK_FORWARD` 层可见；注入时修正 `WINDIVERT_ADDRESS` 的地址层与热点网卡接口索引
- **修证书链**：mitmdump 增加 `emudhra`（车机只信任 eMudhra 链），否则 TLS 握手被车机拒绝
- **修握手超时**：分流器等 mitmproxy CONNECT 响应原来只有 10 秒超时，改为 45 秒并让 mitmproxy 用 `connection_strategy=lazy`
- **QUIC 处理**：默认丢弃 `UDP 443`，逼商店回退到可解密的 TCP
- 新增 `--hotspot-ip` / `--sniff` / `--allow-quic` / `--emudhra-old`，以及「放行防火墙」「抓包诊断」「诊断」按钮、运行日志落盘
- 发布包：`ZEELoad-Windows-x64.zip`（解压即用，不需要 Python）

### v1.0.0（2026-10-30）

首个版本，项目命名 **极载 · ZEEload**。

- **macOS**：一键侧载（拖入 APK），pf 透明转发 + mitmproxy `--emudhra` 解密
- **Windows（beta）**：WinDivert 重定向 + 本地 SNI 分流，共用同一套注入/替换逻辑
  - 启动脚本自动提权、纯 ASCII 输出；自动定位 `mitmdump.exe`（`Scripts\` / `%APPDATA%` / PATH / 内联）
  - 要求并自动切换到 Python 3.12+，启动时校验 mitmproxy ≥ 12.3
  - WinDivert 按方向过滤（只改写 INBOUND 车机包与分流器 OUTBOUND 回程包）
  - `windows/selftest.py` 自检：函数完整性、SNI 解析、mitmproxy 版本
- 自动探测：共享接口（`bridge*`）、车机（DHCP 租约）、mitmdump 位置
- 更新注入支持 appList 与 app/detail 详情页两种响应
- 大响应流式转发、IPv6 回退、签名→下载时间闸门
- 独立 pf anchor、只作用于热点侧、退出自动卸载
- 黑金 Logo（svg / png / icns / ico）与宣传图
- 发布前已清除车辆识别信息（VIN/MAC/设备号/用户 ID/本机路径）

## 参考

- [mitmproxy 透明代理](https://docs.mitmproxy.org/stable/howto/transparent/)
- [mitmproxy 证书机制](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [eMudhra 事件与受影响客户端](https://emudhra.we-have-a-problem.com/)
