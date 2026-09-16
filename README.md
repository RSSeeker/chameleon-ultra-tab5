# ChameleonUltra on M5Stack Tab5

把 [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra) 的官方客户端移植到
**M5Stack Tab5**（ESP32-P4 + ESP32-C6），用触屏 + 实体键盘操作，通过 **USB** 或 **蓝牙** 连接变色龙。

当前进度：**M1 / M2 / M3 已在实机验证通过**；M5（密钥恢复）计算内核已验证，端到端恢复待真实 Classic 卡。

---

## What this is (English)

A standalone **client for the Chameleon Ultra**, running on the M5Stack Tab5
(ESP32-P4, 720×1280 touch panel, optional Tab5 Keyboard). The board talks to the
Chameleon over USB CDC and gives you the whole card toolbox on a handheld:
HF/LF scanning and cloning, emulation (LF ids, Mifare Classic, MF0/NTAG),
ISO14443-4 / EMV / SEOS, sniffer trace decoding, and Mifare Classic key recovery
(factory keys, darkside, nested, static nested, hardnested nonce acquisition,
mfkey32) — all on a touch + keyboard UI.

- **Not the official firmware.** The Chameleon Ultra itself runs its own
  firmware; this repository is a *host*, in the same sense as the official
  desktop CLI and the mobile app. It only speaks the documented USB protocol.
- **Status**: every command in upstream's `chameleon_enum.Command` is implemented
  and used, and every wave of the port is reachable from the UI. Bluetooth is out
  of scope. Real-card success paths are still untested — see
  [§7](#7-下一步) for exactly what has and has not been verified on hardware.
- **Verification**: `tools/` holds 10 host-side test suites that compare this port
  against upstream's own code (its Python client, its device firmware, crapto1,
  mfkey.c, nested, hardnested) rather than against hand-written expectations.
  They all pass; see [§1](#1-快速开始).
- **License**: GPL-3.0-or-later, because it derives from GPL-3.0 upstream code.

```powershell
git clone https://github.com/RSSeeker/chameleon-ultra-tab5
cd chameleon-ultra-tab5\firmware
& "D:\esp\esp-idf-v5.4.2\export.ps1"   # ESP-IDF v5.4.2
idf.py build
idf.py -p COM4 flash                   # then reboot the board by hand
```

The third-party components are vendored under `firmware/components/`, so the
build needs no network access.

---

## 1. 快速开始

### 编译

```powershell
# 已验证环境：ESP-IDF v5.4.2
& "D:\esp\esp-idf-v5.4.2\export.ps1"
cd firmware
idf.py build
```

依赖**全部离线**（见 `firmware/components/`），不需要访问 `components.espressif.com`。
唯一从注册表拉过的是 `espressif/cmake_utilities`，它也已经放在
`firmware/managed_components/` 里一起提交了。

LVGL 9.2.2 也是随仓库提交的，但**去掉了它的 `demos/`（45 MB）和 `examples/`（7 MB）**：
`CONFIG_LV_BUILD_EXAMPLES=n`，本项目不调用任何 `lv_example_*()`。这两个目录本身
仍然保留（里面各有一个 `.gitkeep` 说明原因），因为 LVGL 的 `esp.cmake` 会**无条件**把它们
当作 include 目录注册给 `idf_component_register()` —— 少一个目录，配置阶段就会直接失败。
（这一点是"把仓库 clone 到干净目录里真编一遍"测出来的，不是推断。）

### 烧录

```powershell
idf.py -p COM4 flash
```

> **注意**：Tab5 的 USB-C 口是 `USB-Serial/JTAG` 控制台。**不要**用 DTR/RTS 手工复位
> （会把芯片留在下载模式，必须断电才能恢复）。烧录后请手动按 RST 键或断电重启。

### 接线

| 目标 | 接法 |
|---|---|
| Chameleon Ultra | 插到 Tab5 的 **USB-A** 口 |
| 控制台/烧录 | USB-C 口，`COM4` @115200 |

### 回归测试

```powershell
python tools/verify_frame.py     # 帧协议：对照官方 chameleon_com.py 双向逐字节
python tools/verify_crypto.py    # 密码学：官方向量 + 实时 crypto1.py + mfkey32 端到端恢复 + 峰值内存
python tools/verify_lf.py        # 低频卡：对照官方 chameleon_cmd.py / app_cmd.c 的密钥、命令号、字段布局
python tools/probe_mfkey32.py    # 密钥恢复对拍：同一条轨迹分别跑本项目和上游 crapto1.c，比状态数
python tools/probe_darkside.py   # darkside 对拍：同一组输入分别跑本项目和上游 mfkey.c，比密钥列表
python tools/verify_darkside_search.py  # 跑 DarksideSearch::Feed 本体（交集/所有权/泄漏）
python tools/verify_sniff_decoder.py    # 轨迹解码器（参考 crypto1.py 造的合成认证）
python tools/probe_nested.py            # nested 对拍：候选密钥集合与上游逐个相同
python tools/verify_hardnested_acquire.py  # hardnested 客户端半边：文件格式由上游 hardnested_main.c 判定
python tools/verify_payloads.py            # payload 对拍：命令号与字节逐条对 chameleon_cmd.py + app_cmd.c
python tools/measure_hardnested_tables.py  # 量 hardnested 的表要多少内存（结论：1.5 GB 常驻）
```

这些工具都以官方 Python / 固件源码为判定基准 ——
不使用手抄的期望值（这条教训来自帧协议那一轮，详见 `docs/PORTING-NOTES.md`）。

> 注意：**回归测试要在没跑过 `export.ps1` 的 shell 里执行**。IDF 的 `export.ps1` 会把
> `python` 指向它自带的 venv，那个环境里没有 `pyserial` / `prompt_toolkit`，
> 于是 `verify_payloads.py` 会在 import 上游 `chameleon_cmd.py` 时报
> `ModuleNotFoundError`，看起来像是移植代码坏了。烧录完再跑测试时最容易踩。

> 这些工具要读**上游 ChameleonUltra 的源码**（`chameleon_cmd.py`、`app_cmd.c`、`crapto1.c`
> 等）来当判定基准，所以需要一份上游 checkout。默认路径是本机布局
> （`C:\Users\Jiang\Downloads\ChameleonUltra-main`）；放在别处就设环境变量：
>
> ```powershell
> git clone https://github.com/RfidResearchGroup/ChameleonUltra D:\src\ChameleonUltra
> $env:CU_UPSTREAM = "D:\src\ChameleonUltra"
> ```
>
> 没设又找不到时，工具会以"上游文件不存在"失败并打印它找的路径，不会静默跳过检查。

它们各自抓到过真 bug：

- `verify_lf.py`：我"凭印象"写的 T55xx 密码常量（`FF FF FF FF` 等）和官方实际值
  （`20 20 66 66` / `51 24 36 48, 19 92 04 27`）**一个字节都不对**。
- `probe_mfkey32.py`：密钥恢复里的桶遍历顺序写反，5 万个候选状态只剩 24 个，
  **不崩不报错，只是永远找不到密钥**。详见 `docs/PORTING-NOTES.md` 第 12 条。
- `verify_darkside_search.py`：**每次"没找到密钥"泄漏 1.7 MB**，60 轮的上限会把
  24 MB PSRAM 在第 14 轮耗尽。见第 15 条。
- `probe_darkside.py`：确认把上游 `lfsr_common_prefix()` 的 **128 MB** 固定分配换成
  按实际候选数计算之后，26 组输入（最大一组 219648 个候选密钥）与上游**逐个密钥一致**。
- `verify_hardnested_acquire.py`：导出行缓冲区少算一个字节（`printf` 读到下一行，
  "一行"变 7 KB），以及行解析器只认行首标记（真实日志里前面永远有 `ESP_LOGI` 前缀）。
  两个都是"看起来显然不会错"的那种。见第 21 条。
- `verify_payloads.py`：`MF1_CHECK_KEYS_ON_BLOCK` 的载荷**少了一个 count 字节、前两个字段还是反的**，
  设备会一直回 `PAR_ERR`。因为界面走的是另一条命令（`MF1_CHECK_KEYS_OF_SECTORS`，那条是对的），
  这个错**没有调用者、在真机上永远不会暴露** —— 只有"把每个命令的载荷都拿出来比一遍"才看得见。
  见第 22 条。
- `verify_crypto.py`（第 5 节）：把 `sniff_decoder.cpp` 和 `mfkey32.cpp` 的**接缝**也测了 ——
  一条合成原始轨迹进、密钥出。顺带发现解码器**没有兑现自己的注释**：
  `sniff_decoder.h` 写着"不完整的认证会以 `complete == false` 报告"，
  而实现直接把不完整的认证丢掉，于是"密钥不对"和"什么都没抓到"在界面上长得一样。
  已改成按注释执行，两个探针都加了区分这两种情况的断言。

**hardnested 的用户流程**（板子只做采集，破解在 PC）：

```powershell
# 1. Tab5：Keys 页 → acquire hardnested nonces → export nonces
python tools/capture_console.py --seconds 90 > capture.txt
# 2. 还原 nonce 文件（校验 SZ 与 CRC32，坏抓包直接报错）
python tools/nonce_file_from_console.py capture.txt -o nonces.bin
# 3. PC 上跑上游求解器（HardnestedRecovery 自带 Makefile，需要 liblzma）
HardnestedRecovery/hardnested_main nonces.bin
```

---

## 2. 界面

八个标签页（按注册顺序）：

| 页面 | 功能 |
|---|---|
| **Slots** | 8 个槽位：HF（16 种标签类型）/ LF（12 种）下拉框 + `Use` 切换当前槽位 + `nick` 昵称编辑（含软键盘）；改动自动 `SAVE_SETTINGS` |
| **Device** | 型号 / 固件版本 / git / BLE MAC / 电量 / 模式切换 / LED 动画 / 休眠超时 / PSRAM 用量 / **report device state**（能力表、全部设置、按键功能、启用槽位、所有昵称） |
| **Cards** | **读卡器下拉框（10 种）** + `scan` + `clone to T55xx`；HF 卡显示 UID/ATQA/SAK/ATS 并识别卡型，低频卡按协议解码成 FC/CN 等字段；Mifare Classic 块读写（含软键盘输入密钥、一键采用 Keys 页找到的密钥） |
| **Keys** | Mifare Classic 密钥恢复：`check factory keys`（快）+ `darkside attack`（慢）+ `nested attack` + `acquire hardnested nonces`；结果直接送到 Cards 页 |
| **Emulate** | 配置**当前槽位模拟出去的卡**：LF 卡号（按 LF 类型自动定长）、HF 身份（UID/ATQA/SAK/ATS）、模拟的 Classic 数据块；以及 **classic emulator options**（gen1a/gen2 magic、block anti-coll、detection、write mode、PRNG 类型） |
| **NTAG** | **MF0 / NTAG 模拟器**：页面读写（4 字节/页，读回比对）、GET_VERSION 读写、ECC 签名读写、NTAG 计数器读写（含 tearing 重置）+ 认证计数复位、UID magic 模式、write mode、detection 开关与**抓到的认证口令日志** |
| **Tools** | 三个面板切换：**iso14443-4 / emv / seos**（T=CL 身份与 APDU 收发、静态响应表、读卡器 APDU、EMV 全流程、SEOS 三组数据读写）、**raw hf / lf**（HF14A_RAW 六个选项位、HF14A_SNIFF、AUTH_TRACE（解出 nt/nr_enc/ar_enc）、LF_T55XX_WRITE 原始字、ioProx raw 解码/合成、LF_SNIFF）、**system / mf1**（HF14A 四项配置、槽位启用/昵称/感测类型/数据默认值/落盘、按键短按长按功能、MF1 detection 计数与日志、单块密钥检查、值块加减恢复、加密 nested 采集、`MF1_DETECT_SUPPORT`；`reset settings` 与 `wipe fds` 需要按两次确认） |
| **Log** | 协议与事件日志（200 条环形缓冲，可清空） |

顶部状态栏显示连接状态、型号与固件版本、电量与当前槽位。

**NTAG 页**和 Emulate 页一样改的是**当前激活槽位**，而且**每一次写入都会立刻读回比对** ——
设备接受了写命令但标签是只读的（write mode 0）这种情况，只有读回才能发现。
页面上的 `uid magic` / `detection` / `write mode` 三个状态按钮也是"读 → 改 → 写 → 读回"，
显示的是设备确认过的值，不是点按钮时的意图。

**UI 覆盖率是工具在查的**，不是靠人记：`python tools/verify_payloads.py` 的第 [4] 节会
把 `chameleon_client.h` 里每个公开方法与 `main/*.cpp` 的实际调用比对，
**109 个方法里 102 个已接到界面**，剩下 7 个是**有意不接**的（进 DFU、连接握手用的两个 fetch、
被表驱动的 EM410X 三兄弟、`DecodeTraceFrame`、`MF1_DETECT_SUPPORT` 的内部用途），
每一条都在工具里写了理由；未被调用又不在清单里的会直接判失败。

**Emulate 页**改的是**当前激活槽位**（设备的模拟命令不带槽位参数），所以标题行会写
`ACTIVE SLOT n`；要改别的槽位，先在 Slots 页 `Use` 它。这一页的所有内容都是**设备端状态**，
写入后读回即可验证 —— 不需要真卡。

**Cards 页**的 `check factory keys` → `MF1_CHECK_KEYS_OF_SECTORS` 一次把内置的一小组
出厂/传输密钥试遍 40 个扇区；`darkside attack` → 循环 `MF1_DARKSIDE_ACQUIRE` 采集，
Tab5 本地用移植过来的 Crapto1 算候选密钥。

> **每个候选密钥都会先用 `MF1_AUTH_ONE_KEY_BLOCK` 让卡真的认证一次**，认证不过就丢弃。
> 界面永远不会把一个没被卡确认过的候选值当成"找到的密钥"。

两个密钥操作都跑在独立的 key job 任务上（几十秒到几分钟），界面只轮询进度，不阻塞触控。

**实体键盘**（可选配件 M5Stack Tab5 Keyboard，SKU A164）：经外部 I2C 连接
（SDA=GPIO0 / SCL=GPIO1 / INT=GPIO50 / 地址 0x6D），未插入时只记一条日志，触屏不受影响。

| 按键 | 行为 |
|---|---|
| `1`~`8` | 切换八个标签页（**当输入框聚焦时让路给文本输入**） |
| 字母/数字/符号 | 输入到聚焦的文本框（昵称、十六进制密钥/数据框） |
| `Enter` | 昵称框：保存并关闭；密钥框：读取该块；数据框：写入该块；Keys 页：开始查密钥；NTAG 页：读页面 |
| `D` / `S` | Keys 页：开始 darkside 攻击 / 停止当前任务 |
| `R` / `L` | NTAG 页：读配置 / 读 detection 日志 |
| `M` | Tools 页：三个面板循环切换 |
| `Esc` | 昵称框：取消；卡片页 / Emulate 页 / NTAG 页 / Tools 页：取消焦点 |
| `Backspace` / `Delete` | 删除字符 |

> 快捷键与文本输入的优先级：**页面优先**。若热键先判定，`1`~`8` 将永远无法输入到昵称或
> 十六进制密钥中（这些字段确实需要数字）。

---

## 3. 目录结构

```
firmware/
  CMakeLists.txt / sdkconfig.defaults / partitions.csv
  components/
    chameleon/              ★ 协议 + 会话 + USB CDC 主机驱动
      include/chameleon_protocol.h   帧格式与 LRC
      include/chameleon_commands.h   命令/状态/标签类型枚举
      include/chameleon_client.h     会话层（对应 chameleon_cmd.py）
      include/usb_serial_host.h      USB CDC-ACM 主机驱动
    chameleon_crypto/       ★ Mifare Classic 密钥恢复（GPL-3.0-or-later）
      src/crapto1.c crypto1.c parity.c bucketsort.c   上游 Crapto1（已加边界检查）
      src/mfkey.c                                     上游 darkside 破解核心（逐字复制）
      src/mfkey32.cpp                                 Tab5 适配层（PSRAM 分配 + 内存记账）
      src/darkside.cpp                                本地 darkside 搜索（替代 darkside.exe）
      src/nested.cpp                                  本地 nested / staticnested（单线程改写）
      src/hardnested/                                 上游 hardnested core（能编，但有意不链接，见 §7）
        hardnested_bf_core.{c,h} hardnested_bruteforce.{c,h}
        hardnested_compat.h                           pm3 那 6 个符号的替身（值从上游文件抄）
  main/
    main.cpp                上电流程（每步都注释了原因）
    app_context.{h,cpp}     共享上下文：会话 + USB + 日志环形缓冲 + 查询任务 + 密钥任务
    hardnested_acquire.{h,cpp}  hardnested 客户端半边（纯 C++，能在主机上和上游对拍）
    ui.{h,cpp}              LVGL 工具：主题、字体、Page 基类、Shell 导航
    pages.{h,cpp}           SlotPage / DevicePage / LogPage
    pages_card.cpp          CardPage
    pages_keys.cpp          KeysPage（工厂密钥 / darkside / nested / hardnested 采集）
    pages_mf0.cpp           Mf0Page（MF0 / NTAG 模拟器）
    pages_tools.cpp         ToolsPage（ISO14443-4 / EMV / SEOS + raw HF/LF）
  tools/
  verify_frame.py           协议回归（17 组载荷双向比对 + 坏帧拒绝 + 重同步）
  verify_crypto.py          密码学回归（官方向量 + 实时参考 + 峰值内存）
  verify_lf.py              低频卡回归（T55xx 密钥 / 命令号 / 回复长度 / id 切片 / 写载荷布局）
  probe_mfkey32.py          密钥恢复对拍（本项目 vs 上游 crapto1.c，比恢复出的状态数）
  probe_darkside.py         darkside 对拍（本项目 vs 上游 mfkey.c，比恢复出的密钥列表）
  verify_darkside_search.py 跑 DarksideSearch::Feed 本体（交集语义 / 内存所有权 / 泄漏）
  verify_sniff_decoder.py   轨迹解码器（用参考 crypto1.py 造的合成认证）
  probe_nested.py           nested 对拍（候选密钥集合逐个相同）
  verify_hardnested_acquire.py  hardnested 客户端半边（文件格式由上游 hardnested_main.c 判定）
  verify_payloads.py        命令覆盖 + 载荷对拍（chameleon_cmd.py 与 app_cmd.c 双重判据）
  measure_hardnested_tables.py  量 hardnested 的表要多少内存
  nonce_file_from_console.py   从串口抓包还原 hardnested nonce 文件（校验 SZ/CRC32）
  capture_console.py        串口采集（不碰 DTR/RTS）
  decode_boot.py            启动日志解码 + 地址符号化
  host_stubs/               主机测试替身：ESP-IDF 头文件 + 客户端/硬破解对拍 harness
docs/
  PROTOCOL.md               帧格式规范 + 命令载荷表 + 三大陷阱
  PORTING-NOTES.md          22 个真实踩坑记录
  M5-KEY-RECOVERY.md        密钥恢复移植状态与内存分析（§6 是 hardnested 的内存实测）
```

---

## 4. 已实现能力

### 传输层

- **USB**：自写的 CDC-ACM 主机驱动（IDF 5.4 不自带 `usb_host_cdc_acm`，离线也拉不到）。
  自动解析 CDC 描述符、认领 comm/data 接口、异步发送 CDC 控制请求、持续提交 bulk IN。
  实测连接 Chameleon Ultra（VID:PID `6868:8686`，comm intf 0 / data intf 1 / bulk `0x81`/`0x01`）。
- **蓝牙**：待做（见 §6）。

### 协议层

完整的帧编解码（三重 LRC、坏帧重同步、4096 字节载荷上限），
**已用官方 `chameleon_com.py` 做逐字节回归**：17 组载荷双向比对 + 坏 LRC1/LRC2/LRC3 + 截断 + 前导垃圾重同步。

### 会话层

**命令覆盖：枚举里声明 145 条，除蓝牙 5 条外全部实现，而且现在是工具在核对，不是我在核对。**

```powershell
python tools/verify_payloads.py
# [0] 命令覆盖：上游 145 条逐条对命令号（全中），除 5 条蓝牙 + EM4X05_READSNIFF 外全部被调用
#     EM4X05_READSNIFF 的"设备没有 handler"也是查出来的：app_cmd.c 的分发表里没有这一行
# [1] 载荷对拍：72 条用例里 71 条与上游 chameleon_cmd.py **逐字节相同**
# [2] 上游 Python 没有实现的命令（LF_T55XX_WRITE）改对 app_cmd.c 的 PACKED 结构校验
# [3] 再拿 app_cmd.c 每个 handler 的结构体长度做第三重校验（9 条精确 + 2 条变长尾巴）
```

对拍方式：**移植的客户端编到主机上跑（假传输录帧）× 上游 `chameleon_cmd.py` 原样 import（假设备录载荷）**，
两者用同一组参数调用，比命令号和字节。期望值全部由**运行上游代码**产生，
没有一条是手抄的 —— 这正是它抓到 `MF1_CHECK_KEYS_ON_BLOCK` 那个 bug 的方式。

按区域：

| 区域 | 内容 |
|---|---|
| 系统 | 版本 / 型号 / chip id / MAC / 电量 / 能力表 / **全部设置** / 按键与长按功能 / 启用槽位 / 全部昵称 / 槽位与标签类型 / 昵称 / 模式 / 睡眠 / 动画 / 保存 / 重置 / 清空 FDS / 删除昵称 / 删除感测类型 / 槽位数据默认值与落盘 / **进入 DFU** |
| HF14A / Classic | 扫描 / 扫描保持场上 / raw 收发 / 嗅探 / **认证轨迹** / 配置读写 / 防冲突数据读写 / 块读写 / 密钥认证 / 扇区与块密钥检查 / 值块运算 / PRNG 检测 / NT 距离 / darkside 采集 / nested、static nested、hardnested、加密 nested 采集 |
| Classic 模拟器 | gen1a / gen2 magic、block anti-coll、write mode、field-off reset、PRNG 类型、detection 开关与日志、模拟块读写、模拟器配置总览 |
| MF0 / NTAG 模拟器 | 页读写 / 页数 / UID magic 模式 / 版本 / 签名 / 计数器读写与复位 / 写模式 / detection 开关、计数与日志 / 模拟器配置 |
| 低频 | 10 种读卡器 + T55xx 克隆 + **T55xx 原始字写入** + ioProx raw 解码 / 参数合成 + 7 种协议的模拟 ID 读写 + ADC + 低频嗅探 + EM4x05/EM4x69 |
| ISO14443-4 | T=CL 防冲突数据 / APDU 收 / APDU 发 / 静态响应表 / 读卡器 APDU / **EMV 全流程扫描** |
| SEOS | 模拟数据读写 / 模拟密钥写入 |

> 上表是**命令面**。算法的**破解内核**另有状态：darkside、nested、staticnested
> 都已移植并验证（见 §7）；`hardnested` 是**三段式**，本项目把该在板子上的那一半
> （设备采集 → 首字节奇偶和 → nonce 文件 → 串口导出）做完了，
> 破解核心**实测要 1.5 GB 常驻内存**，只能留在 PC 上 —— 见 §7 与
> `docs/M5-KEY-RECOVERY.md` 第 6 节。

低频读卡类（`pages_card.cpp` 里的 `kReaders[]` 表，一项 = 一种读卡器）：
| 读卡器 | 扫描命令 | 回复 → 卡片 ID | 克隆命令 |
|---|---|---|---|
| HF14A 13.56M | `HF14A_SCAN` | UID/ATQA/SAK/ATS | — |
| EM410X | `EM410X_SCAN` | `tag_type(2)` + ID(5)，Electra 13 | 按 tag_type 自动选 `EM410X_WRITE_TO_T55XX` / `..._ELECTRA_...` |
| HIDProx | `HIDPROX_SCAN`（**必须带 1 字节 format hint**） | 13 字节 = format/FC/CN/IL/OEM | `HIDPROX_WRITE_TO_T55XX` |
| ioProx | `IOPROX_SCAN` | 16 字节 = ver/FC/CN/raw8 | `IOPROX_WRITE_TO_T55XX` |
| PAC/Stanley | `PAC_SCAN` | 8 字节 ASCII | `PAC_WRITE_TO_T55XX` |
| Viking | `VIKING_SCAN` | 4 字节 | `VIKING_WRITE_TO_T55XX` |
| Jablotron | `JABLOTRON_SCAN` | 5 字节（BCD 卡号） | `JABLOTRON_WRITE_TO_T55XX` |
| IDTECK | 上游固件**只有写命令**，没有读命令 | 手工输入 16 位十六进制 | `IDTECK_WRITE_TO_T55XX` |
| EM4x05/EM4x69 | `EM4X05_SCAN`（带 4 字节密码） | config/uid/uid_hi/is_em4x69 | — |
| ADC 电平 | `ADC_GENERIC_READ` | 场强原始 ADC | — |

克隆载荷所有协议统一为 `id | new_key[4] | old_keys[2][4]`，
其中 `new_key = 20 20 66 66`、`old_keys = 51 24 36 48, 19 92 04 27`
（**逐字节取自官方 `chameleon_cmd.py`**，由 `tools/verify_lf.py` 把关）。
`LfSniff` 也已实现，暂未挂到界面。

---

## 5. 硬件要点（Tab5）

| 项目 | 值 |
|---|---|
| 主控 | ESP32-P4 rev v1.3（无射频） |
| 无线 | ESP32-C6，经 SDIO 连接，出场固件为 Wi-Fi 专用镜像 |
| 显示 | 720×1280 MIPI-DSI **ST7121**（需 90° 旋转成 1280×720） |
| 触摸 | ST7121（I2C 0x55），**必须复位后才会应答** |
| 内存 | PSRAM 32 MB（其中约 24 MB 可用）/ 内部 SRAM 约 317 KB 可用 |

---

## 6. 已知问题与注意事项

1. **上电流程顺序不可改动**：`bsp_i2c_init()` → `bsp_io_expander_pi4ioe_init()` →
   `bsp_reset_tp()` → `bsp_display_start_with_config()`。漏掉触摸复位会导致面板误判为
   ILI9881C 并在 DSI 读操作上**死循环卡死**。详见 `docs/PORTING-NOTES.md`。
2. **LVGL 绘制缓冲必须 128 字节对齐**（`CONFIG_LV_DRAW_BUF_ALIGN=128`），否则 PPA 旋转
   报 `ESP_ERR_INVALID_ARG` 并 `abort()`，表现为屏幕闪烁+反复重启。
3. **改 `sdkconfig.defaults` 后必须删掉 `sdkconfig`**，否则旧值会盖掉新默认值。
4. `E ledc: GPIO 22 is not usable` 是无害警告（BSP 重复申请背光通道，后申请者生效）。
5. USB-Serial/JTAG 控制台 FIFO 很小，开机日志容易撑爆并丢掉应用日志。对策：默认日志级别
   INFO + bootloader WARN，且用 `tools/capture_console.py` 在复位**之前**就开始采集。
6. **电量需要延迟读取**：设备上电后电池测量定时器未跑第一轮时返回 `00 00 00`。
   本项目用 5 秒周期轮询，第一次测量完成后界面自动更新。
7. **实体键盘回调的坑**：驱动在 HID 模式下**只填 `hid_key_code`/`hid_modifier`，不填 `pressed`**
   （`pressed` 是 Normal 模式的字段，保持默认 `false`）。因此判据必须是"键码非零"，
   而 `0x00` 表示松开。另外 `setMode()` 之后不能再补 `setKeyCallback()` ——
   要用 `enableHIDMode(callback, arg)` 一次装好。
8. **上游键盘组件依赖 `espressif/i2c_bus`**，本项目离线构建时用
   `components/m5_tab5_keyboard/src/i2c_bus.h` + `i2c_bus_compat.cpp` 提供了最小替身
   （基于原生 `i2c_master` 实现），**未改动那 56 KB 的驱动源码**。
   注意 `i2c_bus_handle_t` 不能写成 `i2c_master_bus_handle_t` 的别名 —— 驱动对两种写法
   都重载了 `begin()`，别名会让重载塌缩成重复定义。
9. **键盘快捷键必须让路给文本框**：`1`~`4` 既是切页热键也是合法输入字符，所以判定顺序
   必须是「页面 `OnKey()` 先返回是否消费，未消费才当热键」。反过来会导致昵称和十六进制
   密钥里的数字永远打不进去。
10. **`HIDPROX_SCAN` 的请求必须带 1 字节**：上游 `cmd_processor_hidprox_scan()` 直接读
    `data[0]` 且**没有 NULL 判断**（同一文件里的 `ioprox` 版本就有 `(data != NULL) ? ... : 0`）。
    空载荷会让变色龙固件解引用空指针 —— 表现是设备从 USB 掉线，而 Tab5 这边只会看到
    "device detached"，很容易误判成 USB 驱动的问题。`verify_lf.py` 会检查这个前提。
11. **上游 `cmd_processor_hidprox_write_to_t55xx()` 的字段名是反的**：结构体把第一个 4 字节
    键叫 `old_key`、后面的列表叫 `new_keys`，而官方 `chameleon_cmd.py` 发的是
    `id | new_key | old_keys...`。**以 CLI 为准**（它是真正在用的客户端），
    和其它所有 `*_WRITE_TO_T55XX` 保持同一布局即可。
12. **`EM4X05_SCAN` 的回复长度上游自己就不一致**：固件发 13 字节
    （config/uid/uid_hi/is_em4x69），Python 却按 14 字节 `!IIIBB` 解包（多一个 uid_block）。
    本项目的解析按 13 字节处理、`len` 更大时也不越界。
13. **`IDTECK` 在上游固件里是只写协议**：`app_cmd.c` 只有 `DATA_CMD_IDTECK_WRITE_TO_T55XX`，
    没有对应的 SCAN。界面因此把"卡片数据"输入框当作 8 字节帧的来源
    （按 `scan` 即写入），而不是假装能扫。
14. **死代码会藏住内存错误**：`chameleon_crypto` 之前没有任何调用者，被 `--gc-sections`
    整个丢掉，所以它那 1 MiB 的 `filterlut` 放在哪儿都无所谓。一旦 Keys 页真的引用它，
    链接立刻炸出一屏 `--enable-non-contiguous-regions discards section '.sbss.*'` ——
    因为 `CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY` 没开，
    `EXT_RAM_BSS_ATTR` 展开成**空**，1 MiB 静态数组落在只有 ~317 KB 的内部 SRAM 里。
    **一个组件"没被引用"时，它的资源假设从来没有被验证过。**

---

## 7. 下一步

| 项 | 状态 |
|---|---|
| **低频读卡/克隆**：10 种读卡器 + T55xx 克隆已实现并通过离线交叉验证；**待实机放卡验证** | ⏳ |
| **实体键盘**：Tab5 Keyboard（I2C 0x6D）接入，用于快捷操作 | ✅ |
| 槽位昵称编辑、UID/密钥输入完善 | ✅ |
| **命令覆盖**：上游 145 条命令全部声明且编号一致，139 条被真正调用（5 条蓝牙 + EM4X05_READSNIFF 除外，后者设备端没有 handler —— 由工具查证） | ✅ |
| **载荷一致性**：72 条用例里 71 条与上游 `chameleon_cmd.py` **逐字节相同**（剩下 1 条上游没实现，改对 `app_cmd.c` 校验） | ✅ |
| **界面覆盖率**：102/109 个客户端方法已接到界面，其余 7 个有意不接且逐条写了理由（`tools/verify_payloads.py` 第 [4] 节在核对） | ✅ |
| **BLE**：走板载 C6 的 `esp_hosted`（BT over SDIO）+ NimBLE Central 连接 NUS 服务。⚠️ 需先给 C6 刷入带蓝牙的 slave 固件（存在刷坏/影响 Wi-Fi 的风险），默认关闭 | ⏳ |

### 界面覆盖：七个波次全部接完

| 波次 | 内容 | 界面位置 | 状态 |
|---|---|---|---|
| W1 | LF 六种协议的模拟卡号、HF 防冲突数据、Classic 模拟块读写 | Emulate 页 | ✅ |
| W2 | gen1a/gen2 magic、block anti-coll、write mode、PRNG 类型、field-off reset、detection | Emulate 页 options 面板 | ✅ |
| W3 | MF0/NTAG 页面、版本、签名、计数器、magic 模式、write mode、detection 日志 | NTAG 页 | ✅ |
| W4 | HF14A 配置、按键功能、槽位启用/昵称/感测类型/数据默认值/落盘、删除、MF1 detection 日志、重置/清空 | Tools 页 system 面板 | ✅ |
| W5 | HF14A_RAW、SNIFF、AUTH_TRACE（带帧解码器）、LF_T55XX_WRITE、ioProx 解码/合成、LF 嗅探 | Tools 页 raw 面板 | ✅ |
| W6 | darkside / nested / staticnested / hardnested 采集 / detect-prng / nt-distance / 单块密钥检查 / 值块运算 / 加密 nested | Keys 页 + Tools 页 system 面板 | ✅ |
| W7 | T=CL APDU 收发、静态响应表、读卡器 APDU、EMV 扫描、SEOS 数据与密钥 | Tools 页 t4t 面板 | ✅ |

有意不接的 7 个：`ENTER_BOOTLOADER`（会掉 USB，不该做成界面按钮）、连接握手用的
`FetchAppVersion` / `FetchDeviceIdentity`、被表驱动的 `ScanEm410x` / `SetEm410xEmuId` /
`GetEm410xEmuId`、`DecodeTraceFrame`（嗅探解码器自己走 buffer）、`Mf1DetectSupport`（攻击内部用）。
每一条的理由都写在 `tools/verify_payloads.py` 的 `KNOWN_UI_GAPS` 里，工具在核对。

> 每个波次的**客户端载荷**由 `verify_payloads.py` 第 [1]–[3] 节对着上游
> `chameleon_cmd.py` 与设备端 `app_cmd.c` 逐字节核对，**界面可达性**由第 [4] 节核对。
> 还没做的是**真卡/真读卡器上的成功路径** —— 手头只有一张 Mifare Ultralight。


### M5 密钥恢复：四套攻击的界面都接上了，**待真卡验证**

| 项 | 状态 |
|---|---|
| Crapto1 计算内核（`lfsr_recovery32` / `crypto1` / `parity`） | ✅ 与上游 `software/src/crapto1.c` **对拍完全一致**（状态数 53329 / 53329 / 72498 逐一相同） |
| `mfkey32v2` 端到端恢复 | ✅ 合成轨迹能恢复出密钥，第二条认证复核通过；峰值 18.00 MB |
| `nonce2key`（darkside 破解核心） | ✅ 26 组输入与上游 `mfkey.c` **逐个密钥一致**，最大一组 219648 个候选 |
| `nested` / `staticnested` 破解核心 | ✅ 候选密钥集合与上游**逐个相同**（`tools/probe_nested.py`） |
| `hardnested` 客户端半边 | ✅ 采集 + 首字节奇偶和 + nonce 文件；文件格式由**上游 `hardnested_main.c` 原文**判定 |
| `hardnested` 破解核心 | ⚠️ 移植了、编译得过 esp32p4，但**有意不链接**：候选生成实测要 **1.5 GB 常驻**（板子 32 MB） |
| 128 MB 固定分配 → 按候选数计算 | ✅ 上游 `lfsr_common_prefix()` 要 8×2²⁴=128 MB（板上只有 24 MB），改为 `候选数×候选数×64` 的**严格上界**；实测只占几百 KB |
| 设备命令（`MF1_DARKSIDE_ACQUIRE` / `MF1_CHECK_KEYS_OF_SECTORS` / `MF1_HARDNESTED_ACQUIRE`） | ✅ 已接入客户端 |
| Keys 界面页 | ✅ 已接入（`pages_keys.cpp`），跑在独立任务上 |
| **真卡验证** | ❌ **没有 Mifare Classic 卡**。四套攻击的"成功路径"都没跑过 |

**验证到什么程度**：算法层用"和上游对拍"证明了一致性（不是靠推理），协议层用
`chameleon_cmd.py` 的 `struct` 布局证明了一致性。**没验证的是"真实卡片上的成功路径"** ——
需要一张 Mifare Classic（手头那张是 Ultralight，没有扇区，密钥检查必然返回失败；
实测 `check factory keys` 走通并回 "no factory key matched"，
`darkside` 返回 `HF_ERR_STAT` 后按预期停下，设备没有掉线）。

**这台设备上做不了的两件事**（都不是"没接"，是设备给不出）：

- **`mfkey32` 没有现成的数据源，但已经接进界面了**。它需要真实卡片用**未知密钥**算出的
  `ar_enc`，而设备上两条路都堵死：`HF14A_SNIFF` 的固件注释明写
  *"passive mode intentionally disabled: CU acts as the card"*（响应是设备自己算的，
  而算它就得先有密钥）；`HF14A_AUTH_TRACE` 的 `nr_enc` 是**用给定密钥**加密的，
  密钥不对卡根本不回 AT。详见 `docs/M5-KEY-RECOVERY.md` 第 5 节。
  Tools 页 raw 面板上的 `mfkey32 crack last trace` 是**完整可用的**：
  把抓到的轨迹解码成认证，取前两条完整的，交给移植过来的内核（跑在独立任务上，
  峰值 18 MB PSRAM）。设备自己抓的轨迹会被明确判成"没有成对认证"而不是假装搜了一遍；
  PC 上被动嗅探来的轨迹可以直接用。
  **这条路径整体被对拍覆盖**：`tools/verify_crypto.py` 用参考 `crypto1.py` 造一条
  含两条认证的原始轨迹，喂进"解码器 → 内核"，要求恢复出密钥
  （`mfkey32 from a raw trace` 那一节）。
- **`EM4X05_READSNIFF` 设备端没有 handler**：命令号在枚举里，但 `app_cmd.c` 的分发表里
  没有这一行，`chameleon_cmd.py` 也没有对应方法。这一条不是我说了算 ——
  `tools/verify_payloads.py` 第 [0] 节会去解析分发表，**发现 handler 就会判失败**。
  EM4x05 的读取走 `EM4X05_SCAN`（已接到 Cards 页）。

**已移植并验证的部分**：

- `nested` / `staticnested`：**已移植并验证**。破解核心改写成单线程
  （`components/chameleon_crypto/src/nested.cpp`，pthread 依赖就此消失），
  `tools/probe_nested.py` 对拍：`valid_nonce()` 300 组输入一致、候选密钥集合
  4 组非空用例**逐个相同**（50 把对 50 把，零差异）；`staticnested` 的派生逻辑
  对照**参考 `crypto1.py` 的 `prng_next`** 验证（gen1/gen2 × keyA/keyB 三种组合 +
  两种拒绝路径）。调参常量 `MEM_CHUNK`/`TRY_KEYS` 由 probe 直接从上游源码读取比对 ——
  这两个数字我一开始凭印象写成 256/256（实际 10000/50），是对拍抓出来的。
- `hardnested`：**结论更正过一次**。原来的判断是"5 MB 的 `tables.c` 两个 core 都不引用，
  所以只有 83 KB 要搬"。引用计数没错，**结论错了** —— 用表的是编排层
  （`cmdhfmfhard.c` 里的 `init_bitflip_bitarrays()` / `generate_candidates()`），
  而我把那一层整个当成了"Proxmark3 客户端壳"。量完之后：
  - `tables.c` 源码 5 MB，里面其实只有 **0.75 MiB** 的 XZ 数据，解压出来 **702 MiB**
  - 通过上游阈值保留 237 块 × 2 MiB = **474 MiB**，再加 `nonces[256]` 的
    **1 GiB**（`cmdhfmfhard.c:522/529`），`malloc_bitarray` 是**真的 `memalign`**
  - **合计约 1.5 GB 常驻 vs 板子 32 MB PSRAM** —— 这不是"慢"，是放不下
    量法见 `tools/measure_hardnested_tables.py`，细节见 `docs/M5-KEY-RECOVERY.md` 第 6 节
- `hardnested` 的**客户端半边已移植并验证**：`MF1_HARDNESTED_ACQUIRE` 反复采集 →
  跟踪 256 个首字节与合法 `Sum(a8)`（19 个值取自上游 `sums[]`）→ 写 nonce 文件 →
  `export nonces` 打成 `[HN]` 行打到串口，`tools/nonce_file_from_console.py`
  从抓包还原 .bin 并校验 SZ/CRC32。判据是**上游 `hardnested_main.c` 原文**
  （只换掉求解器），它读本移植产出的文件，UID/sector/key type 与每一个 nonce、奇偶位都一致。
  两个 core 也**能编译成 esp32p4 目标但有意不链接**（没有候选生成就没有调用者，
  `--gc-sections` 丢掉，flash 不花一个字节，但编译仍在看守）。
- `nested / staticnested` **已接到 Keys 页**（`nested attack` 按钮）：
  照 CLI 的 `recover_a_key()` 编排 —— `MF1_DETECT_PRNG` 选路 → 采集 → 本地破解 →
  每个候选让卡认证确认。已知密钥取"本页上次确认过的密钥"。
  hardnested 的采集也接在同一页（`acquire hardnested nonces` / `fast|slow` / `export nonces`）。
  详见 `docs/M5-KEY-RECOVERY.md` 第 6 节。

**顺手做了**：`HF14A_SNIFF` / `HF14A_AUTH_TRACE` 的**轨迹解码器**
（`sniff_decoder.cpp`），按位计数遍历帧、识别四帧一组的认证、把不完整认证标成
`complete = false`。用参考 `crypto1.py` 造的合成轨迹验证
（`tools/verify_sniff_decoder.py`），必须原样吐出 `nt`/`nr_enc`/`ar_enc`。

---

## 8. 许可

**本项目整体以 GPL-3.0-or-later 发布**，完整许可证文本见仓库根目录的
[`LICENSE`](LICENSE)。

分两层看：

| 部分 | 许可 | 说明 |
|---|---|---|
| 本项目自己写的代码（`firmware/main/`、`firmware/components/chameleon/`、`firmware/components/m5_tab5_keyboard/`、`tools/`、`docs/`） | MIT（每个文件头有 `SPDX-License-Identifier: MIT`） | 可以单独取用 |
| `firmware/components/chameleon_crypto/` | **GPL-3.0-or-later** | `crapto1.c` / `crypto1.c` / `parity.c` / `bucketsort.c` / `nested.cpp` / `hardnested/` 来自 [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra)（GPL-3.0）；`mfkey.c` 来自同一仓库（GPL-2.0-or-later，向上兼容 GPL-3.0） |

把 MIT 部分和 GPL 部分链接成同一个固件后，**整个二进制按 GPL-3.0-or-later 分发** ——
这也是仓库根放 GPL-3.0 全文而不是 MIT 的原因。每个上游文件都保留着它原本的版权头。

第三方组件（`firmware/components/espressif__*`、`lvgl__lvgl`、`esp_lcd_st7121`、
`m5stack_tab5` 等）沿用各自原始许可（Apache-2.0 / MIT），许可证文件随各自目录一起提交。

> 这个仓库**不是** Chameleon Ultra 的官方固件：设备端固件仍然由
> [ChameleonUltra 官方仓库](https://github.com/RfidResearchGroup/ChameleonUltra) 提供，
> 这里只是一个通过 USB 协议与它通信的**上位机**。


