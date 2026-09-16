# Chameleon Ultra 帧协议规范

本文档描述变色龙（Chameleon Ultra）客户端-设备之间的帧协议，以及本项目实现中
**实际踩过的坑**。内容以官方 `software/script/chameleon_com.py` 与固件
`firmware/application/src/dataframe.c`、`app_cmd.c` 为准。

回归验证：`python tools/verify_frame.py`（对照官方 Python 实现逐字节比对）。

---

## 1. 帧布局

```
偏移   0     1       2 3      4 5        6 7      8      9 ...        末
      SOF   LRC1    CMD      STATUS     LEN      LRC2   DATA ...     LRC3
```

| 字段 | 长度 | 说明 |
|---|---|---|
| `SOF` | 1 | 固定 `0x11` |
| `LRC1` | 1 | 仅覆盖 `SOF` |
| `CMD` | 2 | 命令号，**大端** |
| `STATUS` | 2 | 状态码，**大端**；主机请求时为 0 |
| `LEN` | 2 | 数据长度，**大端**，上限 4096 |
| `LRC2` | 1 | 覆盖偏移 0..7（SOF/LRC1/CMD/STATUS/LEN） |
| `DATA` | `LEN` | 载荷 |
| `LRC3` | 1 | 覆盖偏移 0..(8+`LEN`)，即整个头+载荷 |

**帧头长度 = 9 字节，空载荷帧总长 = 10 字节。**

## 2. LRC 校验

二补数累加和：

```c
uint8_t Lrc(const uint8_t* d, size_t n) {
    uint8_t sum = 0;
    for (size_t i = 0; i < n; ++i) sum = (uint8_t)(sum + d[i]);
    return (uint8_t)((0x100 - sum) & 0xFF);
}
```

> 注意 `(0x100 - sum)` 在 C 里是 `int` 运算再截断，与 Python 的 `(0x100 - ret) & 0xFF` 等价。

## 3. 参考实现示例

`GET_APP_VERSION`（cmd = 1000 = `0x03E8`），空载荷：

```
11 EF 03 E8 00 00 00 00 15 00
│  │  └──┬──┘ └──┬──┘ └┬┘ └┬┘ └┬┘
│  │     │       │     │   │   └── LRC3 = 0x00
│  │     │       │     │   └────── LRC2 = 0x15  (= LRC(11 EF 03 E8 00 00 00 00))
│  │     │       │     └────────── LEN  = 0x0000
│  │     │       └──────────────── STATUS = 0x0000
│  │     └──────────────────────── CMD = 1000 (大端)
│  └────────────────────────────── LRC1 = 0xEF  (= LRC(11))
└───────────────────────────────── SOF
```

更多示例（由 `tools/show_reference_frame.py` 直接调用官方代码生成）：

| 命令 | 载荷 | 完整帧 |
|---|---|---|
| 1003 `SET_ACTIVE_SLOT` | `02` | `11 EF 03 EB 00 00 00 01 11 02 FE` |
| 1007 `SET_SLOT_TAG_NICK` | `01 02 68 69` (slot=1,HF,"hi") | `11 EF 03 EF 00 00 00 04 0A 01 02 68 69 2C` |

---

## 4. 三个真实的坑

### 坑 1：把 LRC2 放在索引 6-7（帧短 1 字节）

**错误布局**（我最初的实现）：

```
0    1    2 3    4 5    6 7    8
SOF  LRC1 CMD    STATUS LRC2   LRC3
```

问题在于 `LRC2` 写到了索引 6-7 —— 那正是 `LEN` 字段的位置，等于**用校验字节
覆盖了长度字段**。设备收到后按 `LEN` 解析，一直在等一个永远不来的字节，
表现就是**主机超时无应答**，而且完全没有任何错误提示。

正确做法：`LEN` 在 6-7，`LRC2` 在 **8**。

### 坑 2：以为 `struct.calcsize('!BBHHHB')` 会去掉对齐填充

Python 的 `!` 只保证**大端**，**不会**移除结构体内部的对齐填充。
`BB HH H B` 在末尾 `B` 之前会插入 1 字节填充，所以：

```python
struct.calcsize('!BBHHHB')      # -> 10（含填充）
struct.calcsize('!BBHHHB0s')    # -> 9 （末尾换成 0 长度 bytes，无填充）
```

官方 `make_data_frame_bytes()` 用的是 `!BBHHHB{len}sB`，因此：

| 用途 | 表达式 | 值 |
|---|---|---|
| LRC1 位置 | `calcsize('!B')` | 1 |
| LRC2 位置 | `calcsize('!BBHHH')` | **8** |
| LRC3 位置 | `calcsize('!BBHHHB{n}s')` | 9+`n` |

三个偏移量恰好就是正确布局 —— **官方实现是对的，我的推导是错的**。

### 坑 3：手打的十六进制字符串当验证基准

中途我用一段手工输入的 hex 去对比，手打时多写了一个 `00`，于是得到了
"验证通过" 的假象，白白多绕了两轮。

**教训**：验证协议必须**直接调用参考实现**，不能手抄其输出。
`tools/verify_frame.py` 现在的做法是：`import` 真实的 `chameleon_com.py` 当
判定基准，并用 `g++` 把**真实的 C++ 源文件**编成本机程序跑，双向比对。

---

## 5. 命令载荷格式（以固件为准）

⚠️ 官方 Python 客户端在个别命令上与固件不一致。**以 `app_cmd.c` 为准。**

### `SET_SLOT_TAG_TYPE` (1004)

```c
typedef struct { uint8_t num_slot; uint16_t tag_type; } PACKED payload_t;  // 3 字节
```

**没有 sense/频段字节** —— HF/LF 由 `tag_type` 的数值本身决定
（LF 类型 < 1000，HF 类型 ≥ 1000）。

### `SET_SLOT_ENABLE` (1006)

```c
typedef struct { uint8_t slot_index; uint8_t sense_type; uint8_t enabled; } PACKED payload_t;  // 3 字节
```

`sense_type`：1 = LF，2 = HF。

### `GET_SLOT_INFO` (1019)

返回 8 组，每组 4 字节：`u16 hf_tag_type` + `u16 lf_tag_type`（均大端）。

### 其他常用

| 命令 | 请求 | 响应 |
|---|---|---|
| `GET_APP_VERSION` 1000 | 空 | `u8 major, u8 minor` |
| `GET_DEVICE_CHIP_ID` 1011 | 空 | 8 字节（4×u16 大端） |
| `GET_DEVICE_ADDRESS` 1012 | 空 | 6 字节 BLE MAC |
| `GET_DEVICE_MODEL` 1033 | 空 | `u8`（0=Ultra，1=Lite） |
| `GET_BATTERY_INFO` 1025 | 空 | `u16 电压mV, u8 百分比` |
| `GET_ACTIVE_SLOT` 1018 | 空 | `u8`（**0 基**） |
| `SET_ACTIVE_SLOT` 1003 | `u8`（**0 基**） | 空 |
| `SET_SLOT_TAG_NICK` 1007 | `u8 slot, u8 sense, utf8[≤32]` | 空 |
| `GET_SLOT_TAG_NICK` 1008 | `u8 slot, u8 sense` | utf8 |
| `SET_SLEEP_TIMEOUT` 1040 | `u8 秒` | 空 |
| `SET_ANIMATION_MODE` 1015 | `u8`（0=full,1=minimal,2=none,3=symmetric） | 空 |

> **槽位编号**：协议里是 **0 基**（0..7）。官方 Python 的 `SlotNumber` 枚举是 1 基，
> 通过 `to_fw()` / `from_fw()` 转换。本项目直接用 0 基。

---

## 6. 状态码

| 值 | 名称 | 含义 |
|---|---|---|
| `0x00` | `HF_TAG_OK` | HF 操作成功 |
| `0x01` | `HF_TAG_NO` | 未找到 HF 卡 |
| `0x06` | `MF_ERR_AUTH` | Mifare 认证失败 |
| `0x40` | `LF_TAG_OK` | LF 操作成功 |
| `0x41` | `LF_TAG_NO_FOUND` | 未找到 LF 卡 |
| `0x60` | `PAR_ERR` | 参数错误 |
| `0x66` | `DEVICE_MODE_ERROR` | 当前模式不允许该命令 |
| `0x67` | `INVALID_CMD` | 不支持该命令 |
| `0x68` | `SUCCESS` | 通用成功 |

完整列表见 `chameleon_commands.h` 的 `Status` 与 `chameleon_commands.cpp` 的映射表。

---

## 7. 传输层

协议与传输无关，同一套帧走三种链路：

| 链路 | 服务 | 端点 |
|---|---|---|
| USB | CDC-ACM（`6868:8686`） | comm intf 0 / data intf 1，bulk IN `0x81`，bulk OUT `0x01`，MPS 64 |
| BLE | Nordic UART Service (NUS) | 需按官方 `ble_main.c` 的 UUID 写入/订阅 |
| TCP | 官方 CLI 的调试桥 | 帧格式完全相同 |
