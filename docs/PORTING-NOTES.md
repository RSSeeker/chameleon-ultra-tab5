# 移植踩坑记录

记录把 ChameleonUltra 客户端移植到 M5Stack Tab5 过程中**实际遇到并修复**的问题。
每条都包含现象、根因、修法，便于日后回归。

---

## 1. 构建：IDF 的 `-Werror=format` 与 `int32_t`

**现象**：编译我的 `main.cpp` 报

```
esp_log_color.h:98:31: error: format '%d' expects argument of type 'int',
but argument 9 has type 'int32_t' {aka 'long int'}
```

**根因**：在 riscv32 上 `int32_t` 是 `long int`，不是 `int`。我在 `ESP_LOGI` 里用 `%d`
去打 LVGL 的 `int32_t` 宽高。

**解法**：显式 `(int)` 转换。注意报错位置在 IDF 头文件里会误导人 —— 真正的问题在调用处的格式串。

---

## 2. I2C 驱动冲突导致开机 abort

**现象**：

```
E i2c: CONFLICT! driver_ng is not allowed to be used with this old driver
abort() was called
```

无限重启。

**根因**：`driver/i2c`（旧驱动）被链进镜像，它的 `__attribute__((constructor))`
`check_i2c_driver_conflict()` 在启动时发现新驱动的 `i2c_acquire_bus_handle` 也存在，
于是直接 `abort()`。而 Tab5 BSP 用的是**新** API（`i2c_new_master_bus`）。

值得注意：用户已有的工作固件里旧驱动**也**链进去了，却没有触发 —— 差异未完全查明
（可能与 `--gc-sections` 对 constructor 单元的取舍有关）。

**解法**：`CONFIG_I2C_SKIP_LEGACY_CONFLICT_CHECK=y`。
这正是 IDF 给"我知道旧驱动链进来了但我没用它"提供的官方逃生门。

---

## 3. 漏掉触摸复位 → 显示初始化死循环（最隐蔽的一个）

**现象**：屏幕全黑，`main` 卡住，任务看门狗每 5 秒刷寄存器。解码泄漏的 PC：

```
mipi_dsi_host_ll_gen_is_read_fifo_empty   (hal/mipi_dsi_host_ll.h:690)
  ← mipi_dsi_hal_host_gen_read_short_packet
  ← panel_io_dbi_rx_param                  (esp_lcd/esp_dsi/esp_lcd_panel_io_dbi.c:95)
```

**根因链条**：

1. Tab5 的触摸控制器（ST7121）**必须复位后才会应答 I2C**；
2. `bsp_display_start()` 内部会探测触摸控制器来判定面板型号；
3. 没有复位 → 探测失败 → BSP 走到兜底分支
   `No known touch controller detected, defaulting to ILI9881C`；
4. 实际面板是 **ST7121**，于是 `esp_lcd_ili9881c.c:395` 会通过
   `esp_lcd_panel_io_rx_param()` 去读面板 ID；
5. 面板不是 ILI9881C，不应答 → 主机在 DSI 的 FIFO 上空转，**永远不返回**。

**如何定位**：对比用户已有工作固件的启动日志（`D:\esp\monitor.log`）：

```
I (2448) M5STACK_TAB5: reset tp
I (2650) M5STACK_TAB5: Detected ST7121 touch controller (FW version: 1), using ST7121 display
```

—— 工作固件在探测**之前**调了 `bsp_reset_tp()`，我漏了这一步。

**解法**：严格照工作固件的顺序：

```c
ESP_ERROR_CHECK(bsp_i2c_init());                    // 先起 I2C
bsp_io_expander_pi4ioe_init(bsp_i2c_get_handle());  // bsp_reset_tp() 依赖它建立的设备句柄
bsp_reset_tp();                                     // 复位触摸控制器
bsp_display_start_with_config(&cfg);                // 此时探测才能成功
```

> `bsp_i2c_init()` **不会**创建 `i2c_dev_handle_pi4ioe1`，而 `bsp_reset_tp()` 需要它 ——
> 少调 `bsp_io_expander_pi4ioe_init()` 就会拿空句柄去访问 I2C。

---

## 4. PPA 旋转要求缓存行对齐 → abort → 屏幕闪烁

**现象**：屏幕蓝黑交替闪，日志：

```
E ppa_srm: ppa_do_scale_rotate_mirror(178): out.buffer addr or out.buffer_size
           not aligned to cache line size
ESP_ERROR_CHECK failed: esp_err_t 0x102 (ESP_ERR_INVALID_ARG)
file: esp_lvgl_port_disp.c line 665   func: rotate_copy_pixel
abort() was called at PC ...
```

每约 2 秒 abort 一次 → 面板反复重新初始化 → 看起来像"闪烁"。

**根因**：`esp_lvgl_port` 用 **PPA 硬件**做 90°/270° 旋转，PPA 要求缓冲区按
**数据缓存行**对齐（ESP32-P4 的 L2 缓存行 = **128 字节**）。而缓冲区是由
`heap_caps_aligned_alloc(CONFIG_LV_DRAW_BUF_ALIGN, ...)` 分配的，
`LV_DRAW_BUF_ALIGN` 默认只有 **4**。

**解法**：`CONFIG_LV_DRAW_BUF_ALIGN=128`，并采用与工作固件相同的显示配置
（全屏 PSRAM 双缓冲 + `sw_rotate = true`）。

---

## 5. 改 `sdkconfig.defaults` 不生效

**现象**：加上 `CONFIG_LV_DRAW_BUF_ALIGN=128` 重新编译，`build/config/sdkconfig.h`
里仍然是 4。

**根因**：项目**已存在** `sdkconfig` 时，它会盖过 `sdkconfig.defaults`；
defaults 只影响新符号。而 `LV_DRAW_BUF_ALIGN` 早已被写进旧 `sdkconfig`，
所以新的默认值永远不会被采纳。

**解法**：改完 defaults 后 `Remove-Item sdkconfig` 再 `idf.py reconfigure`。

---

## 6. USB：控制传输在客户端任务里同步等待 → 死锁

**现象**（三连击，其实是同一个错误的不同表现）：

1. `E USBH: usb_transfer_t callback is NULL` + `Submit CTRL URB error: ESP_ERR_INVALID_ARG`
   —— IDF 拒绝 `callback == NULL` 的 transfer；
2. 补上回调后：`CDC control request 32 timed out`（2 秒超时）；
3. 再之后：`Enqueue URB error: ESP_ERR_INVALID_STATE` + `RX submit failed` 刷屏。

**根因**：

- 控制传输**只在 `usb_host_client_handle_events()` 内完成**；
- 而我**在客户端任务自己里**调 `issueLineCoding()` 并原地 `vTaskDelay` 等完成 ——
  任务把自己锁死，回调永远不触发；
- 那两个 URB 一直悬在主机控制器里，导致之后**所有** bulk 提交都以
  `ESP_ERR_INVALID_STATE` 失败。

**解法**：

- CDC 控制请求改为**即发即忘**，在回调里 `usb_host_transfer_free()`；
- 并且**推迟到控制请求全部落地后**再置 `device.valid = true`、才提交第一个
  bulk RX。

---

## 7. USB：在事件回调里做认领 → 事件泵被堵死

**现象**：控制请求立即返回但设备无应答；日志显示 TX 比请求晚 **2 秒**才发出去。

**根因**：`claimDevice()` 是**从客户端事件回调内部**调用的，而那个回调本身就在
`usb_host_client_handle_events()` **里面**。整个认领流程（含等待控制请求）
把事件泵堵住了。

**解法**：拆成状态机 —— 事件回调只做"打开/认领接口"并置 `finish_pending` 后立即返回；
客户端任务循环里检查事件，等控制请求计数归零后再调 `finishClaim()`。

---

## 8. USB：在客户端任务里跑会话查询 → 又是同一个死锁

**现象**：帧终于发出去了，但仍在 2 秒后才发；设备来不及应答。

**根因**：`transport_state()`（在客户端任务里）直接调
`g_client.OnTransportState(true)`，它会**依次发出多个请求并阻塞等应答**，
而应答只能由同一个客户端任务泵出来。

**解法**：把设备查询挪到**独立的 `cham_query` 任务**；`transport_state()` 只置标志 +
`xSemaphoreGive` 就返回。

> 这个模式在这个项目里出现了三次：**任何等待 USB 完成事件的代码都不能跑在
> USB 客户端任务上**。这是写 USB 主机类驱动时值得记住的一条。

---

## 9. 协议：帧头长度搞错（最终 boss）

**现象**：所有环节都验证通过（枚举、端点、OUT 传输 `status=0`、设备也确认收到了），
但 bulk IN **永远收不到数据**，每次请求都超时。

**根因**：帧头布局错了。

| | 0 | 1 | 2-3 | 4-5 | 6-7 | 8 | 9+ | 尾 |
|---|---|---|---|---|---|---|---|---|
| **正确** | SOF | LRC1 | CMD | STATUS | LEN | **LRC2** | DATA | LRC3 |
| 我最初的 | SOF | LRC1 | CMD | STATUS | **LRC2** | LRC3 | DATA | LRC3 |

我把 `LRC2` 写到索引 6-7，**覆盖了 `LEN` 字段**，整帧还是 11 字节。
设备按 `LEN` 解析后一直在等永远不来的字节，于是**永不应答且不报错**。

正确帧头 **9 字节**，空载荷帧 **10 字节**：

```
GET_APP_VERSION: 11 EF 03 E8 00 00 00 00 15 00
```

**为什么会绕这么久**：中途我用一段**手打的 hex 字符串**做比对基准，手打时多写了
一个 `00`，得到"验证通过"的假象。

**解法 + 防回归**：写了 `tools/verify_frame.py`：

- 直接 `import` 官方 `chameleon_com.py` 当判定基准
- 用 `g++` 把**真实的 `chameleon_protocol.cpp`** 编成本机程序执行
- 覆盖 7 种载荷长度（0/1/3/7/64/256 字节）**双向**比对
- 外加坏 LRC1/LRC2/LRC3、截断、前导垃圾重同步

结论：**验证协议必须调用参考实现本身，绝不能手抄其输出。**

---

## 10. 同一课再犯一次：T55xx 密码常量

低频克隆写下去的第一版常量是"凭印象"填的：

```cpp
constexpr uint8_t kT55xxNewKey[4] = {0xFF, 0xFF, 0xFF, 0xFF};
constexpr uint8_t kT55xxOldKeys[4][4] = { {FF,FF,FF,FF}, {00,00,00,00}, {A0,A1,A2,A3}, {20,21,22,23} };
```

注释还写着"Order matches chameleon_cli_unit.py"。实际官方 `chameleon_cmd.py` 是：

```python
new_key  = b'\x20\x20\x66\x66'
old_keys = [b'\x51\x24\x36\x48', b'\x19\x92\x04\x27']
```

**一个字节都不对**，而且数量也不对（2 组而非 4 组）。后果是克隆看起来"成功"
（固件总是返回 `LF_TAG_OK`，注释里写着 *writing results should be verified by upper computer*），
但写进去的密码和标签实际密码不一致，卡就废了 —— 而且**在没有真卡之前完全测不出来**。

对策：`tools/verify_lf.py` 直接从 `chameleon_cmd.py` 里 `ast.literal_eval` 出真实常量，
和 C++ 源码里的数组做逐字节比对。它当场就抓出了这个 bug（还有下面第 11 条）。

---

## 11. 低频协议：上游固件的三个"陷阱"

这三条都不是 Tab5 侧的问题，是照着上游实现写代码时会踩的坑。
`tools/verify_lf.py` 把三条都固化成了自动检查。

### 11.1 `HIDPROX_SCAN` 空载荷会打死变色龙固件

```c
static data_frame_tx_t *cmd_processor_hidprox_scan(...) {
    uint8_t card_data[16] = {0x00};
    status = scan_hidprox(card_data, data[0]);   // ← data 可能是 NULL
```

同一个文件里 ioProx 版本就写得很谨慎：`uint8_t hint = (data != NULL) ? data[0] : 0;`。

`data_frame_make()` 在载荷长度为 0 时把 `data` 传成 `NULL`，所以**不带 hint 字节的
`HIDPROX_SCAN` 会让变色龙解引用空指针**。现象是设备从 USB 掉线，而 Tab5 只看到
`device detached` —— 很容易误判成刚写好的 USB 主机驱动又出问题了。

### 11.2 HIDProx 写命令的字段名是反的

```c
typedef struct {
    uint8_t id[13];
    uint8_t old_key[4];    // ← 名字
    uint8_t new_keys[4];   // ← 名字
} PACKED payload_t;
```

但官方 CLI 发的是 `struct.pack('!13s4s...', id, new_key, old_keys...)`，
和**其它所有** `*_WRITE_TO_T55XX` 完全一致。以 CLI 为准 —— 它才是真正跑通过的客户端，
固件里那两个变量名只是标错了。

### 11.3 `EM4X05_SCAN` 回复长度固件和 CLI 对不上

固件 `data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(payload), ...)` 里的 `payload`
是 `{u32 config; u32 uid; u32 uid_hi; u8 is_em4x69;}` = **13 字节**；
而 `chameleon_cmd.py` 按 `struct.unpack('!IIIBB', resp.data[:14])` 解 —— **14 字节**，
多一个 `uid_block`。也就是说官方的 Python 读 EM4x05 在当前固件上会抛
`struct.error`。本项目的解析按 13 字节处理，长度更大时也不越界。

---

## 12. 用原地排序替掉 bucket_sort：一个"顺序"陷阱（最隐蔽的一个）

为了省掉上游 `bucket_sort_intersect()` 需要的 32 MB 桶暂存，我把
`recover()` 里的"桶内求交集"改成了**原地基数排序 + 扫描相同高位字节的连续段**。
当时的自检是"排序本身正确"（100 万元素，0 处逆序）——
**排序确实是对的，但被它替换掉的那个循环顺序是错的。**

```c
/* 上游：两个表桶排后，只把「两边都非空」的桶紧凑写回，然后 */
for (int i = bucket_info.numbuckets - 1; i >= 0; i--)   /* ← 倒序！ */
    sl = recover(...);
```

我写成了正序（`for (oi = 0; ...)`）。为什么这会是致命的：

`extend_table()` 是**原地增长**的 —— 一个桶在递归里展开时会把新元素写在
`*end` 之后，也就是**越界写进下一个桶的区域**。上游从高位桶往低位桶处理，
被覆盖的区域**已经消费完了**，无害；正序处理时被覆盖的正是**还没轮到**的桶，
于是后面每个桶拿到的都是垃圾，恢复出的状态数从 5 万跌到个位数。

这个 bug 不会崩、不会报错、也不会触发我加的那些边界保护 —— 它只是**安静地找不到密钥**。

**定位方式**：`tools/probe_mfkey32.py` 把同一条合成轨迹分别喂给
「我的实现」和「上游 `software/src/crapto1.c` 原版」，两边都打印恢复出的状态数：

```
two distant nonces
  mine    : states=24     key_in_list=0 second_auth_ok=0
  upstream: states=53329  key_in_list=1 second_auth_ok=1
```

一眼就能看出问题在恢复表、不在 mfkey32 外层。改成倒序后两边**完全一致**：

```
  mine    : states=53329  key_in_list=1 second_auth_ok=1
  upstream: states=53329  key_in_list=1 second_auth_ok=1
```

教训：**替换掉上游一段逻辑时，"我的替代品本身正确"不等于"替换是等价的"。**
被替换代码的*迭代方向*、*调用顺序*、*副作用时机*都可能是算法的一部分。
这类"静默错误"（不崩，只是算不出来）只能靠**和上游对拍**发现。

---

## 13. 内存账目：一个虚构出来的 32 MB

`Mfkey32RequiredBytes()` 是照上游的分配清单抄的，其中包含那 32 MB 桶暂存。
但那块内存在第 12 条的重写里**已经不再分配**，账目却没人改：

```cpp
return kOddTableBytes + kEvenTableBytes + kStateListBytes + kBucketBytes;
//                                                          ^^^^^^^^^^^ 32 MB，早就不存在了
```

于是这道"内存够不够"的闸门报 **50 MB**，而 Tab5 实际只有约 **24 MB** 空闲 PSRAM：

```cpp
if (free_psram < required) return KeyRecoveryStatus::OutOfMemory;
```

**真机上每一次密钥恢复都会在开始前直接失败**，而且失败得"很合理"（内存不足），
最容易让人以为 PSRAM 不够、转头去优化算法 —— 实际算完只要 18 MB。

去掉 `kBucketBytes` 后闸门报 18874368 = 18.00 MB，与实测峰值**完全吻合**。

教训：**删掉一块分配之后，必须同时改掉"需要多少内存"的记账。**

---

## 14. 死代码藏住的两个内存假设

把 darkside 接到 Keys 页之后，链接一次性炸出两屏错误：

```
error: --enable-non-contiguous-regions discards section `.sbss.s_resume_cores'
       from `esp-idf/esp_system/libesp_system.a(cpu_start.c.obj)'
... （几十行，全是 .sbss）
```

**根因**：`crapto1.c` 里的 `filterlut` 是 **1 MiB** 的静态数组，靠
`EXT_RAM_BSS_ATTR` 放进 PSRAM。但 `esp_attr.h` 里它是这么定义的：

```c
#if CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY
#define EXT_RAM_BSS_ATTR _SECTION_ATTR_IMPL(".ext_ram.bss", __COUNTER__)
#else
#define EXT_RAM_BSS_ATTR          /* ← 展开成空 */
#endif
```

而本项目的 `sdkconfig` 里 `CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY` **没开**。
于是那 1 MiB 直接落在只有 ~317 KB 的内部 SRAM 里，把 `.sbss` 挤爆。

**为什么以前没发现**：`chameleon_crypto` 之前**没有任何调用者**，被 `--gc-sections`
整个丢掉（map 文件里查不到 `lfsr_recovery32` / `filterlut`），所以那张表放在哪儿都无所谓。
Keys 页一引用它，假设立刻被检验。

> 教训：**一个组件"没被引用"时，它的资源假设从来没有被验证过。**
> 我此前在文档里写"`filterlut` 已用 `EXT_RAM_BSS_ATTR` 放到 PSRAM"——
> 那句话在当时的构建下是**错的**，只是没人能看出来。

修法：`CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY=y`，并且按第 5 条删掉 `sdkconfig`
重新生成。验证方式不是"编译过了"，而是翻 map：

```
.ext_ram.bss    0x480e0000   0x100000
```

正好 1 MiB，地址在 PSRAM 段（`0x4800_0000` 起）。

### 同一轮里的第二个 128 MB

顺手把 darkside 也接了进来，于是又碰到一个同类问题，在 `lfsr_common_prefix()`：

```c
s = statelist = CP_MALLOC((sizeof * statelist) << 24); // was << 20. Need more for no_par special attack. Enough???
```

`8 × 2²⁴` = **128 MB**。板上总共 32 MB、可用约 24 MB —— 直接移植的话
`CP_MALLOC` 失败返回 NULL，`nonce2key` 返回 0，**darkside 会永远"找不到密钥"**，
而且看起来完全像是"卡不支持"。上游那句注释里的问号（*Enough???*）说明他们自己也是估的。

**不需要猜**：`check_pfx_parity()` 每处理一个 `(odd, even, top)` 三元组最多追加 1 个状态，
`top` 固定循环 64 次，所以

```
odd_count × even_count × 64
```

是**严格上界**。两个 count 都能在分配前数出来；实测每侧只有 32~96 个候选
（16 位过滤后 2²¹ 只剩 2⁵ 量级），于是实际只要几百 KB。

同一个函数里还有个更隐蔽的：`lfsr_prefix_ks()` 用 `CP_CALLOC(4 << 10, 1)` 分配
**1024 项**，却可能写进 2²¹ 项，**完全没有边界检查**。实际候选数远小于 1024 所以没炸过，
但那是运气。已改成显式容量 + 越界返回失败。

验证方式仍然是**和上游对拍**（`tools/probe_darkside.py`）：26 组输入、最大一组
219648 个候选密钥，本项目与上游 `mfkey.c` 输出的密钥列表**逐个一致**。

---

## 15. 每次"没找到密钥"泄漏 1.7 MB

`DarksideSearch::Feed` 是我**手写**的（上游 `darkside.c` 的 main 循环改写成增量版），
所以它不像 `crapto1.c` 那样有"上游原件"可以逐行对照。为了不让它成为唯一没跑过的代码，
写了 `tools/verify_darkside_search.py`：把 `darkside.cpp` 编到主机上，喂进真实采集数据，
并用上游 `nonce2key` 的输出当预期值。

第一次跑就抓到一个会**让 darkside 在真机上彻底废掉**的 bug：

```
[3] par != 0 resets the running state
  call 0 returned 0 total 0 started 0 current 1757256
  call 1 returned 0 total 0 started 0 current 3514448   ← 又涨了 1.7 MB
```

每调用一次泄漏 **1.7 MB**。来源在 `nonce2key()` 的返回值语义上：

```c
unionstate.states = lfsr_common_prefix(...);
if (!unionstate.states) { *keys = NULL; return 0; }   /* 这一路 *keys 是 NULL */
for (i = 0; unionstate.keylist[i]; i++) { ... }       /* 列表为空则 i == 0 */
unionstate.keylist[i] = -1;
*keys = unionstate.keylist;                           /* 但这一路 *keys 有效！ */
return i;
```

也就是说 **`count == 0` 有两种含义**：`*keys == NULL`（没分配），或
`*keys` 指向一块**已经分配好但内容为空**的缓冲区（第一个状态就是终止符，
即所有奇偶校验都没过）。我按"count 为 0 就没东西要释放"写了早退：

```c
if (count == 0 || keys == nullptr) return 0;   /* ← 后者那 1.7 MB 就漏了 */
```

而"所有奇偶校验都没过"**正是打不动的卡的常见结果** —— darkside 循环最多 60 轮，
60 × 1.7 MB = 100 MB，而可用 PSRAM 只有约 24 MB：**第 14 轮左右就会把 PSRAM 耗尽，
连 LVGL 的缓冲区都分配不出来。**

上游 `darkside.c` 有同样的泄漏，但它是短命进程，跑完就退出，所以没人发现。

修法：

```c
if (keys == nullptr) return 0;
if (count == 0) { FreeNonceList(keys); return 0; }
```

> 这一条和第 12 条是同一类：**"没找到"这条路径永远比成功路径更难被测到**，
> 而它恰恰是用户最常遇到的那条。写主机测试时要特意喂"打不动的卡"这种输入，
> 不能只测成功用例。

---

## 16. 把"序号"当成"字符"传：按键配置命令

补齐系统命令时，`GET_BUTTON_PRESS_CONFIG` 我按直觉传了 `0` / `1`（A 键、B 键的序号）：

```cpp
for (uint8_t button = 0; button < 2; ++button)
    client.GetButtonPressConfig(button, &fn);
```

真机日志：

```
button 0: press fn failed, long press fn failed
button 1: press fn failed, long press fn failed
```

翻固件才看到：

```c
bool is_settings_button_type_valid(char type) {
    switch (type) {
        case 'a': case 'b': case 'A': case 'B': return true;
        default: return false;
    }
}
```

**参数是 ASCII 字符 `'A'`/`'B'`，不是索引**，传 0/1 一律回 `PAR_ERR`。
`chameleon_cmd.py` 的方法签名 `get_button_press_config(button)` 看不出这一点，
命令枚举里也只有 `GET_BUTTON_PRESS_CONFIG` —— **只能去读固件的校验函数**。

## 17. 同一个设置的读和写范围不一致

`MF1_GET_WRITE_MODE` 在真机上返回 **31**，而 setter 明确拒绝大于 3：

```c
if (length != 1 || data[0] > 3) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
```

而 `chameleon_commands.h` 里 `MfcWriteMode` 定义了 **5 个**值（0..4）。
三处不一致：枚举 5 个、getter 返回 31、setter 只收 0..3。

处理方式：**只写 0..3**（setter 是唯一有明确校验的），读回来的值当原始字节显示，
并在注释里写明上游自己就不一致 —— 不替上游"修正"，也不假装它就是当前模式。

## 18. 日志环形缓冲会静默截断长行

第一次跑 "report device state" 时，32 个 capability 只打出来 16 个：

```
I (15638) app: [log] 32 capabilities: 1000 1001 ... 1014 101
```

不是协议问题：`LogEntry` 的文本字段只有约 90 字符，`LogEvent` 写超了就截断，**且不报错**。
对策是一条日志一件事、长列表分批。

> 这类"输出被截断"很容易被误读成"设备只返回了 16 个" ——
> 看到不完整的列表时，先分清是设备没发还是显示被截。

---

## 19. 工具与环境

### 不要用 PowerShell 的 `Get-Content`/`Set-Content` 往返改这些文件

本文件就被这样毁过一次：

```powershell
$t = Get-Content $p -Raw          # ← 默认按 ANSI 解码
Set-Content -Path $p -Value $t    # ← 按 UTF-8 写回，还带 BOM
```

这台机器上的 `pwsh` 实际是 **Windows PowerShell 5.1**，`[Text.Encoding]::Default`
是 **gb2312**。于是 UTF-8 的中文被按 GB2312 解码成乱码，再以 UTF-8 写回 ——
而且 GB2312 中未定义的字节对被替换成 `?`，**不可逆**。

修法只有两条：改用文件编辑工具，或者显式指定编码
（`Get-Content -Encoding utf8` / `Set-Content -Encoding utf8NoBOM`，后者要 PS 7）。

顺带一条：**控制台里的中文输出不可信**（本机 CP 是 gb2312），
判断文件内容要看文件本身，别信 `Write-Host` 打出来的样子。

### USB-Serial/JTAG 复位陷阱

Tab5 的 USB-C 是 `USB-Serial/JTAG`，`DTR`/`RTS` 直接接 `GPIO9`/`EN`。
用 `esptool --after hard_reset` 或手工翻转 DTR/RTS 很容易把芯片留在**下载模式**，
必须断电才能恢复。所以：

- 只用 `idf.py -p COM4 flash` 烧录
- 采集日志用 `tools/capture_console.py`（**从不触碰** DTR/RTS）
- 重启请手动按 RST 或断电

### 开机日志丢失

USB-Serial/JTAG 的 FIFO 很小，`esp_psram` 等开机信息在 115200 下会把它撑爆，
应用自己的日志会被丢掉。对策：

- `CONFIG_LOG_DEFAULT_LEVEL_INFO=y` + `CONFIG_BOOTLOADER_LOG_LEVEL_WARN=y`
- 采集脚本在复位**之前**就打开串口并持续落盘
- 临时调试时把任务看门狗设为只警告（`CONFIG_ESP_TASK_WDT_PANIC=n`），
  否则它每 5 秒一次的寄存器 dump 会把 FIFO 彻底刷满

### 地址符号化

`tools/decode_boot.py` 用 `riscv32-esp-elf-addr2line` 把 panic dump 里的裸地址
还原成函数名 —— 第 3 条死循环就是靠它定位的。

---

## 20. "这部分应该是壳吧" —— 一个把结论推向反面 47 倍的判断

hardnested 的搬迁最初是这样估的：用 grep 数引用，发现两个 core
（`hardnested_bf_core.c` / `hardnested_bruteforce.c`）对 `tables.h` **零引用**，
而 `tables.h` 只被 `tables.c` 自己和 `cmdhfmfhard.c` 引用。于是写下结论：

> 5 MB 的 `tables.c` 是 bitflip 路径专用，两个 core 都不引用，**不需要移植**；
> `cmdhfmfhard.c`（85 KB、33 处 pthread）是 Proxmark3 的**客户端命令层**，本项目会替换，**不需要移植**。
> 所以 hardnested 只有 83 KB 要搬。

**引用计数是对的，结论是错的。** 用表的确实不是 core —— 是编排层。
而 `cmdhfmfhard.c` 里除了 pthread 和文件 IO 这些壳，还有真正的算法半边
（`init_bitflip_bitarrays()` / `generate_candidates()` / `estimate_sum_a8()`），
它恰恰是那张表的主要用户。我把"有壳"直接读成了"只有壳"。

量完之后（`tools/measure_hardnested_tables.py`，逐个解压 `tables.c` 里的 351 个 XZ 块）：

| | |
|---|---|
| `tables.c` 源码 | 5,060,449 B —— 里面其实只有 **0.75 MiB** 的 XZ 数据（每字节写成 6 个字符） |
| 解压后 | **702 MiB**（351 块，每块恒定 2 MiB = 2²⁴ 位位图） |
| 通过上游阈值保留的 | 偶态 145 + 奇态 92 = **237 块** |
| `bitflip_bitarrays[2][0x400]` 常驻 | **474 MiB** |
| `nonces[256].states_bitarray[2]` 常驻 | **1 GiB**（256 个首字节 × 2 张 2 MiB 位图，`cmdhfmfhard.c:522/529` 无条件分配） |
| `malloc_bitarray` 是否是虚拟分配 | 不是，`MALLOC_BITARRAY` 就是 `memalign`（`hardnested_bitarray_core.c:194`） |

**合计约 1.5 GB 常驻 vs 板子 32 MB PSRAM。** 这不是"慢"，是**放不下**；
而"2²⁴ 位全量位图"这个数据结构是算法的核心，把它换成稀疏实现属于重新实现，不属于移植。

> **教训（本项目第三次同类，但这次代价最大）**：引用计数只能回答"谁用了它"，
> 不能回答"它是不是壳"。要判断"这部分不用搬"，得**打开它看里面有没有算法**，
> 再用 grep 数出来的引用去**交叉印证**，而不是代替。
> 前两次（T55xx 密码常量、桶遍历顺序）是"凭印象写常量"，
> 这次是"凭印象给文件归类" —— 同一个毛病的两种形状：
> **凡是"这部分应该是……"开头的判断，都必须落到一条可执行的测量上。**

顺带一个反直觉的收获：**体积从来不是障碍**（5 MB 源码只值 0.75 MiB flash），
内存才是。如果当初按"5 MB 太大"来否掉 hardnested，会否掉一个错的东西；
真正否掉它的是 1.5 GB。

---

## 21. 探针抓到的两个"显然不会错"的 bug

hardnested 的客户端半边（`firmware/main/hardnested_acquire.{h,cpp}`）
是纯 C++、无 ESP 依赖，所以能在主机上和上游对拍（`tools/verify_hardnested_acquire.py`）。
它对拍的第一版就抓到两个真 bug，都属于"写的时候完全没觉得有问题"：

### (a) 行缓冲区少一个字节 → `printf` 读到下一行

导出行格式是 `[HN] ` + 4 位 offset + 空格 + 16 字节 hex。常量写成了

```cpp
constexpr size_t kExportLineLength = 5 + 4 + kExportBytesPerLine * 2;   // ← 少了 offset 后那个空格
```

于是 NUL 落在缓冲区之外，`printf("%s")` 顺着内存读到下一行 ——
导出的"一行"变成 7 KB，`[HN]` 数据行的正则匹配数从 170 变成 14535。
probe 里"每行必须放得进 96 字符日志行"这条检查就是靠这个数字露头的。

> 教训：**把"格式串的字符数"和"缓冲区大小"分开手算，就一定会算错一次**。
> 要么让编译期算（`sizeof` 推导），要么让检查盯着最终产物的长度。

### (b) 解析器只认行首标记，而真实日志里标记永远不在行首

设备上这些行要过 `ESP_LOGI`，实际形态是

```
I (12345) tab5: [log] [HN] 0000 0411A2B3...
```

Python 解码器用 `re.search`（能找到），C++ 解析器用 `strncmp(line, "[HN] ", 5)`
（要求 index 0）—— 两边就此分叉，而且**在主机上单测 C++ 解析器时不会暴露**，
因为主机 harness 当时打印的是不带前缀的行。
修法是改成 `strstr`，并让 probe **故意用带前缀的形式同时喂两个解码器**。

> 教训：**"单元测试用的输入"和"真实链路上的输入"必须长得一样**，
> 否则测的是另一个函数。这里真实链路多了一层日志前缀，
> 而前缀恰恰是唯一能让两个实现分叉的东西。

---

## 22. `MF1_CHECK_KEYS_ON_BLOCK` 的载荷少了 1 个字节、字段还反了

这一轮的 payload 对拍（`tools/verify_payloads.py`）是这么做的：
把**移植的客户端**编到主机上，用一个假传输录下每个方法发出的帧；
再把**上游的 `chameleon_cmd.py` 原样 import**，用假设备录下它构造的载荷；
逐条比对命令号与字节。除此之外，还把 `app_cmd.c` 里每个 handler 的
`PACKED payload_t` 解析出来，用设备实际读取的字段长度做第三重校验。

它抓到的第一条就是：

```
FAIL mf1_check_keys_on_block
      port     (14): 6003FFFFFFFFFFFFA0A1A2A3A4A5
      upstream (15): 036002FFFFFFFFFFFFA0A1A2A3A4A5
```

两种可能：移植写错了，或者上游写错了。设备端是裁判 ——
`app_cmd.c cmd_processor_mf1_check_keys_on_block()`：

```c
if (length < 9 || data[2] * 6 + 3 != length) return PAR_ERR;
in.block = data[0]; in.key_type = data[1]; in.keys_len = data[2];
in.keys = (mf1_key_t *) &data[3];
```

即 `block | key_type | key_count | keys`，Python 与设备一致，**移植错了**：
原来发的是 `key_type | block | keys`，既没有 count 字节，前两个字段还是反的。
设备会直接把 `keys` 的第一个字节当成"密钥个数"（那是个密钥字节），
`data[2]*6+3` 几乎不可能等于实际长度，于是**固定返回 `PAR_ERR`**。

修好之后，同一份对拍里 71/72 条逐字节相同（剩下那条是上游 Python 根本没实现、
只能对 `app_cmd.c` 校验的 `LF_T55XX_WRITE`）。

两点值得单独记：

- **这条命令当前没有调用者**（界面走的是 `MF1_CHECK_KEYS_OF_SECTORS`，
  那份载荷是对的）。所以这是一个**潜在的**、永远不会在真机上暴露的错 ——
  只有"把每个命令的载荷都拿出来比一遍"才能发现。这正是把对拍做成工具的理由：
  靠人眼审代码时，没有调用者的代码是第一个被跳过的。
- **"上游也这么写"不能当判据**：这次三方（移植 / Python / 设备）里有两方一致，
  必须先确定谁才是规格。`app_cmd.c` 是唯一的裁判，Python 只是它的一个客户端。

顺带清掉的两个对拍脚手架坑（都属于"判据本身不严谨"）：

- 上游有些方法**先探测再发命令**（`em410x_set_emu_id()` 先读活动槽的 LF 类型），
  所以不能拿"第一次调用"当载荷，要拿**命令号对得上的那一次**；
- 槽位号上游 API 是 1 起（`SlotNumber`，用 `to_fw()` 减 1 上线），
  移植的客户端直接收 0 起的固件值 —— 两边必须换算后再比，
  否则会得到一堆假的"off-by-one 不一致"。


