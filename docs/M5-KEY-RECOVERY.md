# M5 - 密钥恢复移植状态

## 结论一览

| 项 | 状态 |
|---|---|
| Crapto1 / Crypto1 原语（`prng_successor` / 密钥流 / 认证复核） | ✅ 对照官方向量与实时 `crypto1.py` |
| `lfsr_recovery32` 恢复内核 | ✅ **与上游 `software/src/crapto1.c` 对拍完全一致** |
| `mfkey32v2` 端到端恢复 | ✅ 合成轨迹能恢复出密钥，第二条认证复核通过；峰值 18.00 MB |
| `nonce2key`（darkside 破解核心，`mfkey.c`） | ✅ **与上游 `mfkey.c` 对拍逐个密钥一致**（26 组输入，最大 219648 个候选） |
| 候选表边界检查 | ✅ 已加（越界返回失败，不再踩内存） |
| 128 MB 固定分配 → 按候选数计算 | ✅ 实测降到几百 KB（见第 4 节） |
| 设备命令 | ✅ `MF1_DARKSIDE_ACQUIRE` / `MF1_CHECK_KEYS_OF_SECTORS` / `MF1_CHECK_KEYS_ON_BLOCK` 已接入 |
| `nested` / `staticnested` 破解核心 | ✅ 已移植并验证（候选密钥集合与上游逐个相同） |
| `hardnested` **客户端半边**（采集 + 首字节奇偶和 + nonce 文件 + 串口导出） | ✅ 已移植并验证（第 6.2 / 6.4 节） |
| `hardnested` **破解核心** | ⚠️ 搬了、能编，但**有意不链接**；候选生成实测要 1.5 GB 常驻（第 6.1 节） |
| **Keys 界面页** | ✅ `main/pages_keys.cpp`，跑在独立任务上，不阻塞触控 |
| **真卡验证** | ❌ **没有 Mifare Classic 卡**，成功路径从未在真卡上跑过 |
| `mfkey32` 接入界面 | ❌ 需要嗅探轨迹，见第 5 节 |

---

## 1. Tab5 上的密钥恢复是怎么做的

官方的密钥恢复是**分两半**的：变色龙固件负责射频采集，PC 上的独立程序负责算。
本项目把"算"的那一半搬到了 Tab5 上：

| 路线 | 设备负责 | 原本谁算 | 现在谁算 |
|---|---|---|---|
| 出厂密钥检查 | `MF1_CHECK_KEYS_OF_SECTORS` 逐个认证 | 设备自己 | 不需要算 |
| **darkside** | `MF1_DARKSIDE_ACQUIRE` 采集 `(uid, nt, nr, ar, par, ks)` | PC 上 `darkside.exe` | **Tab5 上 `DarksideSearch`** |
| mfkey32 | 无（要嗅探） | PC 上 `mfkey32v2.exe` | Tab5 上 `Mfkey32()`（已实现，未接线） |

`DarksideSearch`（`components/chameleon_crypto/src/darkside.cpp`）是
`software/src/darkside.c` 主循环的增量版本：每次采集喂进去，维护"候选密钥集合"，
`par == 0` 时取两次采集结果的**交集**（`intersection`），`par != 0` 时直接输出全部候选
（官方 CLI 在这种情况下会清空已收集的列表，这个行为也照搬了）。

> **每个候选密钥都会先用 `MF1_AUTH_ONE_KEY_BLOCK` 让卡真的认证一次**，
> 认证不过就丢弃。这不是可选的礼貌 —— 候选集合可能有几千个，
> 只有卡自己知道哪个是真的。

---

## 2. 四个真实错误（都已修）

### (a) Crypto1 是有状态的

我最初让每次 `crypto1_word` 都新建状态，导致 ks1 变成 ks0 的 PRNG 后继
（得到 `ACD39706`，正确值是 `BAA3C92B`）。参考实现三次调用共用同一个实例。
→ 改为 `Crypto1WordSequence()` 序列接口。

### (b) 用错了算法变体

CLI 实际用的是 **`mfkey32v2`**，不是 `mfkey32`。两者只差第二段认证的校验：
v2 用 `uid ^ nt1` 和 `prng_successor(nt1, 64)`，而 `mfkey32.c` 复用第一段的 nonce。
→ 照 `software/src/mfkey32v2.c` 逐行对齐。

### (c) 桶遍历顺序写反（**真正让 mfkey32 永远失败的那个**）

用原地基数排序替掉 `bucket_sort_intersect()` 之后，我按**正序**遍历各桶；
上游是**倒序**。`extend_table()` 原地增长时会越界写进下一个桶的区域 ——
倒序时那块区域已经消费完了，正序时它正是**还没轮到**的桶。

后果：同一条轨迹，上游恢复出 **53329** 个候选状态，我只恢复出 **24** 个，
密钥永远找不到，而且**不崩、不报错**。

定位靠 `tools/probe_mfkey32.py`：把同一条轨迹喂给两个实现，直接比状态数。
详见 `docs/PORTING-NOTES.md` 第 12 条。

### (d) 内存账目报了一个虚构的 32 MB

`Mfkey32RequiredBytes()` 还在累加那 32 MB 桶暂存（早就改成原地排序了），
于是闸门要 **50 MB**，而板子只有约 24 MB —— **真机上每次恢复都会以
"内存不足"提前返回**。去掉后报 18.00 MB，与实测峰值吻合。
详见 `docs/PORTING-NOTES.md` 第 13 条。

---

## 3. 关于"候选表越界"的旧结论：已更正

本文件早先写过一条结论，说 `extend_table*` 的越界写会以
`0xC0000374 STATUS_HEAP_CORRUPTION` 崩掉，并据此怀疑"能跑通不可信"。
**那条推断是错的。**

当时的崩溃来自**测试脚手架自己**：我给主机测试写了一个带 16 字节记账头的
替身分配器，它把返回给被测代码的指针整体偏移了 —— 是替身分配器破坏了内存，
不是 crapto1 踩了界。换成非侵入式的宏记账（`-include host_alloc_tracker.h`）
之后崩溃立刻消失。

**结论：真正让恢复失败的是桶顺序 (c)，不是内存。** 上游的原地增长确实没有
边界检查，本项目照样补上了（越界返回失败而不是踩内存），
但那是**防御性**的，不是修 bug。

---

## 4. 内存：几个"照抄上游"都会失败的地方

| 位置 | 上游 | 板上现实 | 本项目 |
|---|---|---|---|
| `filterlut` 静态数组 | `.bss` 1 MiB | 内部 SRAM 只有 ~317 KB | `EXT_RAM_BSS_ATTR` → PSRAM。**但必须先开 `CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`**，否则这个宏展开成空（踩过，见 PORTING-NOTES 第 14 条） |
| `lfsr_recovery32` 候选表 | 16 MiB | 可用约 24 MB | PSRAM（`CP_MALLOC`） |
| `lfsr_common_prefix` 状态列表 | **128 MB**（`8 << 24`，注释自称 *Enough???*） | 不可能 | 按 `odd_count × even_count × 64` 的**严格上界**算，实测几百 KB |
| `lfsr_prefix_ks` 候选数组 | `calloc` 1024 项却可写 2²¹ 项 | 无边界检查 | 显式容量 + 越界返回失败 |
| ~~bucket 排序工作区~~ | ~~32 MiB~~ | — | **已删除**：改为原地基数排序 |

实测峰值（mfkey32）：**18.00 MB**，闸门报 18874368 = 18.00 MB，可用约 24.2 MB。
主机侧峰值由 `tools/host_stubs/host_alloc_tracker.h` 以 `-include` 方式
非侵入地统计，测的就是固件里那条分配路径。

---

## 5. `mfkey32` 为什么在这台设备上**无解**（不是没做，是没有数据源）

`mfkey32` 需要两次完整认证的 `(uid, nt, nr_enc, ar_enc)`，其中 `ar_enc` 必须是
**真实卡片**用未知密钥算出来的响应。查了固件源码，设备上两条可能的路都被堵死：

**路一：`HF14A_SNIFF` —— 没有被动嗅探模式。**
`app_cmd.c cmd_processor_hf14a_sniff` 里写得很直白：

```c
/* passive mode intentionally disabled: CU acts as the card so it must
 * respond normally to the reader (ATQA/UID/SAK). TX sniff captures responses. */
```

设备**必须处于模拟器模式**，由它自己扮演卡片。也就是说抓到的响应是**它自己算的** ——
而它要算出 `ar_enc` 就必须先知道密钥，也就是 mfkey32 想要找的那个密钥。循环依赖。

**路二：`HF14A_AUTH_TRACE` —— 需要先给出密钥。**
这个命令确实能对着真卡跑完整认证并返回每一帧，但：

```c
/* Encrypt NR + parity */
for (int pos = 0; pos < 4; pos++)
    mf_nr_ar[pos] = crypto1_byte(&pcs, nr[pos], 0) ^ nr[pos];   // ← 用给定的 key 算的
...
pcd_14a_reader_bits_transfer(mf_nr_ar, 64, par, answer, parity_resp, &len, ...);
if (len != 32) return STATUS_MF_ERR_AUTH;   // 密钥不对，卡根本不回 AT
```

第三帧（`nr_enc || ar_enc`）是**设备用给定密钥自己算的**，第四帧（卡的真 AT）只有在
**密钥正确**时才会出现。所以这条命令产出的轨迹，其密钥本来就已知 —— 拿它喂 mfkey32
只会解出同一个密钥。

**结论**：不是"还没来得及接"，而是**设备没有能提供未知密钥卡响应的数据源**。
官方 CLI 的做法（PC 端被动嗅探 + `mfkey32v2.exe`）依赖 PC 侧的嗅探器，
Tab5 + 变色龙这套硬件组合给不出来。`Mfkey32()` 内核仍然是已验证的（见第 2 节），
它可以在**从别处拿到轨迹**时使用，例如从 PC 嗅探日志里抄进来的 nonce。

### 顺手做了：轨迹解码器

既然 `HF14A_AUTH_TRACE` 的输出仍然值得看（能确认认证过程、看 nt/AT 对不对），
把它的帧格式做了解码器：`firmware/components/chameleon/src/sniff_decoder.cpp`。

- 按**位计数**遍历帧（轨迹以 7 bit 的 REQA 开头，不能假设字节对齐）
- 识别四帧一组认证：reader 的 `60/61`、卡的 `nt`、device 的 `nr_enc||ar_enc`、卡的 `AT`
- 不完整的认证标 `complete = false`，**不会被误当成可用素材**

验证方式 `tools/verify_sniff_decoder.py`：用参考 `crypto1.py` 造一条真实认证，
按固件的 `auth_trace_store()` 打包成轨迹，解码器必须原样吐出 `nt` / `nr_enc` / `ar_enc`；
另外验证截断的轨迹不会产出 `complete` 认证。

---

## 6. nested / staticnested 已移植并验证；hardnested 只移植了客户端那一半

> **对第 6 节早先结论的更正**：这里原先写的是"hardnested 只有约 83 KB 需要移植，
> 5 MB 的 `tables.c` 是 bitflip 路径专用、两个 core 都不引用，所以不需要"。
> **前半句对，后半句错**。错在一步推理：我用 `nm`/grep 数出"两个 core 对 `tables.h`
> 零引用"，就推出"整个 hardnested 不需要这张表"—— 但**用表的不是 core，是编排层**。
> 我把 `cmdhfmfhard.c` 一句"这是 Proxmark3 客户端命令层，本项目会替换掉"带过去了，
> 而它里面真正的算法半边（`init_bitflip_bitarrays()` / `generate_candidates()` /
> `estimate_sum_a8()`）恰恰要靠那张表。**教训与本节其他几条一样：先数引用，
> 再量内存，最后才下结论；中间任何一步凭"这部分应该是壳"跳过，结论就会反。**

| 项 | 状态 |
|---|---|
| 采集命令（`MF1_NESTED_ACQUIRE` / `MF1_STATIC_NESTED_ACQUIRE` / `MF1_HARDNESTED_ACQUIRE` / `MF1_ENC_NESTED_ACQUIRE` / `MF1_DETECT_NT_DIST`） | ✅ 已接入客户端 |
| `nested_util.c` 的**单线程改写**（`src/nested.cpp`） | ✅ 已验证（见下） |
| `valid_nonce()` 谓词 | ✅ 与上游 300 组输入**逐一一致**，且真/假两种结果都被覆盖 |
| `NestedRecover()` 与上游 `nested()` 的**候选密钥集对比** | ✅ **完全一致** —— 4 组非空用例，各自 50 把密钥，`only_mine 0 / only_upstream 0` |
| harness 崩溃（`0xC0000374`） | ✅ **已解决 —— 原因在测试脚手架里，不在移植代码里**（见下） |
| `staticnested.c` 的**派生逻辑**（代次识别 + 160 步距离表） | ✅ 与**参考 `crypto1.py` 的 `prng_next`** 逐对一致（gen1-keyA / gen2-keyA / gen2-keyB 三种组合，外加两种拒绝路径） |
| `staticnested.c` 的**搜索部分** | ✅ 复用已验证的 `NestedRecover()`，没有新代码 |
| nested / staticnested 接到 Keys 页界面 | ✅ `nested attack` 按钮 + `KeyJob::Nested` |
| `hardnested` 的**客户端半边**（采集 + 校验和 + nonce 文件 + 导出） | ✅ 已移植并验证（`tools/verify_hardnested_acquire.py`） |
| `hardnested` 的**破解核心**（`hardnested_bf_core.c` / `hardnested_bruteforce.c`） | ⚠️ **已移植、能编译成 esp32p4 目标，但有意不链接**（见下） |
| `hardnested` 的**候选生成**（`cmdhfmfhard.c` 的 bitflip 算法半边） | ❌ **移植不了：实测常驻内存 1.5 GB，是板子 PSRAM 的 47 倍**（见下） |

### 上游那两处必须改写的地方

1. **并发**：`nested_util.c` 把 nonce 列表切成 4 份扔给 `pthread_create`，再合并。
   我改成单线程顺序处理 —— 每个 nonce 是独立的 `lfsr_recovery32()` 调用，
   结果集合与线程数无关，而且单线程的结果**是确定的**（上游的合并顺序取决于线程完成顺序）。
2. **`uniqsort()` 越界读**：上游
   ```c
   for (i = 0; i < size; i++)
       if (possibleKeys[i + 1] == possibleKeys[i])
   ```
   最后一轮读 `possibleKeys[size]`，越界 8 字节。而这个计数结果决定候选密钥的排名，
   所以那个越界读**能改变最终选出哪把密钥**。我改成在边界处直接收尾，
   并在注释里写明这是有意的行为差异。

### 当初为什么必须红着（历史记录 —— 这条现在**已经绿了**）

> 下面这一小节写于"候选集对比还是空集对空集"的时候。后来改用了**真实形态的
> nested nonce**（不再是随手造的 `{ntp, ks1}`），对比就有了内容：
> 4 组非空用例各 50 把密钥，`only_mine 0 / only_upstream 0`。
> 保留这段是因为它记录了"绿灯是怎么变成有意义的绿灯的" ——
> 以及一个更早的问题：当时那个 FAIL **不是**移植的错，是测试自己没测到东西。

`tools/probe_nested.py` 有两条检查，当时第二条**必须**失败：

```
[1] valid_nonce vs upstream
  ok   300 inputs agree
  ok   the predicate is exercised both ways (test is not vacuous)
[2] NestedRecover vs upstream nested()
  FAIL the recovery comparison is non-vacuous (needs real nested nonces)
```

原因：**上游 `nested()` 对合成的 `{ntp, ks1}` 输入返回 0 个候选**，
两边都是空集，"一致"只证明了两边都不崩，什么也没证明。
要让这条检查有意义，需要**真实 nested 攻击会产生的那种 nonce**，
也就是需要一张「已有一个已知密钥扇区」的 Mifare Classic 卡。

另外我的 harness 当时还会以 `0xC0000374`（堆损坏）退出。**排查过程**（保留下来，
因为排掉的假设都是对的，最终根因见后面「崩溃的真正原因」）：

| 假设 | 结论 |
|---|---|
| "`lfsr_recovery32` 在 `in != 0` 时返回的列表没有终止符"（darkside/mfkey32 都传 `in = 0`，这条路从未跑过） | **否**。加了 `walk` 子命令直接调 `lfsr_recovery32` 再走链表：`in=0` 与 `in=ntp` 都干净终止，单次 66614 个状态，进程退出码 0 |
| "tracked 分配配 real free"（脚手架混用分配器） | **已排除**。`nested.cpp` 改用与 `crapto1.c` 同一套分配宏编译；同时修掉了我自己 `walk` 里的同款错误（用裸 `free` 释放 tracked 指针） |
| 候选列表累积到几万条后溢出 | **否**。**单个** nonce 就会崩 |
| "崩在 `uniqSort` 或输出段" | **否**。在 `NestedRecover` 的收集循环之后插了一条 `fprintf(stderr, ...)`（确认过二进制里确实包含该字符串），运行时**一个字都没打出来** → 崩在**收集循环内部** |
| "tracker 自己也被套上了改名宏，`host_real_malloc = malloc` 变成自引用" | **否**。把 `host_alloc_tracker.c` 单独编成 `.o`（`-x c`、不带 `-include`）再链接，崩溃依旧 |
| 崩在移植代码里 | **否 —— 崩溃从头到尾都在我的 harness 里**（见下） |

### 崩溃的真正原因：harness 里的 `strdup` + 宏改名的 `free`

```cpp
char* copy = strdup(argv[2]);   // libc malloc，未被 tracker 记账
...
free(copy);                     // -include 的宏把它变成 host_track_free
```

GCC 的 `-include` 是**整条命令级**选项，所以连 harness 自己也被套上了那套改名宏。
`strdup` 走的是真实 libc malloc，而 `free` 变成 `host_track_free` —— 后者去读一个
**并不存在的 8 字节记账头**，于是堆在 `NestedRecover` **被调用之前**就已经坏了。
这也解释了为什么"一个字都没输出"：损坏发生在第一次 `fprintf` 之前，
崩在 `lfsr_recovery32` 内部的第一次分配上。

而 `walk` 子命令里没有 `strdup`，所以它一直好好的 —— 这正是那条线索
（"崩在收集循环内部"）把我带偏的原因：范围确实缩小了，但缩到了错误的对象上。

改成栈上缓冲、完全不分配即可：

```cpp
char copy[1024];
snprintf(copy, sizeof(copy), "%s", argv[2]);
```

修完之后：

```
recover exit=0
I nested: nested: 84251 candidates from 1 nonces
```

**移植代码本身一次都没有崩过。** 前面五轮排掉的假设全都是对的，
但真正的问题一直在我自己的测试脚手架里。

### 以及一个被这次对拍抓出来的真差异

崩溃修好、对拍变得**非空**之后，立刻暴露出一个语义差异：

```
case 0: mine 256 keys, upstream 50 keys, only_mine 206, only_upstream 0
```

上游的 50 个是我 256 个的**子集**。原因是上游 `uniqsort()` 里的 `count`
统计的是**"重复出现的次数"而不是总次数**：

```c
for (i = 0; i < size; i++) {
    if (possibleKeys[i + 1] == possibleKeys[i]) count++;   // 只在相邻相等时 +1
    else { our_counts[j].count = count; j++; count = 0; }  // 写回后清零
}
```

所以**只出现一次的密钥 count 是 0**，`nested()` 里 `if (ck[i].count > 0)` 会把它丢掉。
我原来存的是总次数（单次 = 1），于是把上游不会输出的单次密钥也输出了。
已改成 `count = run - 1` 以匹配上游语义。

这条差异**只有在对拍真正跑起来之后才可能被发现** —— 也正是这个 probe 存在的理由。

### 那处差异的根因：又是凭印象写死的常量

**已消除** —— 剩下那处差异的根因和前面几次一样，是**我把常量凭印象写死**：

| 常量 | 我写的 | 上游 `nested_util.c` 实际 |
|---|---|---|
| `MEM_CHUNK` | 256 | **10000**（第 19 行） |
| `TRY_KEYS` | 256 | **50**（第 20 行） |

`TRY_KEYS` 直接决定输出多少把候选密钥 —— 所以"我 256 把、上游 50 把、
上游是我子集"的现象**完全由此解释**。改对之后：

```
[0] tuning constants vs nested_util.c
  ok   MEM_CHUNK = 10000
  ok   TRY_KEYS = 50
[2] NestedRecover vs upstream nested()
  case 0..3: mine 50 keys, upstream 50 keys, only_mine 0, only_upstream 0
ALL NESTED CHECKS PASSED (candidate sets identical to upstream)
```

**这是本项目第三次栽在同一件事上**（T55xx 密码常量、HIDProx 字段顺序、现在是这两个常量）。
所以 probe 里加了一条 `[0]` 检查：**直接从上游源码 `#define` 里读出这两个数字**再和
移植代码里的常量比对 —— 让"凭印象写死"这件事不可能再悄悄通过。

### hardnested 的体量与真实依赖（逐文件看过 include 之后）

| 文件 | 大小 | 真实依赖 |
|---|---|---|
| `hardnested/tables.c` | **5,060,449** | **只有** `tables.h` —— 干净的数据表，无平台依赖 |
| `hardnested_benchmark_data.h` | 507 KB | 只被 **benchmark 路径**用，正式攻击大概不需要 |
| `hardnested_bf_core.c` | 33 KB | `crapto1.h` / `parity.h` + `pm3/ui.h`（**只为 `PrintAndLogEx`**）+ `Windows.h` |
| `hardnested_bitarray_core.c` | 31 KB | **`<intrin.h>` 的 `__popcnt64`（x86 专用）** + `Windows.h` |
| `hardnested_bruteforce.c` | 19 KB | pthread（**3 处**）+ `Windows.h`/`share.h`/`io.h`/`libfmemopen` + pm3 util |
| `hardnested_main.c` | 7 KB | 干净：只有 crapto1 / parity / cmdhfmfhard |
| `cmdhfmfhard.c` | 85 KB | **33 处 pthread** —— 但这是 Proxmark3 的**客户端命令层**，本项目会用自己的编排替换，**不需要移植** |
| `pm3/`（`ui.c` / `util*.c` / `emojis.h` …） | ~140 KB | 只有日志与几个小工具函数 → 写替身即可（同 `i2c_bus` 的做法） |

**结论修正（逐文件查 include 之后）**：5.9 MB 里只有约 83 KB 是"源码要搬的部分"。

`tables.h` 只被两个文件 include：`tables.c` 自己和 `cmdhfmfhard.c`。
**两个 core 一次都没有引用它。** 而且 `tables.h` 需要 `<lzma.h>` ——
那 5 MB 是 **LZMA 压缩、运行时解压**的表，服务于 **bitflip 那条攻击路径**
（`get_bitflip()`）。`bitflip` / `lzma` 的引用计数也印证：
`tables.c` 54 处、`tables.h` 7 处、`cmdhfmfhard.c` 6 处，
**`bf_core.c` / `bitarray_core.c` / `bruteforce.c` 各 0 处**。

要移植的源码：

| 文件 | 大小 | 要处理什么 |
|---|---|---|
| `hardnested_bf_core.c` | 33 KB | `pm3/ui.h` 只为 `PrintAndLogEx` → 写替身；`Windows.h`；`SetSIMDInstr()` 的 x86 SIMD 选择在 RISC-V 上退化为 NOSIMD |
| `hardnested_bitarray_core.c` | 31 KB | `__popcnt64`（x86 内建）；**还提供 `malloc_bitarray`/`free_bitarray`，所以编排层要用它** |
| `hardnested_bruteforce.c` | 19 KB | 3 处 pthread → 单线程；`Windows.h`/`share.h`/`io.h`/`libfmemopen` 换成标准 C |
| 三个 .h + `cmdhfmfhard.h` | ~11 KB | `statelist_t` / `noncelist_t` 等类型定义 |
| `tables.c` + liblzma | 4.83 MB 源码（**实为 0.75 MiB XZ 数据**） | **候选生成要用**，见下 |
| `cmdhfmfhard.c` | 85 KB | 33 处 pthread 是壳，但里面**还有算法**，见下 |
| `hardnested_benchmark_data.h` | 507 KB | 只服务 `brute_force_benchmark()`，本移植不需要（不移植该函数即可） |

### 6.1 为什么 hardnested 的破解**不该**在板子上跑（实测，不是估计）

前面那句"83 KB"只是**源码体量**，与"能不能在板子上跑"是两件事。量完之后是这样：

| 量什么 | 结果 | 怎么量的 |
|---|---|---|
| `tables.c` 源码 | 5,060,449 B → 里面其实是 **351 个 XZ 块，共 0.75 MiB 数据** | `tools/measure_hardnested_tables.py` 逐个解压 |
| 解压后的表 | **702 MiB**（每块恒定 2 MiB = 2²⁴ 位图） | 同上 |
| 通过上游 `IGNORE_BITFLIP_THRESHOLD`（count/2²⁴ < 0.99）保留的 | 偶态 145 + 奇态 92 = **237 块** | 同上 |
| `bitflip_bitarrays[2][0x400]` 常驻 | **237 × 2 MiB = 474 MiB** | `cmdhfmfhard.c:266` 每块 `malloc_bitarray(4·2¹⁹)`，全部保留 |
| `nonces[256].states_bitarray[2]` | **256 × 2 × 2 MiB = 1 GiB** | `cmdhfmfhard.c:522/529` 无条件给 256 个首字节各分两张 2 MiB 位图 |
| `malloc_bitarray` 是不是"虚拟分配障眼法" | **不是**：`MALLOC_BITARRAY` 就是 `memalign(__BIGGEST_ALIGNMENT__, x)` | `hardnested_bitarray_core.c:194` |
| 板子可用 PSRAM | **32 MB**（实际可用约 28 MB） | Tab5 硬件 |

**合计约 1.5 GB 常驻，是板子 PSRAM 的 47 倍。**
这不是"慢慢跑也能跑"的问题：那是**工作集**，不是可换出的缓存，
减少非子集任何一块都会改变算法结果。要在这块板子上做 ciphertext-only 攻击，
必须把"2²⁴ 位位图"整套数据结构换成稀疏/流式实现 —— 那是**重新实现**，不是移植。

顺带一个反直觉的发现：那 5 MB 的 `tables.c` **在 flash 里只值 0.75 MiB**
（源码是十六进制文本，一个字节 6 个字符）。所以体积从来不是障碍，
**内存**才是。

### 6.2 上游其实是三段式，客户端那一半才是本项目该搬的

```
1. 设备采集   DATA_CMD_MF1_HARDNESTED_ACQUIRE (2013)
              → mf1_toolbox.c mf1_hardnested_nonces_acquire()
              每 2 个 nonce 输出 9 字节：nt_enc1(4 BE) nt_enc2(4 BE) par_packed(1)
2. 客户端     chameleon_cli_unit.py HFMFHardNested.recover_key()
              扫描取 UID → 反复采集 → 跟踪 256 个首字节与奇偶和
              → 写 nonce 文件（UID(4 BE) block type + 9 字节记录…）
3. PC 破解     software/src/HardnestedRecovery/（自己的 Makefile，-llzma -lpthread）
              客户端只解析它输出的 "Key found: …" 再用卡复核
```

**第 3 步本来就不在客户端里**。所以本项目的正确做法是：把 1、2 两步做在 Tab5 上
（这是唯一必须贴着卡做的部分），产出的 nonce 文件交给 PC 上的上游工具。
Tab5 侧的实现在 `firmware/main/hardnested_acquire.{h,cpp}`（纯 C++、无 ESP 依赖，
所以能在主机上和上游对拍）+ `app_context.cpp` 的 `runHardNested()`，
界面在 Keys 页（`acquire hardnested nonces` / `fast|slow` / `export nonces`）。

**参数照抄 CLI，不凭印象写**：`--max-runs` 默认 200、`--max-attempts` 默认 3、
`--slow` 默认关、19 个合法 `Sum(a8)` 值取自 `cmdhfmfhard.c:65` 的 `sums[]`，
probe 会把这三处（移植表 / `sums[]` / `hardnested_utils.hardnested_sums`）逐项比对。

**导出为什么走串口而不是存 SD**：nonce 文件最终要给 PC 上的工具用，
而 Tab5 到 PC 之间唯一现成的通道就是 USB-Serial/JTAG 控制台。所以导出把文件打成
`[HN] BEGIN SZ=… REC=…` / `[HN] <offset> <hex>` / `[HN] END SZ=… CRC=…`
三种行（每行 16 字节，42 字符，稳稳落在 96 字符的日志行内），
`tools/nonce_file_from_console.py` 从抓到的控制台日志里还原 .bin 并**校验大小与 CRC32**。
丢了行、混进别的输出都会直接报错，而不是安静地产出一个破解不出东西的文件。

### 6.3 `hardnested_bf_core.c` / `hardnested_bruteforce.c`：搬了，但有意不链接

这两个 core（`src/hardnested/`）的移植状态是**能编译成 esp32p4 目标**：

- `hardnested_compat.h` 补上它们期望 pm3 提供的 6 个符号
  （`PrintAndLogEx` / `hardnested_print_progress` / `msclock` / `num_CPUs` / `fmemopen` /
  `logLevel_t` + `BSWAP_32` / `MIN` / `MAX` / `_GREEN_` 等），值是**从上游文件抄的**，
  不是凭记忆写的：`logLevel_t` 按 `pm3/ui.h:32` 的枚举顺序，
  颜色宏按 `pm3/ansi.h:24-28`，`memalign` 映射到 `heap_caps_aligned_alloc(..., MALLOC_CAP_SPIRAM)`。
- `num_CPUs()` 返回 **1**：上游启 `num_CPUs()` 个 pthread，本移植把那圈
  `pthread_create`/`pthread_join` 换成同一份 `thread_args` 上的直接调用，
  桶步长仍是 `NUM_BRUTE_FORCE_THREADS`，所以行为与**单线程版上游**逐位一致。
- `brute_force_benchmark()` 与 `read_bench_data()` 一并去掉：
  它们是 507 KB `hardnested_benchmark_data.h` 的唯一用户，而板子上没有任何调用者
  （上游唯一调用者是 `cmdhfmfhard.c`）。函数仍在头文件里声明 ——
  以后真加了调用点会**链接失败**，而不是悄悄返回一个编出来的速率。
- `hardnested_bitarray_core.c` 没有移植，因为只剩 popcount 路径用它，
  而本移植没走那条路（`malloc_bitarray` 由 `cmdhfmfhard.c` 用，而那一层没搬）。

**为什么不链接**：`crack_states_bitsliced()` 需要候选状态集，而候选集来自
6.1 里那 1.5 GB 的候选生成阶段。没有前半段，这个 core 在板子上**没有任何可达调用者**。
`--gc-sections` 因此把它们整个丢掉，map 里查不到 `crack_states_bitsliced`
（`nested.cpp` 当年因为同样原因被丢掉过，接上界面后才出现 `0x4805d088`）。
留在 `SRCS` 里是有意的：**代码继续跟着编译器走**，腐烂会被构建发现，而 flash 不花一个字节。

对外入口（已确认）：

```c
uint64_t crack_states_bitsliced(uint32_t cuid, uint8_t *best_first_bytes, statelist_t *p,
                                uint32_t *keys_found, uint64_t *num_keys_tested,
                                uint32_t nonces_to_bruteforce, uint8_t *bf_test_nonce_2nd_byte,
                                noncelist_t *nonces);
bool brute_force_bs(float *bf_rate, statelist_t *candidates, uint32_t cuid,
                    uint32_t num_acquired_nonces, uint64_t maximum_states,
                    noncelist_t *nonces, uint8_t *best_first_bytes, uint64_t *found_key);
void prepare_bf_test_nonces(noncelist_t *nonces, uint8_t best_first_byte);
bool verify_key(uint32_t cuid, noncelist_t *nonces, const uint8_t *best_first_bytes,
                uint32_t odd, uint32_t even);
```

验证路径依然成立：MinGW 同时有 `Windows.h`、`intrin.h`、`__popcnt64` 和 pthread，
所以能把**上游 core 原版**编出来对拍 —— 和 darkside / nested 用的是同一套做法。

**已经实测过（不是推断）**：三个 core 在主机上**原样编译通过，不需要任何替身**：

```
OK   hardnested_bf_core        7,533 bytes
OK   hardnested_bitarray_core  8,015 bytes
OK   hardnested_bruteforce    87,398 bytes
```

也就是说**对拍用的 oracle 已经现成了**。而 `nm --undefined-only` 列出的
"非 libc 未定义符号"就是移植要补的全部东西，一共 6 项：

| 符号 | 上游来源 | 替身代价 |
|---|---|---|
| `PrintAndLogEx` | `pm3/ui.c` | 几行，转发到 `ESP_LOGI` |
| `hardnested_print_progress` | `pm3/ui.c` | 几行，转发到进度回调 |
| `msclock` | `pm3/util.c` | 一行 `esp_timer_get_time()/1000` |
| `num_CPUs` | `pm3/util.c` | 常量 1（单线程） |
| `fmemopen` | `compat/fmemopen` | 空实现即可（只有 benchmark 路径用） |
| `pthread_create` / `pthread_join` | `bruteforce.c` 3 处 | 改单线程，同 nested 的做法 |

其余都是**本项目已有的**（`crypto1_byte` / `crypto1_get_lfsr` / `lfsr_rollback_byte`
在已移植并验证过的 `crypto1.c` / `crapto1.c` 里），或者三个 core 之间的互相引用
（`crack_states_bitsliced` / `bitslice_test_nonces` / `trailing_zeros` / `verify_key`）。

判断：**可以做**，工作量比预估的还小（83 KB 源码 + 6 个替身函数），
且 oracle 与验证方法都已就位。**注意这只是"core 能编"**——
它能不能被调用取决于 6.1 里那 1.5 GB 的候选生成，见 6.1 的结论。

### 6.4 客户端半边的对拍（`tools/verify_hardnested_acquire.py`）

这是 hardnested 唯一**能**在板子上跑的那一半，所以对它的要求不是"看起来对"，
而是每一项都拿上游代码当判据：

| 检查 | 判据（上游的哪段代码） |
|---|---|
| 19 个合法 `Sum(a8)` 值 | 三处比对：移植表 / `cmdhfmfhard.c:65` 的 `sums[]` / **直接 import 的** `hardnested_utils.hardnested_sums`，再比对**编译出来的**表；个数对照 `hardnested_bruteforce.h:23` 的 `NUM_SUMS` |
| 首字节跟踪（256 个首字节 + 奇偶和 + 合法性） | **`hardnested_utils.check_nonce_unique_sum` 原函数**，5 组用例（满 256、重复首字节、单条、空、256+重复），另含"末尾半条记录要被丢掉"（设备确实会给出奇数个 nonce，`mf1_toolbox.c:1169`） |
| 记录数 | `len(raw) // 9`，即 CLI 的算法 |
| CRC32 | `binascii.crc32`（0/1/5/6/100/4096 字节） |
| **nonce 文件格式** | **上游 `HardnestedRecovery/hardnested_main.c` 原文编译**（只把 `mfnestedhard()` 换成打印参数的桩），喂进本移植写的 .bin，比对它读出的 UID / sector / key type，以及它转交给求解器的**每一个 nonce 与奇偶位** |
| 导出 → 还原 | 导出文本 → `tools/nonce_file_from_console.py` → **逐字节相同**；再用移植自己的行解析器还原一遍，同样逐字节相同 |
| 容量边界 | 7281 条记录（65535 B，能表示的最大值）通过、7282 条被拒 —— 数据行的 offset 是 4 位十六进制，这是硬边界 |
| 坏抓包必须被拒 | 删掉一行 → 解码器报 CRC 不匹配并退出非 0；完全没有标记 → 报找不到 BEGIN |

对拍当场抓到两个**真 bug**（都已修，都是"看起来显然"的那种）：

1. **导出行长差一个字节**：`kExportLineLength` 少算了 offset 后的那个空格，
   于是 NUL 写在缓冲区外 —— `printf` 顺着读到下一行，导出的"行"变成 7 KB。
   probe 里"每行必须放得进 96 字符日志行"那条检查就是冲这个来的。
2. **行解析器只认行首标记**：`ParseExportDataLine()` 原本要求 `[HN]` 在 index 0，
   但设备上这些行要过 `ESP_LOGI`，前缀是时间戳和 tag，真实控制台里**永远不在行首**。
   Python 解码器用的是 `re.search`（能中），C++ 这边用的是 `strncmp`（不能中），
   两边就此分叉 —— probe 故意用带前缀的形式喂两个解码器，就是为了让这种分叉无处可藏。

### 对拍脚手架：oracle 已经能跑

`tools/host_stubs/pm3_shim.c` 提供那 6 个符号（**注意这是主机侧替身，不是移植本身**——
主机替身和 ESP-IDF 侧的替身分开写，才能保证对拍的是移植代码而不是替身）。
链接配方（已实测通过）：

```powershell
gcc -w -O1 -pthread `
  -I <HardnestedRecovery> -I <HardnestedRecovery>\hardnested -I <HardnestedRecovery>\pm3 `
  -I <software/src> -I <HardnestedRecovery>\..\compat\fmemopen `
  harness.c hardnested_bf_core.o hardnested_bitarray_core.o hardnested_bruteforce.o `
  crapto1.c crypto1.c parity.c bucketsort.c tools/host_stubs/pm3_shim.c -o oracle.exe
```

结果：

```
hardnested oracle linked: crack_states_bitsliced=00007ff7bdab288f  brute_force_bs=00007ff7bdab3607
exit=0
```

也就是说**上游 hardnested 的三块 core + 6 个替身 = 一个可执行的 oracle**，
接下来的移植可以逐单元与它比对（先 `crack_states_bitsliced()`，
再 `brute_force_bs()`），和 darkside / nested 一路用的是同一套方法。

`SetSIMDInstr(SIMD_AVX2)` 在主机上可用；RISC-V 侧需要在数据量或指令选择上退化，
这部分届时单独验证。

### nested / staticnested 现在的状态

- **`NestedRecover()`**（= 官方 `nested()`）：已移植并验证候选密钥集合逐个相同
- **`StaticNestedDerive()` / `StaticNestedRecover()`**（= 官方 `staticnested.c`）：
  派生逻辑对照参考 `prng_next` 验证通过，搜索部分直接复用 `NestedRecover()`
- **`NestedDerive()` / `NestedRecoverFromAcquire()`**（= 官方 `nested.c` 的参数处理）：
  每个采集三元组在 `dist-14 .. dist+14` 共 29 个 PRNG 位置上试探，
  用 `valid_nonce()` 过滤。同样对照参考 `prng_next` + Python 版谓词验证通过
  （dist=160 得 9 对、dist=361 得 15 对，逐对一致）
- 参数映射取自 CLI：
  - 静态：`staticnested.exe <uid> <type> <nt> <nt_enc> ...`（原样传）
  - 普通：`nested.exe <uid> <dist> <nt> <nt_enc> <par> ...`
  - 走哪条由 `MF1_DETECT_PRNG` 决定：0=staticnested、1=nested、2=hardnested
- **已接到 Keys 页**：新增 `nested attack` 按钮 + `KeyJob::Nested` 任务，
  流程照 CLI 的 `recover_a_key()`：`MF1_DETECT_PRNG` 决定攻击方式 →
  对应的 acquire 采集 → Tab5 本地破解 → **每个候选都用 `MF1_AUTH_ONE_KEY_BLOCK` 让卡确认**。
  已知侧用「本页上次确认过的密钥」（工厂密钥检查或 darkside 的结果），
  目标侧用页面上选的 block / key type。
  卡片需要 hardnested（`nt_level == 2`）时**明说"这张卡得走 hardnested"并指向采集按钮**，
  不假装能嵌套出来 —— 硬化 PRNG 的卡本来就不吃普通 nested。
- **hardnested 的采集也接在同一个页面**：`acquire hardnested nonces` +
  `fast|slow` 开关 + `export nonces`（`KeyJob::HardNested`，实现见 6.2）。
  同一个已知密钥、同一个目标 block/type，与 nested 共用界面。

> `NestedRecover` 之前因为没有任何调用者，一直被 `--gc-sections` 丢掉（map 里查不到）。
> 接上界面后 map 里已经出现实体地址 `0x4805d088` —— **这也算是"它真的被编译进固件了"的验证**。

- **`NestedDerive()` / `NestedRecoverFromAcquire()`**（= 官方 `nested.c` 的参数处理）：
  每个采集三元组在 `dist-14 .. dist+14` 共 29 个 PRNG 位置上试探，
  用 `valid_nonce()` 过滤。同样对照参考 `prng_next` + Python 版谓词验证通过
  （dist=160 得 9 对、dist=361 得 15 对，逐对一致）
- 参数映射取自 CLI：静态 `staticnested.exe <uid> <type> <nt> <nt_enc> ...`（原样传）；
  普通 `nested.exe <uid> <dist> <nt> <nt_enc> <par> ...`；
  走哪条由 `MF1_DETECT_PRNG` 决定（0=staticnested、1=nested、2=hardnested）
- **hardnested 不在这条路上**：`nt_level == 2` 时普通 nested 必然失败，
  界面会指向同页的 `acquire hardnested nonces`（客户端半边见 6.2，
  破解核心为什么不在板子上见 6.1）

剩下的范围：收集循环里的四件事 —— `lfsr_rollback_word()`、`crypto1_get_lfsr()`、
`heap_caps_realloc()` 增长、`keys[kcount] = lfsr`。
`walk` 与 `recover` 唯一的差别就是这四件，所以下一个探针应当**在循环内**打点
（例如每 10000 次迭代打一条），定位到具体第几次迭代。

> （这一节写于崩溃未解决时。崩溃的根因最终查明**在 harness 里**，
> 见上面「崩溃的真正原因」；这些推导保留下来是因为它们排掉的假设都是对的。）

### 排查过程中差点被骗两次（值得单独记）

`probe_nested.py` 其实有**两轮根本没编译成功**，而当时我的结论是"跑了但没输出"。
两个原因叠在一起：

1. `subprocess` 默认用**本机 locale（GBK）** 解码编译器输出。一个非法字节就让
   reader 线程抛 `UnicodeDecodeError`、`stderr` 变成 `None`，真正的编译错误被替换成
   一个 `TypeError`（"NoneType is not subscriptable"）。
2. 修好解码后看到的是**一屏空白** —— GCC 的诊断用长串空格 + `^~~~` 对齐，
   而我只打印了 `[-2500:]` 尾部，正好截在空白里。

第三个坑在修好之后：`-x c` 会**持续到命令行末尾**，所以把 `host_alloc_tracker.o`
当成了 C 源码去编（`stray '\206' in program`）；补上 `-x none` 才对。
而单独编译 tracker 又必须**显式 `-x c`**，否则 g++ 按 C++ 编、符号被 mangle，
harness 那边 `extern "C"` 的声明就找不到定义。

> **教训：探针报"没有输出"时，先确认它真的编译并运行了** ——
> 检查二进制时间戳、检查探针字符串是否真的在二进制里。
> 这一轮里"先确认实验执行了"这一步的价值，比实验本身还大。
> 免得下一轮（或下一个人）重复同样的推导。

**下一步的具体做法**：MinGW 下 `-fsanitize=address` 可用性没确认（手工编译时把 C 源误当 C++ 编了，没得出结论），
更稳妥的是给 `NestedRecover` 加分段进度输出（收集完 / 排序完 / 输出完各打一条），
把范围压到具体某一段；或者先写一个只做"收集 + 计数"的最小 harness，逐个加入 `uniqSort` 与输出段。

---

> 与其给一个"两边都是空集所以通过"的绿灯，不如让测试红着。
> 本项目已经栽过两次"未验证的代码看起来没问题"（T55xx 密码常量、桶遍历顺序）。

### 修好它需要什么

1. 查清 `0xC0000374`：在收集循环**内部**打点（每 10000 次迭代一条），
   看是第一次迭代就崩（→ `lfsr_rollback_word`/`crypto1_get_lfsr` 这条路径，
   `walk` 从没调用过它们），还是崩在某次 `realloc` 之后（→ 增长逻辑）。
2. 造出真实形态的 nonce：要么用真卡（一张 Classic + 一个已知密钥的扇区），
   要么先在 PC 上用官方 `nested.exe` 生成一组 `(ntp, ks1)` 作为固定测试向量 ——
   **后者不需要硬件**，是更快的路。

`staticnested.c` 的破解核心已经补上（见上），`hardnested` 的结论见 6.1：
**不是"还没搬"，是"不该在这块板子上跑"**。

---

## 7. 验证工具

```powershell
python tools/verify_crypto.py             # 原语 + 实时参考 + mfkey32 端到端 + 峰值内存
python tools/probe_mfkey32.py             # 与上游 crapto1.c 对拍（比恢复出的状态数）
python tools/probe_darkside.py            # 与上游 mfkey.c 对拍（比恢复出的密钥列表）
python tools/verify_darkside_search.py    # 跑 DarksideSearch::Feed 本体（交集/所有权/泄漏）
python tools/verify_sniff_decoder.py      # 轨迹解码器（参考 crypto1.py 造的合成认证）
python tools/probe_nested.py              # nested 对拍（候选密钥集合逐个相同）
python tools/verify_hardnested_acquire.py # hardnested 客户端半边（见 6.4）
python tools/measure_hardnested_tables.py # 量 hardnested 的表到底要多少内存（见 6.1）
```

**用户侧的 hardnested 流程**（抓包那一环也在这个目录里）：

```powershell
# 1. Tab5 上：Keys 页 → acquire hardnested nonces → export nonces
python tools/capture_console.py --seconds 90 > capture.txt
# 2. 还原 nonce 文件（会校验 SZ 与 CRC32，坏抓包直接报错）
python tools/nonce_file_from_console.py capture.txt -o nonces.bin
# 3. 在 PC 上跑上游的求解器（HardnestedRecovery 自己的 Makefile，需要 liblzma）
HardnestedRecovery/hardnested_main nonces.bin
# 4. 拿到的密钥回 Tab5 的 Cards/Keys 页面用
```

这些工具都把**真实的 C 源文件**编成本机程序运行，把上游实现当判定基准，
不使用手抄的期望值（这是协议层踩过的坑）。

`verify_darkside_search.py` 存在的理由：`darkside.cpp` 是**手写**的（不像 `crapto1.c`
有上游原件可以逐行对照），所以必须真的执行它。第一次跑就抓到"每次没找到密钥泄漏
1.7 MB"——60 轮上限会在第 14 轮耗尽 24 MB PSRAM。详见 `docs/PORTING-NOTES.md` 第 15 条。

**没验证的部分要说清楚**：上面几条都是"与上游一致"或"内存行为正确"的证明，
不是"在真卡上能出密钥"的证明。darkside 的 `par != 0` 分支在 probe 里只走了空结果路径 ——
一致的 `par` 向量必须来自真实卡片（40 个奇偶约束，随机位几乎不可能满足），
probe 会把这一点明确打印出来而不是假装通过。
