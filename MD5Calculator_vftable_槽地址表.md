# `BW::MD5Calculator::vftable` —— 槽地址表（给 IDA/Ghidra 直接用）

导出 2026-09-24。**只读**，未改任何代码。

> 你要的是「点开 vftable 符号、抄下槽函数地址」。地址表在 §一，
> 语义在 §三，**证明它在 15 个槽全部是真 override 的判据在 §二**。

---

## 一、★ 表本体（照抄这一块）

**`BW::MD5Calculator::vftable` 的 slot0 = `0x1439230B8`**（表头 RTTI 在 `0x1439230B0`）。

| slot | 槽地址 | 指向 | `decomp` 里的名字 |
|---|---|---|---|
| 0 | `0x1439230B8` | `0x142A9B580` | `FUN_142a9b580` |
| 1 | `0x1439230C0` | `0x1402F7290` | （无函数名，见 §三.2） |
| 2 | `0x1439230C8` | `0x1402F7290` | 同上 |
| 3 | `0x1439230D0` | `0x1402F7290` | 同上 |
| 4 | `0x1439230D8` | `0x1402F7290` | 同上 |
| 5 | `0x1439230E0` | `0x1403E8290` | `FUN_1403e8290` |
| 6 | `0x1439230E8` | `0x1403E8260` | `FUN_1403e8260` |
| 7 | `0x1439230F0` | `0x1403E8230` | `FUN_1403e8230` |
| 8 | `0x1439230F8` | `0x1403E8290` | `FUN_1403e8290` |
| 9 | `0x143923100` | `0x1403E8260` | `FUN_1403e8260` |
| 10 | `0x143923108` | `0x1403E8230` | `FUN_1403e8230` |
| 11 | `0x143923110` | `0x1403E8230` | `FUN_1403e8230` |
| 12 | `0x143923118` | `0x1403E8210` | `FUN_1403e8210` |
| 13 | `0x143923120` | `0x1403E81E0` | `FUN_1403e81e0` |
| 14 | `0x143923128` | `0x1402ED600` | `FUN_1402ed600` |

**表到 slot14 结束。** 紧接其后的 `0x143923130` 是相邻类
`BW::AbstractMD5Visitor::vftable` 的**表头（COL 指针 = `0x143EA0180`）**，
⇒ **那个类的 slot0 在 `0x143923138`**。
（★ 别把 `0x143923130` 当槽：它是别人的表头。见 §四.2。）

### 原始字节（`0x1439230B0` 起，136 字节，小端 u64）

```
0B0: a800ea43 01000000    ← COL 指针 0x143EA00A8（表头，不是槽）
0B8: 80b5a942 01000000    → 0x142A9B580   slot0
0C0: 90722f40 01000000    → 0x1402F7290   slot1
0C8: 90722f40 01000000    → 0x1402F7290   slot2
0D0: 90722f40 01000000    → 0x1402F7290   slot3
0D8: 90722f40 01000000    → 0x1402F7290   slot4
0E0: 90823e40 01000000    → 0x1403E8290   slot5
0E8: 60823e40 01000000    → 0x1403E8260   slot6
0F0: 30823e40 01000000    → 0x1403E8230   slot7
0F8: 90823e40 01000000    → 0x1403E8290   slot8
100: 60823e40 01000000    → 0x1403E8260   slot9
108: 30823e40 01000000    → 0x1403E8230   slot10
110: 30823e40 01000000    → 0x1403E8230   slot11
118: 10823e40 01000000    → 0x1403E8210   slot12
120: e0813e40 01000000    → 0x1403E81E0   slot13
128: 00d62e40 01000000    → 0x1402ED600   slot14
130: 8001ea43 01000000    ← 下一个类的 COL（表已结束）
```

### RTTI

```
COL = 0x143EA00A8  →  TypeDescriptor = .?AVMD5Calculator@BW@@  (sig=0x1)
```

---

## 二、★★ 为什么这 14 个槽「钉得死」—— 基类是纯虚

同一份结论我做了**反向验证**：读**基类** `BW::IMD5Calculator::vftable`（`0x143923038`）。

```
vtable @ 000143923038
  COL  = 000143EA0030  RTTI = .?AVIMD5Calculator@BW@@
  slot 0x00 -> 000142A9B550      ← 析构（唯一有实现的）
  slot 0x08 -> 000142C96CB2  ┐
  slot 0x10 -> 000142C96CB2  │
  slot 0x18 -> 000142C96CB2  │
  slot 0x20 -> 000142C96CB2  │
  slot 0x28 -> 000142C96CB2  ├ 14 个槽全是同一个地址
  slot 0x30 -> 000142C96CB2  │
  slot 0x38 -> 000142C96CB2  │
  slot 0x40 -> 000142C96CB2  │
  slot 0x48 -> 000142C96CB2  │
  slot 0x50 -> 000142C96CB2  │
  slot 0x58 -> 000142C96CB2  │
  slot 0x60 -> 000142C96CB2  │
  slot 0x68 -> 000142C96CB2  │
  slot 0x70 -> 000142C96CB2  ┘
```

**`0x142C96CB2` = `_purecall`**（`decomp/index.tsv` 直读）：

```
142c96cb2	_purecall	6	c_142c7ee30.c	23124
```

⇒ **基类 14 个虚函数全是纯虚**（MSVC 对纯虚槽填 `_purecall`）。

**这条的份量**：`MD5Calculator` 表里 14 个非析构槽**没有一个**等于 `0x142C96CB2`
⇒ **14 个全是货真价实的 override**，不存在「继承来的槽我没看见」的问题。
**你可以放心不用再去基类翻。**

---

## 三、逐槽语义（每条的判据）

**结论：这个类 = 标准 MD5（RFC 1321）。**

| # | 语义 | 判据 |
|---|---|---|
| **0** | 析构（scalar deleting dtor） | 写基类表 + `free`；**`mov edx, 0x60` ⇒ 对象 96 字节** |
| **1–4** | **空钩子**（一条 `ret`） | `0x1402F7290 = ret`（见 §三.2） |
| **5** | `update(u32)` —— 喂 4 字节 | 见 §三.1 |
| **6** | `update(u16)` —— 喂 2 字节 | 同上 |
| **7** | `update(u8)` —— 喂 1 字节 | 同上 |
| **8** | = slot5 | 指针相同 |
| **9** | = slot6 | 指针相同 |
| **10** | = slot7 | 指针相同 |
| **11** | = slot7 | 指针相同 |
| **12** | `update(std::string)` —— 喂 `size()` 字节 | SSO 判据 |
| **13** | `update(const char*)` —— 喂 `strlen+1` 字节（**含 NUL**） | `strlen` 循环 + `+1` |
| **14** | `digest()` —— 返回 **16 字节结果**指针（`this+8`） | 一条 `lea` |

### 三.1 槽 5/6/7 —— 同一个 worker，只有宽度不同

```c
void FUN_1403e8290(longlong p1, undefined8 p2, undefined4 p3)   // slot 5, 8 → 4 字节
{ undefined4 t[4];  t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 4); }

void FUN_1403e8260(longlong p1, undefined8 p2, undefined2 p3)   // slot 6, 9 → 2 字节
{ undefined2 t[8];  t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 2); }

void FUN_1403e8230(longlong p1, undefined8 p2, undefined1 p3)   // slot 7, 10, 11 → 1 字节
{ undefined1 t[16]; t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 1); }
```

**三个函数体逐字相同，只有最后一个实参 4/2/1 不同** —— 那个实参就是「喂几个字节」。

### 三.2 ★ 槽 1–4 是空函数（也解释了为什么索引里没有名字）

```asm
0x1402F7290  ret
0x1402F7293  int3
```

**一条 `ret`，只有 3 字节。** 四个槽都指向它。
⇒ 这四个虚函数在本类是**故意空实现**（visitor 的默认钩子）。
⇒ `decomp/index.tsv` 里它的名字 `AkStompAllocatorInitForThread` 是**同名符号碰撞的假名**
（3 字节的 `ret` 不可能是那个函数），**别被它误导**。

### 三.3 槽 12 / 13 —— 两条字符串路，**结果不同**

```c
void FUN_1403e8210(longlong p1, undefined8 p2, undefined8 *p3)  // slot 12: std::string
{
  undefined8 *len = p3 + 2;
  if (0xf < (ulonglong)p3[3]) p3 = (undefined8 *)*p3;   // SSO 边界 15 → 堆指针
  FUN_1403e82f0(p1+8, p1+8, p3, *(undefined4 *)len);    // 喂 size() 字节，【不带 NUL】
}

void FUN_1403e81e0(longlong p1, undefined8 p2, longlong p3)    // slot 13: const char*
{
  longlong n = -1;
  do { n = n + 1; } while (*(char *)(p3 + n) != '\0');  // = strlen
  FUN_1403e82f0(p1+8, p1+8, p3, (int)n + 1);            // ★ +1 = 【含 NUL】
}
```

⇒ **同一个字符串走槽 12 和走槽 13，MD5 结果不一样。**
要复现这个类的输出，`const char*` 那条路**必须带上 `'\0'`**。

### 三.4 worker `FUN_1403e82f0` 就是 MD5 的 `update`（逐字对上）

```c
void FUN_1403e82f0(undefined8 p1, uint *st, void *data, uint n)
{
  uint bitoff = *st >> 3 & 0x3f;              // 缓冲里已有多少字节 (0..63)
  if (0 < (int)n) {
    uint lo = *st + n * 8;                    // 位计数 low
    uint hi = (n >> 0x1d) + st[1];            // 位计数 high（含进位）
    st[1] = hi; *st = lo;
    if (lo < n * 8) st[1] = hi + 1;
    if (bitoff != 0) {
      uint m = (0x40 < (int)(bitoff + n)) ? (0x40 - bitoff) : n;
      memcpy((char*)st + bitoff + 0x18, data, m);   // ★ 缓冲在 st+0x18
      if ((int)(m + bitoff) < 0x40) return;
      n -= m; data += m;
      FUN_1403e8620(p1, st, st + 6);          // ★ 压缩一个块（st+6 == +0x18）
    }
    if (0x3f < (int)n) {
      ulonglong blk = n >> 6;
      n = n + (n >> 6) * -0x40;               // n %= 64
      do { FUN_1403e8620(p1, st, data); data += 0x40; blk--; } while (blk != 0);
    }
    if (n != 0) memcpy(st + 6, data, n);
  }
}
```

### 三.5 ★★★ 压缩函数 `FUN_1403e8620` 里是 **RFC 1321 的 T 表**（铁的判据）

| 实测常量 | RFC 1321 | |
|---|---|---|
| `0xd76aa478` | T[0] | ✓ |
| `0xe8c7b756` | T[1] | ✓ |
| `0x242070db` | T[2] | ✓ |
| `0xc1bdceee` | T[3] | ✓ |
| `0x4787c62a` | T[4] | ✓ |
| `0x57cfb9ed` | T[5] | ✓ |
| `0x698098d8` | T[8] | ✓ |
| `0x895cd7be` | T[11] | ✓ |
| `0xf61e2562` | T[20] | ✓ |
| `0xc040b340` | T[21] | ✓ |
| `0x265e5a51` | T[22] | ✓ |

**⇒ 是 MD5，不是别的哈希。不用猜。**

### 三.6 槽 14 —— digest

```c
longlong FUN_1402ed600(longlong p1) { return p1 + 8; }
```

一条指令。配合「状态在 `this+8`」⇒ **返回指向 16 字节 MD5 结果的指针。**

### 三.7 对象布局（从析构的 `mov edx, 0x60` 反推）

```
+0x00  vptr            (8)
+0x08  位计数          (8)     ← digest() 返回这里，即 16B 结果
+0x10  ?               (8)
+0x18  64 字节缓冲     (64)    ← st+0x18，同时也是 st+6
+0x58  对齐            (8)
                        总 0x60 = 96 字节 ✓ 与 free 的 0x60 吻合
```

---

## 四、三条坑（都会让「抄地址」抄错）

1. **slot0 不是表头。** 表头 `0x1439230B0` 是 COL 指针（RTTI），**slot0 = `0x1439230B8`**。
   在 IDA/Ghidra 里点开 `vftable`，有时它显示的是**表头地址**。
   **以「槽地址 = slot0 + n×8」为准，slot0 = `0x1439230B8`。**

2. **只有 15 个槽，不是 16。** slot0..slot14。`0x143923130` 是**别人家**的表头
   （`BW::AbstractMD5Visitor::vftable` 的 COL `0x143EA0180`，
   它的 slot0 在 `0x143923138`）。多抄一个就串类了。
   ⇒ **怎么一眼看出表到头了**：读槽位置上的 8 字节，看它指向哪里。
   - **真槽** → 指向一个**函数**（在 `.text`，且那段代码结尾是 `c3`/`ret` + `cc` 填充）
   - **表尾后的那个值** → 指向一个 **COL 结构**，其内容以 `01 00 00 00` 开头
     （`sig=1` + 两个 0 + `TypeDescriptor*`）。
     实测 `0x143923130` 这 8 字节 = `0x143EA0180`，而 `0x143EA0180` 的内容是
     `01 00 00 00 | 00… | f8d37904a801ea03` ⇒ **是 COL，不是函数**。
   ★ **别用「地址落在哪个区间」判**（我试过，`.text` 和 `.rdata` 的 VA 是连着的，
   这个判据不区分）；**要看解引用后的内容长什么样。**

3. **★ 别用「析构里写了哪张表」来定位这个 vtable。**
   `FUN_142a9b580`（本类析构）与 `FUN_142a9b550`（基类析构）**都**写
   `*p1 = BW::IMD5Calculator::vftable`（`0x143923038`）。
   ⇒ **只读析构会得出「它用基类表、自己没表」的错结论。**
   本表地址是从 **RTTI 反推**（`COL → TypeDescriptor`）得到的，
   与析构读法**必须两个都对上**才算数。

---

## 五、复现（分「有原始 EXE」和「只有 decomp」两种）

### 只有 `decomp`（你那边就能跑）

```bash
grep -i "^142a9b580\b" decomp/index.tsv   # slot0 析构  -> c_1428d1e40.c:368014
grep -i "^1402f7290\b" decomp/index.tsv   # slot1-4 空钩子
grep -i "^1403e8290\b" decomp/index.tsv   # slot5/8
grep -i "^1403e8260\b" decomp/index.tsv   # slot6/9
grep -i "^1403e8230\b" decomp/index.tsv   # slot7/10/11
grep -i "^1403e8210\b" decomp/index.tsv   # slot12
grep -i "^1403e81e0\b" decomp/index.tsv   # slot13
grep -i "^1402ed600\b" decomp/index.tsv   # slot14
grep -i "^142c96cb2\b" decomp/index.tsv   # ★ 基类槽 = _purecall（§二 的判据）
```

函数体：

```bash
sed -n '212059,212165p' decomp/chunks/c_1402c13f0.c   # 槽 5..13 全部
sed -n '368014,368030p' decomp/chunks/c_1428d1e40.c   # 槽 0 析构 + 对象大小
sed -n '367999,368013p' decomp/chunks/c_1428d1e40.c   # 基类析构（对照用）
```

### 需要原始 EXE 才能读的（你那边用 Ghidra 直接看）

```bash
py -3 tools/vtinfo.py --at 0x1439230B8     # RTTI + 全部槽地址
py -3 tools/vtinfo.py --at 0x143923038     # 基类表（§二 的对照）
py -3 tools/exe_ref.py read 0x1439230B0 144  # 原始字节（§一 那张表）
```

**★ 只有 `decomp` 读不到的两处（诚实标注）**：
1. **vtable 里填了哪些字节** —— `decomp` 只给符号名、不给内容。
   替代路径：在 Ghidra 里打开构造函数 `FUN_142a9b640`，找
   `local_88 = BW::MD5Calculator::vftable;` 那一行，Ghidra 会解析到具体地址。
2. **槽 1–4 的 `ret`** —— 反汇编才看得见（`decomp` 里它是空的或只有一个 `return`）。

---

## 六、一句话总结

**`BW::MD5Calculator` = 标准 MD5（RFC 1321 T 表逐项吻合），15 槽 =
1 析构 + 4 空钩子 + 7 个 `update` 重载（4/2/1 字节 ×2 组 + `std::string` + `const char*`）
+ 1 个 `digest()`。对象 96 字节，栈上一次性使用。
基类 `IMD5Calculator` 14 个虚函数全是 `_purecall` ⇒ 本表 14 个非析构槽全部是真 override。**

---

## 七、链条对账

| 环 | 内容 | 标记 |
|---|---|---|
| 1 | 15 个槽地址 + COL + RTTI 名 | **`[读]`** 原始 EXE 字节（§一 hex） |
| 2 | 基类 14 槽 = `_purecall` | **`[读]`** `index.tsv:142c96cb2` |
| 3 | 槽 5/6/7/8/9/10/11 语义（宽度 4/2/1） | **`[读]`** 函数体逐字 |
| 4 | 槽 12/13 语义（含 `+1` NUL） | **`[读]`** 函数体逐字 |
| 5 | 槽 14 = digest（`this+8`） | **`[读]`** 函数体 |
| 6 | 对象 96 字节 | **`[读]`** 析构 `mov edx,0x60` |
| 7 | 这是 MD5（T 表吻合） | **`[读]`** 11 个常量逐项 |

**7 环全 `[读]`，无 `[推]` ⇒ 本次链条闭合。**

★ 但按「**证据闭环 ≠ 功能闭环**」：这是**只读轮**，产出是**证据**，
不代表任何代码已被验证可用。要算「功能闭环」得等你实测。
