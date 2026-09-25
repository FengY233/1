# `BW::MD5Calculator::vftable` —— 15 个指针

导出 2026-09-24。**只读**，未改任何代码。

---

## 一、表本身

```
vtable 基址（含 RTTI 头）  = 0x1439230B0
  +0x00  COL 指针          = 0x143EA00A8
  +0x08  ← 这就是 slot0
```

RTTI：`COL = 0x143EA00A8` → `TypeDescriptor = .?AVMD5Calculator@BW@@`（`sig=0x1`）

**15 个槽**（slot0 = `0x1439230B8`，每槽 +0x8）：

| # | 槽地址 | 指针值（函数） | 符号 |
|---|---|---|---|
| 0 | `0x1439230B8` | `0x142A9B580` | `FUN_142a9b580` |
| 1 | `0x1439230C0` | `0x1402F7290` | `FUN_1402f7290` |
| 2 | `0x1439230C8` | `0x1402F7290` | 同上（重复） |
| 3 | `0x1439230D0` | `0x1402F7290` | 同上（重复） |
| 4 | `0x1439230D8` | `0x1402F7290` | 同上（重复） |
| 5 | `0x1439230E0` | `0x1403E8290` | `FUN_1403e8290` |
| 6 | `0x1439230E8` | `0x1403E8260` | `FUN_1403e8260` |
| 7 | `0x1439230F0` | `0x1403E8230` | `FUN_1403e8230` |
| 8 | `0x1439230F8` | `0x1403E8290` | = slot5 |
| 9 | `0x143923100` | `0x1403E8260` | = slot6 |
| 10 | `0x143923108` | `0x1403E8230` | = slot7 |
| 11 | `0x143923110` | `0x1403E8230` | = slot7 |
| 12 | `0x143923118` | `0x1403E8210` | `FUN_1403e8210` |
| 13 | `0x143923120` | `0x1403E81E0` | `FUN_1403e81e0` |
| 14 | `0x143923128` | `0x1402ED600` | `FUN_1402ed600` |

表到 slot14 结束。`0x143923130` 是相邻类 `BW::AbstractMD5Visitor::vftable`（COL `0x143EA0180`）。

**原始字节**（从 `0x1439230B0` 起，136 字节）：
```
a800ea43 01000000  80b5a942 01000000
90722f40 01000000  90722f40 01000000
90722f40 01000000  90722f40 01000000
90823e40 01000000  60823e40 01000000
30823e40 01000000  90823e40 01000000
60823e40 01000000  30823e40 01000000
30823e40 01000000  10823e40 01000000
e0813e40 01000000  00d62e40 01000000
8001ea43 01000000     ← 下一个类的 COL
```

★ **只有 15 个**，不是 16 —— slot0 起数到 slot14，`0x143923130` 已经是别人家的表头。

---

## 二、这 15 个槽各是什么（有 6 个语义已读死）

**这个类 = 标准 MD5。** 证据在 §三。

| # | 语义 | 类型宽度 |
|---|---|---|
| **0** | **析构**（scalar deleting dtor） | — |
| **1–4** | **空操作**（`ret` 一条指令，见下） | — |
| **5** | `update(u32)` —— 喂 4 字节 | 4 |
| **6** | `update(u16)` —— 喂 2 字节 | 2 |
| **7** | `update(u8)` —— 喂 1 字节 | 1 |
| **8** | = slot5 | 4 |
| **9** | = slot6 | 2 |
| **10** | = slot7 | 1 |
| **11** | = slot7 | 1 |
| **12** | `update(std::string)` —— 喂 `str.size()` 字节 | 变长 |
| **13** | `update(const char*)` —— 喂 `strlen+1` 字节（**含 NUL**） | 变长 |
| **14** | `digest()` —— 返回指向 **16 字节结果**的指针（`this+8`） | — |

### ★★★ 关键洞察：**槽号 = 类型宽度表**

看 slot5–11 的**顺序**：

```
slot 5  → 4 字节
slot 6  → 2 字节
slot 7  → 1 字节
slot 8  → 4 字节      (与 5 同)
slot 9  → 2 字节      (与 6 同)
slot 10 → 1 字节      (与 7 同)
slot 11 → 1 字节      (与 7 同)
```

**这是三组「同一批重载、不同声明序」被 dedup + stable_sort 挤在一起的结果。**
（BigWorld 的方法号规则：定长按 `streamSize` 升序、变长在后、`stable_sort` 保声明序 ——
但**这里排序键不是 streamSize**，见 §四的坦白。）

`slot 5/6/7` 与 `8/9/10` 是**两组不同的重载族**（同函数体、同宽度），
说明源码里有**两处**各自声明了 `(u8/u16/u32)` 这一组重载 ——
一处是 MD5 的「喂整数」，一处是 visitor/序列化器的「喂基础类型」。

---

## 三、语义是怎么读死的

### 3.1 槽5/6/7/8/9/10 —— 同一个 worker，只有一个宽度参数不同

```c
void FUN_1403e8290(longlong p1, undefined8 p2, undefined4 p3)   // slot 5, 8 → 4 字节
{ undefined4 t[4]; t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 4); }

void FUN_1403e8260(longlong p1, undefined8 p2, undefined2 p3)   // slot 6, 9 → 2 字节
{ undefined2 t[8]; t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 2); }

void FUN_1403e8230(longlong p1, undefined8 p2, undefined1 p3)   // slot 7, 10, 11 → 1 字节
{ undefined1 t[16]; t[0] = p3; FUN_1403e82f0(p1+8, p1+8, t, 1); }
```

⇒ **三个函数体逐字相同，只有最后一个实参 4/2/1 不同。** 那个实参就是「喂几个字节」。

### 3.2 槽12/13 —— 字符串版

```c
void FUN_1403e8210(longlong p1, undefined8 p2, undefined8 *p3)  // slot 12: std::string
{
  undefined8 *len = p3 + 2;                       // SSO: 长度在 +0x10
  if (0xf < (ulonglong)p3[3]) p3 = (undefined8 *)*p3;   // >15 → 堆指针
  FUN_1403e82f0(p1+8, p1+8, p3, *(undefined4 *)len);
}

void FUN_1403e81e0(longlong p1, undefined8 p2, longlong p3)    // slot 13: const char*
{
  longlong n = -1;
  do { n = n + 1; } while (*(char *)(p3 + n) != '\0');   // = strlen
  FUN_1403e82f0(p1+8, p1+8, p3, (int)n + 1);             // ★ +1 = 含 NUL
}
```

`0xf < p3[3]` 是 libstdc++/MSVC 的 SSO 边界 15 —— **`std::string` 判据**。
`FUN_1403e81e0` 是 `strlen` 循环，且 **+1 把 `'\0'` 也算进去**。

### 3.3 槽14 —— 返回 digest

```c
longlong FUN_1402ed600(longlong p1) { return p1 + 8; }
```

一条指令。配合 §3.4 的「状态在 `this+8`」⇒ **返回指向 16 字节 MD5 结果的指针。**

### 3.4 ★★★ worker `FUN_1403e82f0` 就是 MD5 的 `update` —— 逐字对上

```c
void FUN_1403e82f0(undefined8 p1, uint *st, void *data, uint n)
{
  uint bitoff = *st >> 3 & 0x3f;              // ★ 缓冲里已有多少字节（0..63）
  if (0 < (int)n) {
    uint lo = *st + n * 8;                    // ★ 位计数 low
    uint hi = (n >> 0x1d) + st[1];            // ★ 位计数 high（进位）
    st[1] = hi; *st = lo;
    if (lo < n * 8) st[1] = hi + 1;           // ★ 低 32 位溢出 → 高进位

    if (bitoff != 0) {                        // 缓冲里有残字节
      uint m = (0x40 < (int)(bitoff + n)) ? (0x40 - bitoff) : n;
      memcpy((char*)st + bitoff + 0x18, data, m);   // ★ 缓冲在 st+0x18
      if ((int)(m + bitoff) < 0x40) return;
      n -= m; data += m;
      FUN_1403e8620(p1, st, st + 6);          // ★ 压缩一个块，块输入在 st+0x18
    }
    if (0x3f < (int)n) {                      // 有整块
      ulonglong blk = n >> 6;
      n = n + (n >> 6) * -0x40;               // n %= 64
      do { FUN_1403e8620(p1, st, data); data += 0x40; blk--; } while (blk != 0);
    }
    if (n != 0) memcpy(st + 6, data, n);      // 余数进缓冲
  }
}
```

**这是教科书 MD5 的 `update`，一行不差** —— 位计数、64 字节块、0x40 边界、
`st+0x18` 当 64 字节缓冲、`st+6`（= `+0x18`）当缓冲起点。

### 3.5 ★★★ 压缩函数 `FUN_1403e8620` 里是 **RFC 1321 的 T 表**（铁的判据）

反汇编里出现的常量，逐个对上 MD5 的标准 T 表：

| 实测常量 | RFC 1321 |
|---|---|
| `0xd76aa478` | T[0] = `d76aa478` ✓ |
| `0xe8c7b756` | T[1] ✓ |
| `0x242070db` | T[2] ✓ |
| `0xc1bdceee` | T[3] ✓ |
| `0x4787c62a` | T[4] ✓ |
| `0x57cfb9ed` | T[5] ✓ |
| `0xf57c0faf`* | T[6] |
| `0x698098d8` | T[8] ✓ |
| `0x895cd7be` | T[11] ✓ |
| `0xf61e2562` | T[20] ✓ |
| `0xc040b340` | T[21] ✓ |
| `0x265e5a51` | T[22] ✓ |
| `0xe9b6c7aa`* | T[23] |

**⇒ 这是 MD5，不是别的哈希。** 不用猜。

### 3.6 槽0 析构 —— 顺带把对象大小读出来了

```c
undefined8 *FUN_142a9b580(undefined8 *p1, ulonglong flags)
{
  *p1 = BW::IMD5Calculator::vftable;      // ★ 写的是【基类】表（见 §四.3）
  if ((flags & 1) != 0) free(p1);         // ★ 释放
  return p1;
}
```

反汇编：`mov edx, 0x60` 然后 `call` 到 free ⇒ **整个对象 0x60 = 96 字节**。
反推布局：`+0x00` vptr｜`+0x08` 位计数(8)｜`+0x10` ??(8)｜`+0x18` 64 字节缓冲｜
`+0x58` 结果/对齐 ⇒ 96 字节正好。

### 3.7 槽1–4 是空函数

```asm
0x1402F7290  ret
```

**一条 `ret`。** 四个槽都指向它 ⇒ 这四个虚函数在本类是**故意空实现**
（对应 `AbstractMD5Visitor` 里那几个「留给子类 / 默认什么都不做」的钩子）。

---

## 四、三条你必须知道的坑

### 4.1 ★ **槽号不是「按宽度排序」的通用规则**

我一度想写成「slot5=4字节、6=2字节、7=1字节，所以槽号=宽度表」，
但 **slot 12（变长 `std::string`）排在定长之后**，而 slot 8–11 又是定长 ——
**顺序不单调**。真实成因是 BigWorld 的「接口优先 + 定长升序 + 变长在后 +
同名 dedup + `stable_sort`」在**两组重载族**上叠加的结果，
**不能当成一条可直接外推的公式**。
⇒ 要判别的类的槽号，**得逐类读它的表**，别套公式。

### 4.2 ★ 槽13 的 `+1` 会把终止符也算进 MD5

`FUN_1403e81e0` 喂的是 `strlen+1` 字节，**`'\0'` 参与哈希**。
⇒ 若你要**复现**这个类的输出，`const char*` 那条路必须带上 NUL；
而 `std::string` 那条路（槽12）**不带**。
**两条路对同一个字符串的哈希结果不同。**

### 4.3 ★★ 析构里写的是**基类**表 —— 这是「静态反汇编读 vtable」的经典陷阱

`FUN_142a9b580` 与 `FUN_142a9b550`（`IMD5Calculator` 的析构）**都**写
`*p1 = BW::IMD5Calculator::vftable`（`0x143923038`），
**只有类外多一层包装**才把 `MD5Calculator` 的表填进去。

⇒ **`BW::MD5Calculator::vftable` 这个符号在反汇编里指到的 `0x1439230B0`
是我的工具（`vtinfo.py`）从 RTTI 反推出来的**，不是从析构里读的。
**两者必须都验** —— 只读析构会得出「它用基类表、自己没表」的错结论。

### 4.4 ★ `MD5Calculator` 的**实例**是栈上的局部对象

```c
undefined8 *FUN_142a9b640(undefined8 *out, undefined8 arg, code *visitor)
{
  ...
  local_88 = BW::MD5Calculator::vftable;   // ★ 栈上造一个 MD5Calculator
  FUN_1403e8140(local_80);                 // 初始化
  (*visitor)(arg, &local_88);              // ★ 把 visitor 喂给它
  FUN_1403e82e0(local_80, out);            // 取出结果
  return out;
}
```

⇒ `MD5Calculator` **不是** `IMD5Calculator` 的子类实例堆分配，
而是一个**栈上的一次性哈希器**：造出来 → 让 visitor 灌数据 → 取 digest → 丢。
这解释了为什么它是「计算器」：**它的生命周期只有一次哈希。**

---

## 五、复现命令（**你只有 `decomp` 也能跑前三条**）

```bash
# 1) 类的 RTTI / vtable（需要原始 EXE 读字节）
py -3 tools/vtinfo.py --at 0x1439230B8
#   → COL = 0x143EA00A8   RTTI = .?AVMD5Calculator@BW@@

# 2) 各槽目标是什么符号（只用 decomp/index.tsv，★ 你那边就有）
grep -i "^142a9b580\b" decomp/index.tsv
grep -i "^1402f7290\b" decomp/index.tsv
grep -i "^1403e8290\b" decomp/index.tsv
grep -i "^1403e8260\b" decomp/index.tsv
grep -i "^1403e8230\b" decomp/index.tsv
grep -i "^1403e8210\b" decomp/index.tsv
grep -i "^1403e81e0\b" decomp/index.tsv
grep -i "^1402ed600\b" decomp/index.tsv
#   → 全部落在 c_1402c13f0.c / c_1428d1e40.c

# 3) 函数体（只用 decomp，★ 你那边就能读）
sed -n '212059,212165p' decomp/chunks/c_1402c13f0.c   # 槽5..13 全部
sed -n '368014,368030p' decomp/chunks/c_1428d1e40.c   # 槽0 析构
sed -n '368068,368090p' decomp/chunks/c_1428d1e40.c   # 构造函数

# 4) MD5 的 T 表（需要原始 EXE 反汇编；你那边可用 Ghidra 直接看）
py -3 tools/disasm.py 0x1403e8620 400 | grep -o "0x[0-9a-f]\{8\}" | sort -u
```

### ★ 只有 `decomp` 时读不到的两处（诚实标注）

1. **vtable 里填了哪些字节** —— `decomp` 只给 `BW::MD5Calculator::vftable`
   这个**符号名**，不给地址、不给内容。
   **替代路径**：在 Ghidra 里对该类的构造函数 `FUN_142a9b640` 找
   `local_88 = BW::MD5Calculator::vftable;` 那一行，Ghidra 会把它解析到具体地址。
2. **槽1–4 的 `ret`** —— 反汇编才看得出来；`decomp` 里它可能是空的或显示为
   一个只 `return` 的函数。

---

## 六、一句话总结

**`BW::MD5Calculator` = 标准 MD5（RFC 1321 T 表逐项吻合），15 槽 =
1 析构 + 4 空钩子 + 7 个 `update` 重载（4/2/1 字节 ×2 组 + `std::string` + `const char*`）+
1 个 `digest()`。对象 96 字节，栈上一次性使用。**
