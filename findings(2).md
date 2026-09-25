# WoT 回放逆向 · 结论登记册（findings.md）

- 重建时间：2026-09-24（会话环境曾被完全重置一次：`upload/` 清空、`/tmp` 清空、原 findings.md / worklog.md / scripts / csi_tables_v8.json 丢失。本文件依据会话摘要 + 本轮新证据重建；v1–v8 为摘要级复述，细节论证过程已失；v9 起为逐字可验的新结论。）
- **v12（2026-09-24）**：全部失散资产已从 FengY233/test 恢复（csi_tables_v8.json / V7 交付包 / 会话记录.txt，见附录 A）；重置前原版 findings.md（v8 全细节版）亦在仓库中寻回；本册为当前最全结论登记。
- **v13（2026-09-24）**：§9 新增——EntityDescriptionMap::parse 全架构白盒（挂载规则全解 + records 集合真相）；§5/§7 增补 fork 增量④⑤（client 方法出局 / FIXED_DICT 定长化，后者推翻 v8 的「+5=组件注入」归因，40/40 实体 csi 全对账）；§6 开放项刷新；附录 E 新证据坐标。
- **v14（2026-09-24 · 本轮）**：**§10 新增——FeatureExtension 体系发现（本轮最大突破）**：客户端存在 18 个全部 IsEnabled=true 的 res/<ext>/extension.xml，向 digest 贡献 39 static 挂载 + 171 dyncomp + 10 CS 实体记录（v13 的「干净安装=空树」判断被推翻，records 集合实为 ~318 条而非 148 条）；另完成全链字节级复核（walker 计数器/isForClient/ExposedForReplay/DT 层 24 feeder/parseProperties 全链/迭代序），全部与模型一致——差异唯一剩余自由度锁定在扩展记录内容；§6 开放项改写；附录 F 新证据坐标。
- 同步位置：`/home/z/my-project/findings.md` ≡ `upload/findings.md` ≡ `download/findings.md`（三处 md5 一致）
- 登记制度（用户指令）：新结论确认后及时写入本册并在附录留痕，每次更新三处同步。

## 0. 对象与目标
- 样本：`20260911_1801_ussr-R52_Object_261_37_caucasus.wotreplay`（2.4.0.0 CN 客户端录制，1x 实时）
- 已通透（v1–v7）：容器格式 / 加密 / 包流 / 38 种包类型 / 时钟（float32 秒）
- 当前主线：**0x3D 包 = entityDefs 摘要**
  - 目标值：`5DF886F75E73B33CFF9D87FB9C69389C`（replay.jsonl 第 4 行，t=61，MD5 quote 大写 hex，全流唯一；replay.jsonl 已从 FengY233/test 恢复并核对此行）

## 1. [v8 · 已闭环] 0x07/0x24 属性号 = csi
- 40 实体 / 306 条 CS 属性，14 锚点验证；权威表 `csi_tables_v8.json`（**v12 已从 FengY233/test 恢复**，md5 `5ac32922ca7a61fd0cd144b52405cd86`，44,158B；已随 V9 交付包分发）。
- 遗留属性确名：**1=isStrafing、16=avatarID、33=perkEffects、34=perks**。
- 服务器 273 个 .def（EN/pxml）可用用户权威版 `tools/bwxml_decode.py`（勿替换）全量解码；**v11 起已恢复**（upload/bwxml_decode.py，3930B）。

## 2. [v8→v11] 0x3D 算法归属与配方状态
- 0x3D = **WoT fork 重写版** entity_description_digests（IMD5Calculator/MD5Visitor 体系；vanilla 14.4.1 无此架构）。
- **v11：fork 完整配方已从 decomp 逐函数解出**（见 §7），与 vanilla 的差异收敛为三个确定项 + 一个待定项（组件挂载规则）。
- 已排除：vanilla 全复刻、15,552 组合暴力、122,880 结构族网格、原始字节族 14 式、UDO 并入族 18 式、编码层（NUL/宽度/端序/掩码）系统性排除。

## 3. [v9 · 2026-09-24] BW::MD5Calculator vtable 全解 —— 0x3D 的 MD5 层闭合

### 3.1 表结构（用户 Ghidra 导出 + 本机交叉验证通过）
- `BW::MD5Calculator::vftable`：COL 指针在 `0x1439230B0`（值 `0x143EA00A8` → `.?AVMD5Calculator@BW@@`），**slot0 在 `0x1439230B8`，共 15 槽**；对象 vptr = slot0 地址（MSVC ABI）。
- 原始字节 ↔ 槽表 17 个 qword 逐一核对一致（0x142A9B580 | 4×0x1402F7290 | 0x1403E8290/260/230/290/260/230/230/210/1E0 | 0x1402ED600）。
- RTTI 零间隙邻接（交叉验证边界）：
  - IMD5Calculator slot0 = `0x143923038`（其析构 FUN_142a9b550 写入 vptr 的值；MSVC ABI 要求该值 = slot0 地址）
  - `0x143923038 + 15×8 = 0x1439230B0` = MD5Calculator 的 COL → **IMD5Calculator 也恰 15 槽**（干净继承：全量覆写、不加槽；其 1–14 槽全为 `_purecall`@0x142C96CB2 = 纯虚）
  - `0x1439230B0 + 8 + 15×8 = 0x143923130` = AbstractMD5Visitor 的 COL → 零间隙

### 3.2 槽位 → 虚调用偏移 → 字节编码（**v11 机器码级终验**）
| 槽 | 偏移 | 语义 | 函数 | 字节贡献 |
|---|---|---|---|---|
| 0 | +0x00 | scalar deleting dtor | FUN_142a9b580 | — |
| 1–4 | +0x08..+0x20 | **空壳**（COMDAT 折叠进 AkStompAllocatorInitForThread，单条 ret） | 0x1402F7290 | **无（no-op 钩子）** |
| 5 | +0x28 | update(u32) 族A | FUN_1403e8290 | 4 字节 LE |
| 6 | +0x30 | update(u16) 族A | FUN_1403e8260 | 2 字节 LE |
| 7 | +0x38 | update(u8) 族A | FUN_1403e8230 | 1 字节 |
| 8 | +0x40 | update(u32) 族B | FUN_1403e8290 | 4 字节 LE |
| 9 | +0x48 | update(u16) 族B | FUN_1403e8260 | 2 字节 LE |
| 10 | +0x50 | update(u8) 族B | FUN_1403e8230 | 1 字节 |
| 11 | +0x58 | update(u8) 族B' | FUN_1403e8230 | 1 字节 |
| 12 | +0x60 | update(std::string) | FUN_1403e8210 | size 字节，**无 NUL、无长度前缀**；第 2 参数（标签名）被忽略 |
| 13 | +0x68 | update(const char*) | FUN_1403e81e0 | strlen+1 字节，**含 NUL**；第 2 参数（标签名）被忽略 |
| 14 | +0x70 | digest() | FUN_1402ed600 | return this+8（兼作「取 state 指针」惯用法：调用点先 slot14 再直调 worker FUN_1403e82c0 喂 4 字节） |

**v11 铁证**：FUN_142a9b640 机器码 `48 8d 05 45 7a e8 00`（lea rax,[rip+…]）解码目标 = **0x1439230B8**，即 vptr = slot0 首项，无 COL 位移歧义。slot3（+0x18）/slot4（+0x20）确为**空函数**（0x1402F7290 实测单字节 `c3` ret）→ **v9 的「+0x18 slot3 异常」闭合：所有经 +0x18 的调用（"properties"/"baseMethods"/"clientMethods"/"cellMethods" 段标记、成员名 no-op 预告）和经 +0x20 的 endSection 全部不贡献任何字节**。

### 3.3 对象布局（0x60 = 96 字节，Init/Final 机器验证）
`+0x00 vptr | +0x08 count(8B) | +0x10 A,B,C,D（Init 直写 67452301/efcdab89/98badcfe/10325476，与 RFC1321 逐项吻合）| +0x20 buf[64]`。
FUN_1403e8140=Init(state=this+8)、FUN_1403e82e0=Final（转 FUN_1403e8410，RFC1321 标准填充）、FUN_1403e82f0=MD5Update worker（v9 已逐行对账）。

### 3.4 对外部 AI 报告的核验结论（v9，v11 增补）
- **通过**：原始字节↔槽表全对；RTTI 邻接零间隙；worker 与 RFC1321 逐行吻合；SSO 判据；cstr 含 NUL；0x60 布局。
- **修正**：① 布局差 8 字节（buf 实为 this+0x20）；② T 表索引 0/1 基混用；③ `0x57cfb9ed` 非 RFC1321 常量。
- **v11 判决**：其 DAT "type"/"args" 读值正确（本机 exe 直读复核，见 §7.4），但两值**均为喂入器 label 参数、被 MD5Calculator 忽略**，不进入 digest 字节流；「疑似与 digest 无关」的谨慎判断部分正确——它们在 digest 路径上出现但贡献 0 字节。

## 4. [v10 · 2026-09-24] 资源恢复 + vanilla 配方全链复刻 + csi 机制破译

### 4.1 资源三件套（本机 `/home/z/my-project/repos/`）
- `scripts.7z`（FengY233/test）**md5=3291a19748a129bf8e16cd5983fda4c4 与丢失原件逐字节一致**；解压 → `scripts_x/scripts/`（192MB）。
- `BigWorld-Engine-14.4.1-HEAD/`（v2v3v4 镜像，1.4GB vanilla 源码）。
- `wot-src-59e92351…/`（wotstat，653MB）= **wot-cn 2.4.0.0 #942 sd 客户端资源树**。
- **v11 新增（FengY233/test 自取）**：`dec.7z.001/002`（合并→`dec_full.7z`，密码 114514.1919810）→ `decomp.zip`（47MB）→ `repos/decomp/`（30 chunks ≈320MB + giants + index.tsv 8.7MB + funcs_all.txt）；`replay.jsonl.zip`（156,482 行，t=61 目标行核对✓）；`wotexe.7z` → **WorldOfTanks.exe sha256 = `2ec886a84004be8ac1873a7d3d62d61e8d102a57fa34a8873afe67ca24ef9045`（78,777,520B）= wot-src stubs/manifest.json 权威值，逐字节一致 —— Ghidra 分析二进制与录制回放客户端同一性闭合**；`replay.wotreplay` 原件、`bwxml_decode.py`（用户权威版）、`def_dump.py`、`replay_setup.py`（两个新脚本待阅）。
- decomp.zip 覆盖度：主 digests 链路全部函数均在（c_1428d1e40.c 含 entity_description_digests.cpp 全簇 + entity_description.cpp 全簇 + data_types 全簇；c_1402c13f0.c 含 MD5Calculator 槽函数群）。

### 4.2 BWXML/PackedSection 解码器重建（`scripts/bwxml.py`，vanilla 源码级）
- 格式：`uint32 magic=0x62A14E45 | uint8 ver=0 | 字符串表(NUL串,空串终止) | 根块`；块=`int16 nChildren + ChildRecord[n](pack(1): int32 dataPos,int16 keyPos) + int32 finalPos + blob`。
- **类型在「下一记录」dataPos 高 4 位**（`ChildRecord::type() = (this+1)->dataPos_ & TYPE_MASK`）。
- 值语义：STRING=裸字节；BOOL=len>0；INT=小端1/2/4/8B；**BLOB=合法回环 Base64 的值**（实证：`b'\x04\x04\x84'`→"BASE"、`b'\n\x16\xad'`→"Chat"；Vehicle.def 的 arena 属性 Flags 即此形态）。2881 文件全解。
- ⚠️ 解码坑（v11 实录）：**有子节点的段 type 字段也可能标成 1（STRING）**，判断「是否为段」必须看 `children` 非空而非 type==0。

### 4.3 vanilla digest 配方全链（源码级，全部落地 `scripts/defparse.py`）
- 编排：`EntityDescriptionMap::digest()` = MD5 逐实体 `EntityDescription::addToMD5`（entities.xml **ClientServerEntities 文件序**，isClientType 过滤——fork 侧由 visitor slot7 检查 `entity+0x87` 等价实现）。
- 每实体：`name(无NUL无长度)` → 每 CS 属性（`dataFlags & 0x106`，即 OTHER_CLIENT|OWN_CLIENT|REPLAY）`[csi int32][varLenHeaderSize uint32 仅当 isForClient && streamSize<0 && ≠1][name 无NUL][dataFlags&0x5F int32][DataType::addToMD5]` → client 方法全量、base/cell 仅 exposed（`flags & 0xC`），各带计数器 `[同 Member 前缀][flags uint8][各 arg 类型][legacyExposedIndex int32]`。
- DataType 喂入全表（vanilla 源码 `md5.append( "Tag", sizeof("Tag") )` = **含 NUL**）：Int/Uint+size int32；Float/Float64/String/Blob/MailBox/Python/UnicodeString 单标签；Vector+NUM_ELEMENTS int32；User+module+instance(无NUL)；Array/Tuple=标签+size int32+dbLen int32(仅>0)+元素；FixedDict=标签+[!isCustomClassImplInited_||hasCustomClass() 时 module+instance]+allowNone u8+每字段 name(无NUL)+类型；UDO_REF="UserDataObjectLinkDataType\0"。
- **csi 分配破译**：每次 parseProperties 后 stable_sort（定长在前按 streamSize 升序、变长按 |−streamSize| 升序、同键保持声明序）再重编号。
- vanilla 基线实算：**`562A9B2278044E1EF6401BB7518E7701`**（≠目标 5DF886F7…，预期内）。
- fork-delta 搜索（负结果登记）：①结构族网格 122,880 组合；②原始字节族 14 式；③UDO 并入族 18 式——全部未命中 → 差异在语义层（v11 证实：isVolatile + 组件方法）。

### 4.4 锚点验证与 +5 缺口
- 40 实体 ✓ / 306 CS 属性 ✓（=v8 表）；Vehicle：isStrafing=1 ✓、avatarID=16 ✓、perkEffects=28/perks=29 ≠ 真值 33/34（+5 缺口 = 组件属性，见 §7.5 归因修正）。
- v10 判定「0x3D 不受组件影响」**在属性维度成立**（digest walker 只走 entity+0x28 自有属性向量），**在方法维度被 v11 推翻**（组件方法经 +0x2f0 进 digest，见 §7.5）。

## 5. [v11→v13 判决] 领先假设（解释 vanilla 复刻 ≠ 目标）
- ~~H1：fork 以 cstr 槽喂 def 名/路径（多 NUL）~~ **证伪**：名字一律 slot12（std::string，无 NUL）。
- ~~H2：长度前缀差异~~ **证伪**：无任何前缀。
- ~~H3：DAT 标记串混入输入流~~ **证伪**：标记串全部喂给空槽（slot3/slot4），贡献 0 字节。
- **v11 实况**：真差异 = ①每 CS 属性多 1 字节 isVolatile(u8)；②方法 returnValues 列表（本 def 集 0 字节）；③组件方法并入（+0x2f0 子描述）。
- **v13 增量④**：**client 方法全部出局**——onMethod（FUN_142a9b810）的 `(m+0x70 & 0xC)!=0` 过滤对全部域通用，而 fork 的方法解析禁止 client 方法带 `<Exposed>`（报错路径「Unable to use \<Exposed\> tag in client method」）、域位 CLIENT=0 → client 方法 flags 恒为 0（AllowUnsafeData 置的 0x10 在 0xC 掩码外）→ 全部被过滤。全 def 集 0 个 client 方法带 Exposed（与禁止规则自洽）。
- **v13 增量⑤（本轮最大）**：**FIXED_DICT 的 AllowNone 不再使 streamSize=-1**——vanilla `streamSize_( allowNone_ ? -1 : 0 )` 被改为无条件字段定长和。实证：DOT_EFFECT=8+4+1+1=14、BUFF_EFFECT=24、REMOTE_CAMERA_DATA=22、OWN_VEHICLE_POSITION=32、INSPIRED_EFFECT=36，与回放验证的 csi 表全部吻合；修复后 **40/40 实体 csi+streamSize+flags&0x5F 三要素全对账通过**（此前 39/40，Vehicle 变长区错位）。
- **+5 缺口新解（推翻 v8/v10 归因）**：Vehicle perkEffects/perks 28/29→真值 33/34 的 +5 从来不是「组件属性注入」——是上述 6 个 AllowNone FIXED_DICT（dotEffect 14/remoteCamera 22/inspiringEffect 24/healingEffect 24/ownVehiclePosition 32/inspired 36）从变长区(-1)移入定长区引发的排序位移。v10「动态组件为逐实例→不可能进静态 digest」的判定出子错因但仍成立；「0x3D 不受组件属性影响」在属性维度的结论不变。

## 6. [v14 改写] 开放项 / 下一步
1. **0x3D 唯一剩余差异 = FeatureExtension 扩展记录内容**（v14 发现，见 §10）：
   - 主链路全绿：本轮已把 walker 计数器语义、isForClient 公式、ExposedForReplay、DT 层 24 个 addToMD5 feeder（含 exe 直读 DAT 常量）、parseProperties 全链（含覆盖/csi 簿记/空段 Exposed→0x4 规则）、FUN_142a99f30 迭代序、parseMethods 域分支、ReturnValues=5 全非 exposed、静态挂载组件全扁平——全部字节级复核完毕，与 digest_fork_v2.py 模型一致；25 组合消融矩阵 + 本轮新增复核均未发现模型与 decomp 的任何偏差；
   - 唯一未建模维度：**18 个 FeatureExtension 的记录贡献**（39 static 挂载边 + ≤171 dyncomp 记录 + 10 CS 实体记录）——v13 的「干净安装=空树」判定是错的（wot-src 镜像 res/ 下有全部 18 个 extension.xml，全部 IsEnabled=true；paths.xml 列有对应 18 个扩展 pkg）；
   - **阻塞项：扩展 def 文件不在任何现有资源中**（scripts.7z=主 scripts.pkg 内容，无扩展 def；wot-src 镜像剥除了全部 .def 二进制）——需用户从客户端 res/packages/ 的 18 个扩展 pkg 提取 scripts/{entity_defs,component_defs}（含 interfaces）+ scripts/client 文件清单，上传 FengY233/test；
   - def 到货后的执行清单：①按 §10 模型扩展 digest_fork_v2.py（扩展实体→loop#1、扩展 dyncomp→loop#2+decider、扩展 static→Part b 挂载）；②顺序假设枚举（pkg/paths.xml 序=字母序 vs 枚举序，若未命中再试交换）；③同名去重跨批次语义（FUN_142a99f30 每次调用独立 FNV 集合→跨批次同名可重复入 records，需按实况处理）。
2. （已结）方法层合并细节：§7.8 接口序 + §10 复核 walker 计数器=exposed 连续编号——模型与 decomp 一致，非差异源。
3. （已结）DT 层：24 个 addToMD5 feeder 逐字节复核（含 "Int"/"Uint"/"Blob"/"User" DAT 直读验证，均含 NUL）——模型一致。
4. def_dump.py / replay_setup.py 已阅：前者为客户端 scripts.pkg 读取工具（证实 scripts.7z=客户端树，含 scripts/client 270 个 pyc），后者为回放解包器，均不含 digest 真值。
5. `tools/bwxml_decode.py`（用户权威版）与 `scripts/bwxml.py` 交叉验证——仍未做（低优先）。
6. 0x07/0x24 csi 表：**v8 表已全部正确**（40/40 复验），无需重建；0x05 创建块 n∈{3,6,7,18,28,29,40} 全部 ≤40（与「扩展实体在 40 之后」的数组布局无矛盾——本场战斗未创建扩展实体）。
7. 实算基座：`scripts/digest_fork_v2.py`（148 记录完整模型）+ `scripts/digest_fork_diag.py`（25 组合矩阵）+ `scripts/ext_inventory.py`（扩展清单提取，产出 download/ext_inventory.json）；defparse.py 已修 FIXED_DICT streamSize。

## 7. [v11 · 2026-09-24] decomp 全解 —— fork digest 配方逐函数闭合

### 7.1 调用链顶层（entity_type.cpp:0xe0，`BW::EntityType::init`，c_1402c13f0.c:143725）
```
FUN_140394440 = EntityType::init:
  打开 scripts/entities.xml
  FUN_142a98830(map@0x14483e050, …) = EntityDescriptionMap::parse   ← 解析全部实体/接口/组件
  FUN_142a9b640(&out, map, FUN_142a9b5b0) = 计算digest → 存全局 0x14483e028/030
  FUN_142a9b3e0(map) = 实体计数（<1 报错；计数不进 digest）
  逐实体（0x328 步长）：isClientType(+0x87) → 解析 client 脚本路径
```
栈哈希器 FUN_142a9b640：`local_88=MD5Calculator::vftable → Init(state=obj+8) → visitor 回调 FUN_142a9b5b0(map, &calc) → Final(state, out)`。

### 7.2 Visitor 双表架构（entity_description_digests.cpp 全簇，c_1428d1e40.c 367936–368300）
- `FUN_142a9b5b0` = 顶层 visitor 装配：`calc->slot3(0,0)`(no-op) → 建 **ClientServerTypesMD5Visitor**（栈对象 {vptr, calc_ptr@+8, inSection@+0x10}）→ `FUN_142a9b410(map, &visitor)` 遍历 → 两层 `calc->slot4()`(no-op) 收尾。
- **AbstractMD5Visitor vftable @ 0x143923138**（8 槽 + 字符串池）：slot1=FUN_142a9b7f0(startProperties→calc slot3 no-op)、slot2/slot4=FUN_1404397b0(endSection→calc slot4 no-op)、slot3=FUN_142a9b750(startMethods(domain)：1/2/4→"baseMethods"/"clientMethods"/"cellMethods"→calc slot3 no-op)、slot5/6/7=空(纯虚)。
- **ClientServerTypesMD5Visitor vftable @ 0x143923290**（覆盖 slot5/6/7）：slot5=**FUN_142a9b870(onProperty)**、slot6=**FUN_142a9b810(onMethod)**、slot7=**FUN_142a9b6c0(实体过滤+喂名)**。
- `FUN_142a9b410`：按 0x328 步长遍历 map 实体数组 → `visitor->slot7(entity)` 过滤 → 通过则 `FUN_142a93420(entity, visitor)` 逐实体喂入。
- `FUN_142a9b6c0`：`entity+0x87 != 0`（isClientType）→ `FUN_142a9b6e0`：`calc->slot3(name_data,0)`(no-op) + **`calc->slot12("name", &entity->name)` = 喂实体名（无 NUL）**。
- **`FUN_142a93420`（逐实体编排，顺序铁证）**：
```
startProperties → 遍历 entity+0x28..0x30（0xf0 步长）onProperty → endProperties
startMethods(client=2) → 遍历 entity+0x218..0x220（0x170 步长）onMethod(m, idx++)
                       → 遍历 entity+0x2f0..0x2f8 的每个子描述的 +0x218..0x220 onMethod(m, idx++)
endMethods(2) → startMethods(base=1) → 自有 +0x198（exposed 过滤 0xC）+ 子描述同域（idx 连续）
endMethods(1) → startMethods(cell=4) → 自有 +0x118（exposed 过滤）+ 子描述同域
endMethods(4)
```
- **onProperty（FUN_142a9b870）**：`(prop+0x78 & 0x106)!=0`（=vanilla isClientServerData）→ 经 slot14 惯用法喂 `[csi u32（prop+0x9c）]` → `FUN_142a894e0` 正文。
- **onMethod（FUN_142a9b810）**：`(m+0x70 & 0xC)!=0` → `FUN_142aa17d0` 正文 → 经 slot14 惯用法喂 `[index u32]`。

### 7.3 Member 正文喂入器（与 vanilla 逐项对照）
**属性 FUN_142a894e0**（DataDescription::addToMD5 fork 版）：
```
[slot3(name,0) no-op]
FUN_142abc050:  [varLenHeaderSize u32 仅当 +0x55(isForClient) && streamSize<0 && ≠1] + [name slot12 无NUL]
slot5(+0x28)("dataDistributionFlags", flags&0x5F)   → u32
slot11(+0x58)("isVolatile", *(prop+0xb3))           → u8  ★fork 增量①（vanilla 无此喂入）
prop->type(+0x70)->slot15(calc, "type")             → DataType::addToMD5
[slot4() no-op]
```
**方法 FUN_142aa17d0**（MethodDescription::addToMD5 fork 版）：
```
[slot3(name,0) no-op]
FUN_142abc050:  [varLenHeaderSize 判定同上] + [name slot12 无NUL]
slot10(+0x50)("flags", *(m+0x70))                   → u8（vanilla flags_ uint8 同位）
FUN_142abcbc0(m+0x80, calc, "args")                 → 逐 arg 仅喂 DataType（arg 名经 slot3=no-op；列表空则 0 字节）
FUN_142abcbc0(m+0xa0, calc, "returnValues")         → ★fork 增量②（vanilla 不喂返回值；本 def 集全空=0 字节）
[slot4() no-op]
（onMethod 随后喂 index u32 = vanilla legacyExposedIndex，语义相同：每域 0..N-1，自有+组件连续）
```
**FUN_142abc050 的 varLenHeaderSize 条件与 vanilla 完全一致**（isForClient_@+0x55、streamSize 经虚调用、默认值 1=Mercury::DEFAULT_VARIABLE_LENGTH_HEADER_SIZE）。

### 7.4 "type"/"args" 之谜 —— 已彻底解决
- exe 直读（VA→文件偏移）：`0x1435E0950 = "type"`（邻域 "No such entity type '%s'"/"transform"/"properties" 与外部 AI 报告吻合）、`0x143665890 = "args"`（邻域 "execute"/"({%}) -> unicode"/"PyGuiApplication" 吻合）。
- **角色**：两者都是喂入器 API 的 **label 参数**，随调用传入后被 MD5Calculator 实现忽略：
  - `"type"`：属性类型喂入 `DataType::addToMD5(calc, label="type")`（DataType vtable slot15 @+0x78）；
  - `"args"` / `"returnValues"`：方法参数/返回值列表喂入 `FUN_142abcbc0(list, calc, label)`；
  - 同族的 label 还有 "name"(0x1435D2D24)、"flags"、"size"、"dataDistributionFlags"、"isVolatile"、"varLenHeaderSize"、"moduleName"、"instanceName"、"allowNone"、"dbLen"、"elementType"、"fields"、"baseMethods"/"clientMethods"/"cellMethods"/"properties" —— **全部 0 字节贡献**（ visitor API 为多消费者共享设计；FUN_1403e8170/81a0 属于另一个 calculator 实现，其 +0x08/+0x18 语义不同，勿混）。
- 外部 AI 报告的 decomp 引用行号（c_140b9d8b0.c:255971 PyDict_GetItemString 等）属于 Python 桥接层，与 digest 路径无字节交集。

### 7.5 ★fork 增量③：组件方法进 digest（+0x2f0 子描述体系）
- `FUN_142a8d480`：构造 **0x338 字节的新 EntityDescription**（`std::_Ref_count_obj2<BW::EntityDescription>` 包装）并 push 进实体 `+0x2f0` 向量 —— 组件以「子实体描述」形态挂载，**方法并入 digest、属性不并入**（walker 只走 entity+0x28 的自有属性向量 → 组件属性不进 0x3D，解释 v8 +5 csi 缺口为何只出现在 0x07/0x24）。
- 挂载机制：`FUN_142a900a0`（建子描述）← 两路调用：`FUN_142a8ff40`（EntityDescription::parseComponents 路径，vanilla `<Components>` 机制，**41 个 entity def 均未使用**）与 `FUN_142a99f30`（map 级 parse，833 行，内含 FNV-1a 名字去重映射 + 0x328 实体记录管理 —— **静态挂载真值源头，待细读**）。
- def 侧素材：`component_defs/*.def` 127 个（**185 属性 / 3 Base / 41 Cell / 28 Client 方法**），其中 **79 个声明 `<ofEntity>`**（Account←2、Arena←16、ArenaInfo←5、Avatar←6、AvatarInfo←1、Entity←10、StaticDeathZone←1、TeamInfo←7、Vehicle←31）；`components.xml` 另列 StaticComponents 16 + DynamicComponents 113（仅名单，无挂载关系）。
- 组件方法语义：与实体方法同一喂入器（旧式 `<Arg>TYPE</Arg>` 形态），三域过滤规则一致（client 全量、base/cell exposed）。

### 7.6 fork 专属 volatile 属性机制
- 解析函数 `FUN_142a923c0 = EntityDescription::parseVolatileProperties(entity, section)`：把段的子节点当**属性名列表**，逐个 `FUN_142a83cb0` 查属性 → 插入 csi 树 → **`prop+0xb3 = 1`**；查无此属性则报 `"Volatile property \"%s\" does not refer to a valid property…"`；已 IsReliable/SendLatestOnly 的属性报暗示性警告。
- 调用点：`EntityDescription::parseInterface`（FUN_142a90940）末尾，段 = **`<Volatile><Properties>`**（entity+0x58 类型 ∉{3,4} 时）。
- def 实况：41 个 entity def 的 `<Volatile>` 段全是 vanilla 形态（position/yaw/roll/pitch）；**唯一 `<Volatile><Properties>` 在 component_defs/GunMarkerComponent.def（gunMarker）** —— 组件属性本就不进 digest → **40 实体全部 CS 属性 isVolatile=0x00，但该字节仍逐属性喂入（增量①的 306 个 0x00）**。

### 7.7 类型标签层：fork ≡ vanilla（逐函数对账）
fork 各 DataType vtable slot15(+0x78) 实测喂入（RTTI→COL→vftable 全链解析 47 表）：
| 类型 | 喂入 | vanilla 对照 |
|---|---|---|
| IntegerDataType<C/E/F/G/H> + LongIntegerDataType<I/_J/_K> | `"Int"`/`"Uint"`(含NUL) + size u32 | ✓ 同（integer_data_type.cpp:145） |
| FloatDataType<M>/<N> | `"Float"` / `"Float64"` | ✓ 同 |
| StringDataType / BlobDataType / UnicodeStringDataType / PythonDataType | `"String"`/`"Blob"`/`"UnicodeString"`/`"Python"` | ✓ 同 |
| UserDataType | `"User"` + module + instance（slot12 无NUL） | ✓ 同 |
| UserDataObjectDataType（fork 具体类） | `"UserDataObjectLinkDataType"`（与 vanilla UDORefDataType 同标签；UserDataObjectLinkDataType@BW 为抽象基类无 COL） | ✓ 同 |
| VectorDataType<Vector2/3/4> | `"Vector"` + N u32 | ✓ 同 |
| ArrayDataType / TupleDataType | `"Array"`/`"Tuple"` + Sequence 喂入（size u32 + dbLen u32 仅>0 + 元素 slot15） | ✓ 同 |
| FixedDictDataType | `"FixedDict"` + [!isCustomClassImplInited_‖hasCustomClass() 时 module+instance] + allowNone u8 + 每字段 name(slot12)+类型 | ✓ 同（fixed_dict_data_type.cpp:917 条件逐字一致） |
| UnsupportedDataType | （387200 行起，异常路径） | — |
- **fork 无 MailBoxDataType / Dict / Class 类型类**：MAILBOX 在 22 个 def 中出现但 **0 处进入 digest**（3 个属性全非 CS——CELL_PRIVATE/BASE；全部方法参数都在非 exposed 的 base/cell 方法上）；DICT/CLASS 未在 def 中使用。→ 对 0x3D 零影响。

### 7.8 fork 解析顺序 ≡ vanilla（方法合并顺序依据）
`EntityDescription::parseInterface`（FUN_142a90940）实测顺序：`FUN_142a84690`（Base 版 parseInterface：**parseImplements 递归（虚 +0x18 → FUN_142a83da0：开 `<defs>/interfaces/<name>.def` → 对同一实体递归 parseInterface）→ parseProperties**）→ VolatileInfo/AppealRadius/bools → parseMethods（FUN_142a91030：Base→Cell→Client）→ parseTempProperties → parseVolatileProperties。与 vanilla entity_description.cpp:381-444 一致 → **接口方法在解析期并入实体方法表（接口在前、自有在后），digest 的 +0x218 即此合并序；组件方法在合并表之后（+0x2f0）**。

### 7.9 实算测试（v13 更新，scripts/digest_fork_v2.py + digest_fork_diag.py）
- 旧 A/B/C（digest_fork_test.py，**含 csi 错位 bug**）：A=B6DFA134…、B=D54806FD…、C=196E8A39…，均≠目标（历史值仅作参考，csi 修复后全部失效）。
- v13 完整模型（csi 修复后）：records=148（space+40 实体+107 dyncomp），CS 属性 489（isVolatile=1 仅 gunMarker），digest 方法 134（base/cell exposed）→ `E2E9EBE2131D9580DDA9D6BE7288AAB3` ≠。
- 25 组合消融矩阵全负（见 §6.1）。目标 `5DF886F75E73B33CFF9D87FB9C69389C` 仍未命中，剩余自由度见 §6。

## 9. [v13 · 2026-09-24] EntityDescriptionMap::parse 全架构白盒 —— 挂载规则与 records 集合真相

### 9.1 顶层编排（FUN_142a98830 = EntityDescriptionMap::parse，c_1428d1e40.c:365735）
```
读 scripts/spaces.xml（FUN_142b79900）→ local_120
读 scripts/components.xml（FUN_142b79880）→ local_128
计数 = calculateEntitiesSize(FUN_142a96bc0: ClientServerEntities+ServerOnlyEntities 子数)
       + spaces.xml 子数 + components.xml/<DynamicComponents> 子数 → 预留 0x328 记录数组
① FUN_142a9b170 = parseSpaces（mode=2，decider=SpaceDescriptionHasPythonScript）→ records[0]
② FUN_142a7fae0 = FeatureExtensionManager 单例（扫 extension.xml；干净安装=空树）
③ FUN_142a971a0 = createEntityTypeToComponentSectionsMap（挂载索引，见 9.2）
④ FUN_142a996e0 = parseEntitiesBySide(param_5=0) → "ClientServerEntities" 40 实体（mode=1）
⑤ 扩展文件循环#1：逐文件读根 "Components" 子段 → 再解析实体（无扩展 → 跳过）
⑥ FUN_142a996e0(param_5=1) → "ServerOnlyEntities"（服务器树无此段 → 跳过）
⑦ FUN_142a99bc0 = 旧格式兼容（ClientServerEntities 存在时 no-op）
⑧ FUN_142a994c0 = parseDynamicComponents（mode=7，空索引不挂载）→ 110 唯一动态组件
⑨ 扩展文件循环#2：扩展文件的 DynamicComponents（无 → 跳过）
```
错误串铁证：`EntityDescriptionMap::parseSpaces/parseEntitiesBySide/parseDynamicComponents: Failed to load or parse def for …`、`calculateEntitiesSize: … doesn't have a <ClientServerEntities> section. Reverting to old-style parsing…`。

### 9.2 挂载索引（FUN_142a971a0 = createEntityTypeToComponentSectionsMap）
- **结构**：`std::multimap<实体名, {组件名, shared_ptr<DataSection>}>`（节点 0x68：KEY 串@+0x20、VALUE 串@+0x40、ptr@+0x60；插入函数 FUN_142a94570，等值键走右子树=**追加序**）。
- **Part a（静态）**：components.xml `<StaticComponents>`（16 名）逐名载 `scripts/component_defs/<名>.def`（FUN_142a96400）→ 其 `<ofEntity>` 每个实体名一条边。错误串：`Component definition file %s not found` / `no <ofEntity> section found in component %s`。
- **Part b（扩展）**：FeatureExtension 文件的 `<ExternalComponents>` 同样处理（干净安装为空）。错误串：`no <ofEntity> section found in external component %s, file %s`。
- **关键判定**：DynamicComponents 的 ofEntity（79 个组件声明中约 63 个属动态）**不进索引**——索引只由 StaticComponents(16)+扩展构成。16 条静态边：Arena←10、Account←2、TeamInfo←2、Avatar←1、Vehicle←1。
- **实际生效挂载**（目标实体须在 digest 记录集内）：**Account←[AccountFairplayComponent, AccountPBHComponent]、Avatar←[AvatarInBattleVehicleSwitch]、TeamInfo←[PoiTeamInfoComponent, TeamInfoInBattleVehicleSwitch]、Vehicle←[VehicleInBattleSwitch]**（"Arena" 不在 ClientServerEntities → 其 10 条边无效）。

### 9.3 parseFromSectionList（FUN_142a900a0）与记录构造（FUN_142a99f30）
- FUN_142a99f30（通用 def 批量入 map）：FNV-1a 名字去重收集 → 0x328 数组扩容 → 逐条：`FUN_142a8ee00(mode,名,dir)` 载主 def（目录由 mode 定：1=entity_defs、2=space_defs、3=service_defs、5=event_topics、7=component_defs）→ pairs=[(主def,"")]++equal_range(实体名)命中 → `FUN_142a900a0(记录,pairs,mode,名)`。
- FUN_142a900a0：pairs[0]（空名）走主解析（**Parent 段 → FUN_142a90f20 → FUN_142a8ff40 → 递归 parseFromSectionList 同记录**——继承链）；pairs[1+]（有名）逐个 `FUN_142a8d480` 建 0x338 子描述（**type=6**）压入记录+0x2f0（重名报 `Double static entity component definition %s for entity %s`）。记录+0x80=typeIndex、+0x82=clientIndex、+0x87=isClientType、+0x58=DescriptionType、+0x60=目录串。
- mode==7 附加：记录+0x2f=+0x4f=1、读 `DefaultKeyName`→+0x308。

### 9.4 decider 三表（isClientType 的来源，parseFromSectionList 末尾三连虚调用 → 记录+0x85/86/87）
| decider | vftable | slot2（→+0x87）语义 |
|---|---|---|
| EntityDescriptionHasClientScript | 0x143922908 | `return this+0x28`（= side^1）→ **ClientServer 侧全部 40 实体 isClientType=1，ServerOnly=0** |
| DynamicComponentsDescriptionHasPythonScript | 0x143922930 | Distribution/Client 有则用之；否则 `scripts/client/<名>.py/.pyc/.pyo/.pyd` 存在（FUN_142a8e660+FUN_142a8fc10+FUN_142a92970，四扩展名序试） |
| SpaceDescriptionHasPythonScript | 0x143922958 | FUN_140355960 = `b0 01 c3`（mov al,1; ret）**恒真** |
RTTI 反查方法：COL 用 32 位 RVA（非 64 位 VA）——v13 修正了 v9-v11 的反查盲区。

### 9.5 records 集合与顺序（digest 遍历集，FUN_142a9b410 从数组头全量 0x328 步长）
```
records = [GeneralSpaceData（spaces.xml 唯一子节点；space_defs/GeneralSpaceData.def：
           Implements SpaceRecording(recorderFragment 非 CS)；CS 属性 3 个——itemsVisibilityMask
           (UINT32)/environment(STRING)/replicableHash(UINT64)，均带 <Exposed> 子段]
         + 40 ClientServer 实体（entities.xml 序，各挂 §9.2 静态组件）
         + 110 唯一 DynamicComponents 中 107 个（排除 ExtendedSPG/EnemyShotPredictorController/
           ArenaVehiclesInfo——无 scripts/client 脚本；DynamicComponents 列表有 3 个重名
           (SecondaryGunComponent/NetworkReplicationPointComponent/NetworkVehicleHierarchy×2)被 FNV 去重）
         ] 共 148 条
```
- space 属性规则（param_5=1）：跳过 Flags（dataFlags=0）+ `<Exposed>` 子段→OWN_CLIENT(0x4)；实体/组件（param_5=2）：读 Flags + 跳过 Exposed 规则。
- 组件记录解析：Parent 链（NextClipsReloader→GunReloadBoost）+ Implements（component_defs/interfaces，接口名在子节点值：ShotsReceiver 等 3 个→ReplicableComponent、2 个→SecondaryGunActivatorInterface）+ `<Volatile><Properties>` 标记（仅 GunMarkerComponent.gunMarker=0x01）。

### 9.6 方法层 fork 语义（v13 新解，与 vanilla 的差异汇总）
- 域常量：CLIENT=0/CELL=1/BASE=2（FUN_142a91030 三调用实证）+ bit3(0x8)=跳过 Args 读。
- flags 字节 = 域位 | exposed 位（CELL+ALL_CLIENTS→0x4；OWN_CLIENT→0x8；空→0xC；BASE+ALL_CLIENTS→报错）| **0x10=AllowUnsafeData**（11 处全在 client 方法→被过滤→无效）；HasReliableRetry/IsImmediate/IgnoreIfNoClient→独立字节；ReplayExposureLevel→+0xdc 枚举；version→+0x78 u16；scope→+0x74——均不进 digest。
- **client 方法禁带 `<Exposed>`**（报错）→ flags 恒 0 → onMethod 通用过滤出局（§5 增量④）。
- 方法 varLen 前缀永不喂入（isForClient=域==CLIENT，而 client 方法已出局）。
- returnValues：全 def 集仅 5 个 Base 方法有（Account×3/Avatar×1/BattleResultProcessor×1），全部无 Exposed → 0 字节（§7.3 增量②的「def 无 ReturnValues」表述修正为「有但全不喂」）。
- 挂载组件方法贡献：仅 Avatar 的 3 个 exposed cell 方法（confirmVehicleSelection/chooseVehicle/switchSetup）；PoiTeamInfoComponent 的 3 个 client 方法被增量④过滤。

## 10. [v14 · 2026-09-24] FeatureExtension 体系 —— records 集合的缺失维度（本轮最大发现）

### 10.1 体系结构（decomp + wot-src 镜像 + paths.xml 三方实证）
- **FeatureExtensionManager（FUN_142a7fae0 单例）**：首次访问时内联执行 FUN_142a7fbb0 = FeatureExtensionMap::parse——枚举文件系统根的全部一级目录，逐个检查 `<dir>/extension.xml` 存在性（FUN_142b819b0），读文件（FUN_142b79900）→ **readBool("IsEnabled")，false 则跳过**（错误串 "Extension %s is disabled in config file."）→ 读 FeatureName 注册 → 收集 `<Components><StaticComponents>` 子名到向量（挂载索引 Part b 的数据源）→ 读 `<cgf><script><module>`（cgf 模块注册）。
- **真实客户端实证**：wot-src 镜像 `sources/res/` 下有 18 个扩展目录（battle_modifiers/battle_royale/comp7/comp7_core/comp7_light/content_exclude/event_platform/fall_tanks/frontline/fun_random/in_battle_achievements/la_pinger/last_stand/open_bundle/resource_well/server_side_replay/story_mode/white_tiger），**全部 IsEnabled=true**；`sources/paths.xml` 列有对应的 18 个 `res/packages/<ext>.pkg`（type="sandbox,sd,hd"，0x30 包证实本客户端为 sd 型 → 全部挂载）；pkg 在 paths.xml 中的出现顺序恰为字母序。
- **v13 勘误**：「② FeatureExtensionManager 单例（扫 extension.xml；干净安装=空树）」的"空树"判断错误——当时只在 scripts 树（scripts.7z=scripts.pkg 内容）中找过 extension.xml，未查 res/ 一级目录与 pkg 体系。

### 10.2 三个扩展消费点（FUN_142a98830 = EntityDescriptionMap::parse 全序）
```
① parseSpaces（records[0]）
② FeatureExtensionManager 单例（惰性扫描，18 个全 enabled）
③ 挂载索引 FUN_142a971a0：
     Part a：components.xml <StaticComponents>（16 名）→ scripts/component_defs/<N>.def → ofEntity 边
     Part b：逐扩展（列表序）逐 static 名 → <ext>/scripts/component_defs/<N>.def（尾部拼 ".def" 实锤
             0x6665642e）→ ofEntity 边（在 Part a 之后追加 → 同实体名的挂载序 = Part a 先、扩展后）
④ ClientServerEntities（40 实体，dir=""）
⑤ 扩展循环#1：逐扩展重读 extension.xml → 打开根 "Entities"(0x143920128) 子段
   → FUN_142a996e0（ClientServerEntities 分支，dir=<扩展名>）
   → def 路径 = <ext>/scripts/entity_defs/<E>.def（FUN_142a8e790 mode=1 的 dir 前缀分支）
⑥ ServerOnlyEntities（entities.xml 无此段 → 跳过；扩展的 SO 实体在客户端同样不解析）
⑦ 旧格式兼容 FUN_142a99bc0（no-op）
⑧ parseDynamicComponents：components.xml <DynamicComponents>（110 名 FNV 去重→107）
⑨ 扩展循环#2：逐扩展重读 extension.xml → 打开根 "Components"(0x1439200e8) → 其 "DynamicComponents"
   子段 → FUN_142a994c0（mode=7，dir=<扩展名>）→ def 路径 = <ext>/scripts/component_defs/<D>.def
⑩ 收尾：type!=7 的记录做 max 属性数等统计（不进 digest）
```
- **记录数组全貌**：`[space][40 实体][扩展实体（扩展列表序）][107 dyncomp][扩展 dyncomp（扩展列表序）]` ≈ 1+40+10+107+≤171 ≈ **~318 条**（v13 模型仅 148 条）。
- **def 加载失败语义（FUN_142a99f30）**：FUN_142a8ee00 返回空 → 清理后 goto LAB_142a9b067 → **返回 false**（该批次整体中止），但 EntityDescriptionMap::parse 继续执行其余步骤（bVar8 &= …），digest 仍会计算——即"缺 def 的扩展批次"会让整批记录缺席而非崩溃。
- **decider 与 dir 前缀的全局一致性**：FUN_142a8e790 的 mode 1/2/3/5/7 分支均支持 `<dir>/scripts/<子目录>` 前缀；dyncomp decider 的脚本检查（FUN_142a8e660→FUN_142a8fc10）同样吃 dir——扩展 dyncomp 判 `<ext>/scripts/client/<D>.py|.pyc|.pyo|.pyd` 存在性（镜像 loose 树有这些 .py；12 个组件在镜像中无 py → decider 排除候选，pkg 到货后复核）。
- **FNV 去重是每次 FUN_142a99f30 调用独立的**（局部哈希集）→ 跨批次同名（如扩展 dyncomp 与主树 dyncomp 同名）不会被去重，会双记录入数组（名字 map 亦双条目）。

### 10.3 扩展清单（scripts/ext_inventory.py 提取，download/ext_inventory.json）
| # | 扩展 | static | dynamic | CS实体 | 镜像缺py |
|---|---|---|---|---|---|
| 1 | battle_modifiers | 0 | 0 | 0 | 0 |
| 2 | battle_royale | 3 | 34 | 6 (Mine/Loot/Placement/InfluenceZone/BattleRoyaleRadio/ThunderStrike) | 4 |
| 3 | comp7 | 3 | 2 | 1 (Comp7Lighting) | 0 |
| 4 | comp7_core | 0 | 7 | 1 (ApplicationPoint) | 0 |
| 5 | comp7_light | 2 | 2 | 0 | 0 |
| 6 | content_exclude | 0 | 0 | 0 | 0 |
| 7 | event_platform | 3 | 0 | 0 | 0 |
| 8 | fall_tanks | 1 | 3 | 0 | 0 |
| 9 | frontline | 6 | 9 | 0 | 3 |
| 10 | fun_random | 3 | 0 | 0 | 0 |
| 11 | in_battle_achievements | 1 | 2 | 0 | 1 |
| 12 | la_pinger | 1 | 0 | 0 | 0 |
| 13 | last_stand | 5 | 66 | 0 | 3 |
| 14 | open_bundle | 1 | 0 | 0 | 0 |
| 15 | resource_well | 1 | 0 | 0 | 0 |
| 16 | server_side_replay | 1 | 0 | 1 (ReplayAccount) | 0 |
| 17 | story_mode | 4 | 21 | 1 | 0 |
| 18 | white_tiger | 4 | 25 | 0 | 0 |
- 合计：39 static 挂载边 + 171 dynamic + 10 CS 实体（SO 实体 16 个客户端不解析）。本回放为 SERVER_REPLAY 模式（bonus cap），server_side_replay 扩展启用——与 ReplayAccount 的存在自洽。

### 10.4 与既有验证的自洽性
- 0x05 创建块 n∈{3,6,7,18,28,29,40} 全 ≤40：本场随机战斗未创建扩展实体，无矛盾（且 n=7=Vehicle/n=6=AreaDestructibles/n=40=NetworkEntity 与数组布局吻合）。
- csi 表 40/40：csi 是 per-record 编号，扩展记录不影响 40 实体的 csi 值——对账依然成立。
- 25 组合消融全负：矩阵从未触及"扩展记录"维度——与"唯一剩余自由度=扩展内容"的判定一致。
- 扩展 def 的存在性间接证据：①游戏支持 BR/frontline 等模式，客户端必须有这些实体 def 才能创建客户端实体；②引擎专门实现了 `<ext>/scripts/{entity_defs,component_defs}` 路径与挂载/循环代码；③镜像扩展树含全部 client .py（decider 设计目标）；④paths.xml 专门列出 18 个扩展 pkg。**但 def 文件本体不在任何现有资源**（scripts.7z=主 pkg；wot-src 镜像无任何 .def）。

## 附录 A：资产恢复终态（v12 结算）
- 重置损失已 **100% 恢复**：`replay.jsonl✓ / decomp.zip✓(dec.7z 分卷) / scripts.7z✓(md5 3291a197…) / BigWorld tar.gz✓ / tools/bwxml_decode.py✓ / csi_tables_v8.json✓(md5 5ac32922…)`；`scripts/digest_fork.py` 功能已被 digest_fork_test.py 覆盖。
- **v12 新寻回**（FengY233/test 仓库）：`csi_tables_v8.json`（重置丢失的权威表原件）、`WoT回放解析交付包_v7.zip`（正式交付包 V7 全套 16 文件）、`会话记录.txt`（253KB 全程对话记录，结论对账依据）、重置前原版 findings.md（v8 全细节，含 §0 状态速览——细节可向该版本回溯）。
- 恢复渠道：`https://github.com/FengY233/test`（14 文件，gh_fetch.py 全量拉取 + md5 校验）。

## 8. 交付包沿革（v13 登记）
- **v1–v7**（正式报告线，官方下载渠道可取）：报告 MD/PDF + xlsx + json + 8 图表 + 封面 + 审计。v7=无服务器资料收官版。
- **v8**（过渡包，仅脚本集）：findings_bundle_v8.zip = findings + worklog + 18 脚本（非报告形态，已被 v9 取代）。
- **v9**（FengY233/test 官方渠道）：`WoT回放解析交付包_v9.zip` —— V7 全套 16 文件内容升级（报告 +§17/§18、xlsx 17 表、json +2 段、审计 v9、README v9）+ findings.md（v12）与 csi_tables_v8.json；57 页 PDF。
- **v10（本轮，最新）**：V9 结构 + **worklog.md（用户指令新增）** + findings.md v13 + digest_fork_v2/diag 脚本 + defparse 修复。

## 附录 D：v11 证据存根
- exe：`/tmp/wotexe_x/WorldOfTanks.exe`（v13 注：exe 在隐藏区 /tmp，sha256 校验同前）（sha256=2ec886a8… ✓ manifest 权威值）。本机直读脚本：`scripts/dat_verify.py`（DAT 双值）、`scripts/vtable_resolve.py`（vptr=0x1439230B8 机器码铁证 + vtable 区直读）、`scripts/visitor_vtables.py`（visitor 双表 + FUN_142a9b6e0 反汇编）、`scripts/datatype_vtables2.py`（47 DataType vtable RTTI 全链）、`scripts/read_feeders.py`（全部 addToMD5 批量导出）。
- decomp 关键坐标：digest 顶层 c_1402c13f0.c:143725（EntityType::init）；栈哈希器 c_1428d1e40.c:368056；visitor 簇 367936–368300；walker FUN_142a93420@361589；onProperty/onMethod FUN_142a9b870/810@368194/368174；属性/方法正文 FUN_142a894e0@353568 / FUN_142aa17d0@372497；Member 前缀 FUN_142abc050@394282；args 列表 FUN_142abcbc0@394897；parseVolatileProperties FUN_142a923c0@360730；parseInterface FUN_142a90940@359328；parseImplements FUN_142a83da0@349241；组件子描述 FUN_142a8d480@356666；map 级挂载 FUN_142a99f30@366955（833 行待细读）；MD5 槽函数群 c_1402c13f0.c:211996–212175。
- def 侧：`repos/scripts_x/scripts/{entity_defs(41+interfaces 61), component_defs(127), components.xml, spaces.xml, entities.xml, alias.xml}`；组件统计脚本内嵌于 `scripts/digest_fork_test.py`（185 属性/3B/41C/28Cl；ofEntity 79 个）。
- 实算：`scripts/digest_fork_test.py`（A/B/C 三变体 + 组件解析/挂载框架，可直接扩展变体）。

## 附录 B：v9 证据存根
- 用户导出（Ghidra，只读未改码）：vtable 15 槽原始字节（0x1439230B0 起 136 字节）、槽函数伪代码引用、RTTI 邻接类。
- `scripts/md5calc_ref.py`：RFC1321 自测 507 项 + 槽位语义 6 项全通过；T 表锚点 12 常量位置精确；0x57cfb9ed 非 MD5 常量。

## 附录 C：v10 证据存根
- `repos/scripts.7z` md5=3291a19748a129bf8e16cd5983fda4c4（=原件）；wot-src `.publication.json` commit_subject=2.4.0.0 #942（wot-cn sd）。
- `scripts/bwxml.py`：PackedSection 解码（2881 文件实测；blob=Base64 回环实证 6 例）；`scripts/defparse.py`：vanilla digest 全链（40 实体/306 CS 与 v8 双吻合；锚点 1/16 命中、33/34 差 5 且数学闭合）。
- vanilla 源码依据：entity_description_map.cpp L287-289/L608-622、entity_description.cpp L1740-1802/L381-444、member_description.cpp L281-296、data_description.cpp L415-439（v11 复核为 431-439）、method_description.cpp L1294-1302、method_args.cpp L372-382、data_types/*（md5String 全表）、packed_section.hpp/cpp。

## 附录 E：v13 证据存根
- **资源位置（本轮重组）**：分析资源已全部移至用户不可见区（根治内存撑爆）：`/tmp/wot/gh_test`（FengY233/test 14 文件）+ `/tmp/my-project/repos`（decomp 356M / scripts_x 192M / wot-src 653M / BigWorld 1.4G + tar×2，root 属主只读）；可见区仅 29MB 交付物。worklog Task 1–17 已据 会话记录.txt 重建。
- **decomp 新坐标（本轮白盒）**：EntityDescriptionMap::parse FUN_142a98830@365735；parseSpaces FUN_142a9b170@367788；createEntityTypeToComponentSectionsMap FUN_142a971a0@364520（静态装载器 FUN_142a96400@363757）；parseEntitiesBySide FUN_142a996e0@366519；parseDynamicComponents FUN_142a994c0@366406；旧格式兼容 FUN_142a99bc0@366790；通用记录构造 FUN_142a99f30@366955（833 行已全读）；parseFromSectionList FUN_142a900a0@358890；Parent 解析 FUN_142a90f20@359596 + FUN_142a8ff40@358825；子描述构造 FUN_142a8d480@356666（type=6）；方法解析 FUN_142aa1fa0@372941（域常量/Exposed/AllowUnsafeData=0x10/version/scope/ReplayExposureLevel）；方法列表解析 FUN_142aa7540@377206（+0x100=cell/+0x180=base/+0x200=client）；parseProperties FUN_142a91b20@360236（param_5=(type≠2)+1：space=1 跳 Flags+启用 Exposed 规则，其余=2）；DataDescription::parse FUN_142a8a1f0@354356（Flags 表@0x144341530：CELL_PRIVATE=0/CELL_PUBLIC=1/OTHER_CLIENTS=3/OWN_CLIENT=4/BASE=8/BASE_AND_CLIENT=0xC/CELL_PUBLIC_AND_OWN=5/ALL_CLIENTS=7/EDITOR_ONLY=0x40；Backupable=0x200/AllowUnsafeData=0x400/Identifier=0x80 均在 0x5F 掩码外）；模式→目录 FUN_142a8e790@357668；脚本存在性 FUN_142a8e660@357596（.py/.pyc/.pyo/.pyd @0x1435d5a04 区）；FeatureExtensionManager FUN_142a7fae0@345742（"extension.xml"）。
- **decider vtable 解析脚本**：`/tmp/wot/decider_final.py`（COL 32 位 RVA 反查）；**判定函数**：FUN_140b99eb0@381337（this+0x28）、FUN_142a8e1f0@357365（脚本检查）、FUN_140355960@94530（b0 01 c3 恒真）。
- **csi 修复与对账**：defparse.py FIXED_DICT streamSize 去 AllowNone 罚则 → 40/40 实体 csi+streamSize+flags&0x5F 三要素对 csi_tables_v8.json 全对账（对账脚本本轮内联，Vehicle 变长区 25-49 全对）。
- **实算**：`scripts/digest_fork_v2.py`（148 记录完整模型 → E2E9EBE2…）、`scripts/digest_fork_diag.py`（24 组合矩阵）、+内联第 25 组合（client 方法原始 flags）——全部 ≠ 目标。
- **vanilla 源码对照**：fixed_dict_data_type.cpp:441（streamSize_(allowNone?-1:0)——fork 改动点）、:769-779；member_description.cpp:281-296（isForClient 门控 varLen）；method_description.cpp:335-470（Exposed/Args/ReturnValues）、:1289-1303（setExposedMsgID）；entity_method_descriptions.cpp:197-215（exposed 排序+range）；entity_description.cpp:831-886（csi 排序）、:1740-1802（addToMD5）。

## 附录 F：v14 证据存根
- **本轮字节级复核（全部与模型一致，负结果登记）**：
  - walker FUN_142a93420 重读：onMethod 的 index=walker 第三参计数器；client 域计数器无条件++（但全被过滤→无关）；base/cell 域计数器仅对通过 (flags&0xC) 者递增 → index=域内 exposed 连续编号（自有+组件接续）。
  - onMethod FUN_142a9b810 / onProperty FUN_142a9b870 重读：csi 读 prop+0x9c（u32）；过滤掩码 0x106 确认。
  - ExposedForReplay：DataDescription::parse 读两处（非 CS 路径 default=0 + CS 路径 default=isOtherClients 即 bit1），置 dataFlags bit8(0x100)；全 def 树 32 处扫描：29 处本就带 client 位、3 处为 space 记录（经 <Exposed>→0x4 已进模型）→ 对 digest 零影响（0x100 在 0x5F 外、过滤位已过）。
  - DT 层：24 个 addToMD5 feeder 全量导出（/tmp/wot/feeders_v11.txt，read_feeders.py 路径已改 /tmp/my-project/repos）+ exe 直读 DAT 常量（scripts/dat_strings2.py）：DAT_143676a60="Int"/DAT_143928948="Uint"/DAT_1437d083c="Blob"/DAT_1437d0d1c="User"（slot13=含 NUL 喂入）、DAT_1435d2d24="name"/DAT_1435e92e4="size"（label 0 字节）——与 defparse 逐字节一致；Sequence 的 dbLen 条件 0<dbLen、FixedDict 的 [!inited‖hasCustom] 模块/实例喂入（全树 0 个自定义类/USER 类型 → 恒 0 字节）一致。
  - parseProperties FUN_142a91b20 全读：type==3 报错；type==6 用记录名做组件名；type==7 置标记；param_5=(type≠2)+1；EDITOR_ONLY(bit6) 属性跳过；同名覆盖=原位替换+保留旧 csi（读旧+0x9c）；csi=cs_props.size()+base(+0xf8)（等效模型的多轮 allocate_csi，已证稳定排序等价）。
  - DataDescription::parse FUN_142a8a1f0：Flags 表查表（param_5 bit0=跳过→space dataFlags=0）；空 <Exposed/> 且 (param_5&2)==0 → |=0x4（space 专属规则实锤）；MemberDescription::parse FUN_142abc1e0 的 isForClient=param_4 ← DataDescription::parse 传 (flags&0x106)!=0（与 vanilla data_description.cpp:320 逐字一致）；<tags> 段入 +0xb8 map（不进 digest）。
  - parseMethods FUN_142a91030 全读：type∈{1,6} 三域；type==7 禁 BaseMethods（报错）→ 仅 Cell+Client；type==3 服务型；列表头 +0x100(cell)/+0x180(base)/+0x200(client)，vector 在 +0x18 处（= walker 的 +0x118/+0x198/+0x218 ✓）；"Methods"/"Events" 标签拒绝。
  - 方法 Exposed 语义精读：CELL+ALL_CLIENTS→0x4；OWN_CLIENT→0x8；**空 <Exposed/>→0xC**；BASE+ALL_CLIENTS→报错；client+任意 Exposed→报错（"Unable to use <Exposed> tag in client method"）。
  - FUN_142a99f30 重读：FNV-1a 去重=首遇序（子节点序），记录索引=base+i 顺序填入；**equal_range 仅 mode==1**（实体）→ 挂载只发生在实体批次；def 加载失败→批次中止返回 false。
  - space/挂载组件/ReturnValues 内容核查：GeneralSpaceData+SpaceRecording 无方法段；6 个静态挂载组件全扁平（无 Parent/Implements，Avatar 3 exposed cell + AccountFairplay 0 + Poi 3 client）；ReturnValues 全树恰 5 个（Account×3/Avatar×1/BattleResultProcessor×1 接口）全非 exposed → 0 字节；component_defs 3 个 Base 方法全在静态组件（挂 Arena——非记录集）→ 0 贡献。
  - 实体/组件 def 格式：Avatar 等用旧式 <Arg>（直接子节点）、组件用新式 <Args>（具名子节点）——defparse 两式均处理 ✓。
- **FeatureExtension 证据坐标**：FeatureExtensionMap::parse=FUN_142a7fbb0@345786（IsEnabled 过滤+FeatureName+StaticComponents 向量收集+cgf/script 注册）；目录枚举 FUN_142b822d0@153333（FileSystem 根）+ 挂载根收集 FUN_142b87610@157392（mount+0x88==1 过滤）+ FUN_14037f0a0@127602（vector insert，非 sort——顺序=挂载序+枚举序，具体待 def 到货后枚举验证）；扩展消费点三处见 §10.2（"Entities"=0x143920128 / "Components"=0x1439200e8 / "DynamicComponents"=0x143920110 / "StaticComponents"=0x1439200f8 / ".def"=0x6665642e 直写）；def 路径构造 FUN_142a8e790@357668（mode 1/2/3/5/7 的 <dir>/scripts/<子目录> 前缀分支）；decider 脚本检查 FUN_142a8e660@357596→FUN_142a8fc10；wot-src 镜像 res/ 18 扩展目录 + paths.xml 18 pkg（字母序）；泄漏构建路径 "D:\BuildAgent\work\wotd_ci_release\wc\programming\shared_libs\entitydef\entity_description.cpp"（FUN_142a8e740 内 ERROR_MSG，证实 fork 把 vanilla lib/entitydef 重组为 shared_libs/entitydef）。
- **新脚本**：`scripts/dat_strings2.py`（exe DAT 直读）、`scripts/ext_inventory.py`（扩展清单→download/ext_inventory.json）、`scripts/read_feeders.py`（路径修复 /tmp/my-project/repos）。
- **待用户供给**：18 个扩展 pkg 的 scripts/{entity_defs,component_defs}（含 interfaces）+ scripts/client 清单（详见 §6 执行清单）。

## 11. [v15 · 2026-09-24] 扩展 def 到货 → 全模型实算 + u16 真 bug 修复 —— 0x3D 进入"全层汇编级验证"时代

### 11.1 用户材料核验（wot24_ext_defs.zip，GitHub FengY233/test）
- 包结构：18 扩展目录（entity/component/arena_defs 解码 XML + _raw 原始 BWXML + extension.xml + client_files.txt）+ MANIFEST.tsv(242 行) + INDEX.tsv + README + tools×4（用户侧 AI 的导出器）
- `scripts/verify_ext_pkg.py` 十项对账 95 PASS / 0 FAIL：C1 目录 18/18；C2 component_defs 210 == static(39)∪dynamic(171)；C3 entity_defs 10 == cs_entities（so_entities 16 个正确缺席——extension.xml ServerOnlyEntities 有名单但服务器侧 def 不随客户端发行）；C4 IsEnabled 全 true；C5 StaticComponents 名单 18/18；C7 dyncomp 脚本真值（client_files.txt 精确路径）与镜像推断完全吻合（BR 4/前线 3/IBA 1/背水 3 无脚本）；C8 xml↔_raw 242/242；C10 MANIFEST 字节数全对
- `scripts/ext_raw_decode_test.py`：自研 vanilla 版解码器独立消费 242/242；`scripts/ext_facts.py` 从 _raw 独立提取全部建模事实（不信 README）
- README 独立复核：3 处跨包 Parent ✓（FallTanksRespawnComponent→VehicleRespawnComponent / SPGZone→AreaOfEffect / SMVehicleRespawnComponent→VehicleRespawnComponent）；零接口引用 ✓；white_tiger 小写 vehicle ofEntity 原样 ✓

### 11.2 模型修正（推翻 v14 两处）
- **✗ 推翻「39 static 挂载边进 digest」**：挂载索引 Part b（else 分支）打开的是 extension.xml **根级 <ExternalComponents>**——18 个扩展全部为空/缺失 → 0 条扩展挂载边。v14 的「Part b 逐 static 名载 <ext>/scripts/component_defs/<N>.def（尾部拼 .def 实锤 0x6665642e）」系**误归因**：0x6665642e 写点在 Part a（主 components.xml 静态装载器 FUN_142a96400），行号 fun_142a971a0_full.c:377 实锤。ExternalComponents 子节点=内联组件定义（须自带 ofEntity 子段，缺失报 "no <ofEntity> section found in external component %s, file %s"）
- **✗ 修正「pkg 顺序恰为字母序」的依据**：paths.xml 整体并非字母序（shared_content part3<part2<part1），但 18 扩展 pkg 在其中的出现序恰为字母序；且管理器容器为 **FeatureName 键的有序 map**（FUN_140313020 拷贝 FeatureName 为键 + memcmp 插入比较 + isnil 树遍历）→ 迭代序=字母序 双重成立
- 机器码裁决（disas_call_sites.py）：扩展循环#1 调用 FUN_142a996e0 传入 **同一个挂载 multimap**（r8=[rsp+0x60]）+ **dir=rbx+0x80**（FeatureExtension 对象内目录名串）+ **side=0 仅 ClientServer**（[rsp+0x20]=0）——Ghidra 反编译丢失了参数，机器码没有说谎；扩展 SO 实体客户端永不解析
- 记录集 = 1 space + 40 主实体 + 10 扩展实体 + 107 主 dyncomp + 160 扩展 dyncomp = **318**；FUN_142a99f30 的全局名字 map 去重（pvVar7==local_1e0 才追加）——全部名字组合重叠检查为空，无去重影响

### 11.3 ★ 本轮最大发现：方法 flags 是 u16 不是 u8（v9-v13 集体漏读）
- **证据链**：方法体喂入器 FUN_142aa17d0（disas 全文）第 4 步 `(calc+0x50)(calc,"flags",method+0x70)` = calculator **slot10**；MD5Calculator vtable(0x1439230B8) slot10=0x1403e8260 = **u16 喂入器**（`mov word ptr [rsp+0x40], r8w; mov r9d,2`）；调用点 `movzx r8d, byte ptr [rdi+0x70]` 零扩展 → 实喂 2 字节 LE **[flags, 0x00]**
- v9 的槽位表判定"记录中无 u16 调用"是因为只追了属性/名字喂入器，漏了方法体喂入器的 slot10；v11「方法：…[flags u8]…」自此勘误
- 影响面：全部喂入方法（主 134 + 扩展 29 = 163 个），每个多 1 字节 0x00——**主模型自 v13 起从未命中由此解释**
- 修复：defparse.MD5.append_uint16 + digest_fork_v2.method_to_md5 改 append_uint16(m.flags)

### 11.4 全层汇编级复核（本轮二轮验证，全部一致）
- 属性体 FUN_142a894e0：[slot3 名字标签 no-op]→FUN_142abc050[varLen u32 条件(slot8)][名字 slot12 无NUL]→[flags&0x5F u32(slot5)]→[isVolatile u8(slot11)]→[类型 slot15]——与 v2 喂序逐字节一致；slot3/4=0x1402f7290=`ret` 纯 no-op；slot12=0x1403e8210 按串长度喂（无 NUL）；slot14=0x1402ed600=`lea rax,[rcx+8]; ret` 无副作用
- 方法体 FUN_142aa17d0：[slot3 no-op]→FUN_142abc050[varLen 仅 client 域(+0x55)][名字]→[flags **u16** slot10]→args 喂入器 FUN_142abcbc0（仅类型、参数名 slot3 no-op、空集 0 字节）→returnValues 同构（FLRespawnComponent.updateVehicleOnRespawn=BOOL 但非 exposed → 0 字节）→[index i32 由 onMethod 补]
- walker FUN_142a93420：域序 [+0x218=CLIENT 全量无预过滤][+0x198=BASE 预过滤][+0x118=CELL 预过滤]（parse 侧 Base→+0x180 wrapper/Cell→+0x100/Client→+0x200，向量在 wrapper+0x18）；onDomain 参数 2/1/4 = visitor 枚举（1="baseMethods"/2="clientMethods"/4="cellMethods"，FUN_142a9b750 标签→slot3 no-op 0 字节）；client 方法 flags 恒 0（FUN_142aa1fa0 无隐式 exposed 位）→ onMethod 的 (flags&0xC) 全灭；每域计数器独立从 0 起、跨自有+子描述连续、仅对通过者递增
- decider 三槽（+0x85/86/87=slot0/1/2）汇编：Entity=读对象+0x28 字节（side^1，恒 1）；Dynamic=分发码(1=声明/2=缺省)或脚本存在；Space=`mov al,1; ret` 恒真
- VLH 默认=1（FUN_142abc1e0: readInt("VariableLengthHeaderSize", 1)）→ 缺省不喂；ARRAY size 默认=0=变长（vanilla sequence_data_type.cpp 源码复核 + size_==0 即 trust DataSource）
- flags 表 @0x144341530 九项 exe 直读：CELL_PRIVATE=0/CELL_PUBLIC=1/OTHER_CLIENTS=3/OWN_CLIENT=4/BASE=8/BASE_AND_CLIENT=0xC/CELL_PUBLIC_AND_OWN=5/ALL_CLIENTS=7/EDITOR_ONLY=0x40——与 defparse 完全一致
- digest 顶层：FUN_142a9b640(MD5Calculator init→回调→final)→FUN_142a9b5b0(slot3(0,0) no-op→FUN_142a9b410 全量 0x328 步长遍历)——无版本/计数前后缀；EntityType::init(c_1402c13f0:143725)确认 parse→digest 同一全局 map(DAT_14483e050) 且顺序执行
- 静态子描述属性不进父记录：csi_tables_v8 权威表 Avatar=28 条/TeamInfo=1 条均无组件属性（0x05 块回放验证过）→ 子描述仅方法进 digest 维持
- 29 个扩展 exposed 方法对账 = 27 自有 + 2 继承（FallTanksRespawnComponent/SMVehicleRespawnComponent 自 VehicleRespawnComponent.chooseSpawnGroup）；story_mode 2 个静态组件（StoryModeAccountComponent/StoryModeAvatarComponent）的 3 个 exposed 方法按修正模型不挂载不喂

### 11.5 实算现状与剩余自由度
- 主消融（无扩展）= FD632272DB2A3B151A2AA1D6EB1B8E39（v13 的 E2E9EBE2 + u16 修复后）；全量 318 记录 = **20E4276EECFABCE2D667889230F03CD1** ≠ 目标 5DF886F75E73B33CFF9D87FB9C69389C
- digest_variants.py 十变体全负（扩展位置/逆序/含无脚本/消融组合）
- vanilla 基线漂移说明：defparse.entity_digest()=EBE966BE（v13 AllowNone 定长化修复的预期效果，非回归）
- **全部结构层已汇编级穷尽验证** → 剩余偏差指向数据同期性：①回放录制(09-11 18:01)与扩展导出(09-24)之间客户端是否微更新（exe FileVersion=2.4.0.10161 #2616763，回放 0x2D="17, 1, 0, 5" 来源未定位，无法排除）；②res_mods 是否有改 entityDefs 的 mod；③主树（与回放数据 100% 自洽：csi 40/40 + 0x05 块 + 方法锚点）与扩展 pkg 是否同期
- 新脚本：verify_ext_pkg / ext_raw_decode_test / ext_facts / disas_call_sites / disas_full_flow / disas_ext_key / digest_fork_v3 / digest_variants；新数据：download/ext_facts.json
