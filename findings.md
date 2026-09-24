# WoT 回放逆向 · 已确认结论登记册（findings）

> **定位**：本册只收录**已经过验证或交叉实证**的结论，每条附证据与状态；未经证实的推测不进本册（只进 worklog 流水）。
> **登记制度**（2026-09-24 用户指令）：后续调查出的成果，只要确认没问题，**及时写入本文件**，并在附录更新记录中留痕。
> **副本同步**：主副本 `/home/z/my-project/findings.md`；每次更新后同步至 `upload/findings.md`（防快照回退）与 `download/findings.md`（用户可见）。
> **关联文档**：`worklog.md`（全过程流水账，Task 1–17）；`download/WoT回放完全解析报告.md / .pdf`（正式报告，现 v7 / 24 页，尚未吸收 v8 内容）。
> **对象回放**：`20260911_1801_ussr-R52_Object_261_37_caucasus.wotreplay`（WoT 2.4.0.0 CN，37_caucasus，15v15 随机战，261 工程火炮视角，队 2 全歼胜）。

---

## 0. 状态速览（截至 2026-09-24）

| # | 领域 | 状态 | 一句话结论 | 详见 |
|---|---|---|---|---|
| 1 | 容器/加密/包流 | ✅ 通透 | magic 0x11343212；2 JSON 块；主流 Blowfish-ECB+前向异或→zlib；156,482 包 100% 消费 | §4.1 |
| 2 | 38 种包类型 | ✅ 全命名 | 37 内容类型 + 0xFFFFFFFF 终止符，每种都有确定名字与语义 | §4.2 |
| 3 | 时钟本质 | ✅ 定论 | clock = float32 秒；回放 = 正常战斗 1x 实时录制（v3） | §4.3 |
| 4 | 载荷语义覆盖 | ✅ 99.48% | A 级 99.48% / B 级 0.52%（字段级命名残留） | §4.5 |
| 5 | 0x07/0x24 属性确名 | ✅ 闭合 | csi 权威表：40 实体 306 条 CS 属性，14 锚点验证（v8） | §1 |
| 6 | 0x3D entityDefs 摘要 | ◐ 98% | 算法终版结构全提取+实现（§3.6），84 组合暴力未命中，差单一细节；验证神器就绪（§3.7） | §2.1 / §3 |
| 7 | 0x32/0x37 视觉节点名 | ○ 开放 | 材料 cgf_names.xml 在位（1,921B），未展开 | §6 |

---

## 1. v8 核心成果（Task 16）：csi 体系与 0x07/0x24 收口 ✅

**结论**：回放 0x07（sliceEntityProperty）/ 0x24（nestedEntityProperty）块中的属性号 = **csi（clientServerFullIndex）**。csi 表可从服务器 .def 精确重建，与全部实测锚点吻合。v7 遗留的"0x07 属性 1/16/33/34 确名"就此闭合：**1=isStrafing、16=avatarID、33=perkEffects、34=perks**。

### 1.1 csi 生成规则（BigWorld 源码逐函数考证 + 服务器 .def 实算双向验证）

1. **累积序**：Parent 链 → Implements 按声明序（各自递归，不跟随接口的 Parent）→ 自有 Properties；同名属性先到先得、覆盖保留原位。
2. **CS 判定**：`flags & 0x106`（OTHER_CLIENT 0x02 | OWN_CLIENT 0x04 | REPLAY 0x100）。
3. **csi 分配**（parseProperties 末尾 allocateClientServerFullIndexes）：对 CS 属性做**稳定排序**——定长属性按 streamSize 升序在前，变长属性按 VLH（变长头）字节数升序在后；排序位次即 csi。
4. **streamSize 语义**：定长 = 类型宽度（Int/Uint 1/2/4/8、Float 4 / Float64 8、Vector 4n、MailBox 12、序列 size×元素、FixedDict 字段和，任一 -1 则 -1）；变长 = -varLenHeaderSize。
5. **方法侧规则**（digest 复算要用）：Base→Cell→Client 三组件各自按名去重、先到先得；Client 方法自动 setExposedToAllClients（flags_=0x04）；Exposed 语义 ''→0xC / OWN_CLIENT→0x8 / ALL_CLIENTS→0x4（仅 CELL）；ExposedForReplay 缺省 = isOtherClientData。

### 1.2 锚点验证（2026-09-24 全量复验通过，14/14）

- **Vehicle（12）**：csi0=burnoutLevel、1=isStrafing、4=siegeState、13=gunAnglesPacked、14=health、15=engineMode、16=avatarID、22=wheelsState、23=stunInfo、24=arenaUniqueID、33=perkEffects、34=perks
- **Avatar（2）**：csi10=ownVehicleGear、19=ownVehicleAuxPhysicsData
- **行为学佐证**：csi16=avatarID 死亡复位 4B 零（Avatar 脱离载体）；csi33=perkEffects 死亡前清空（空数组 1B 零）；csi23=stunInfo 定长 8B（54 包载荷均匀 8B）。

### 1.3 勘误（对 v5，两处）

- csi23 = **stunInfo**（非 damageStickers；STUN_INFO 为 8B 定长结构）。
- csi1 = **isStrafing**（原"移动标志"；触发条件待细化：值=1 与 10Hz 移动更新相关）。

### 1.4 权威产出

`download/csi_tables_v8.json`：40 实体全量 CS 属性 csi 表，共 **306 条**（Vehicle 50 / Avatar 28 / FlockExotic 21 / SimulatedVehicle 19 / Flock 15 …）。**今后任意 v2 回放的 0x07/0x24 解码直接查此表。** 生成脚本 `scripts/csi_tables.py`。

---

## 2. BigWorld 14.4.1 源码对账（Task 14）：①②③④ 逐条复核

> 背景：用户提供的 vanilla BigWorld-Engine-14.4.1 全源码。定位：老、且非 WoT 原版（消息编号已重排、PackedXYZ 量化参数已改），但**语义骨架完全同源**。原四项收获复核如下（① 有状态修订）。

### 2.1 ① "0x3D 完整算法配方" → ⚠️ 状态修订（Task 16 降级为 vanilla 基线）

- **原结论**：lib/entitydef/ 的 `EntityDescriptionMap::digest()` 字节级算法——对 entities.xml 顺序的每个 client 实体，MD5 拼入【实体名 + 每个客户端属性（i32 csi / 变长条件 / 名称 / flags&0x5F / DataType 配方）+ 各类方法】。
- **复刻**：`scripts/bigworld_defs_digest.py`（引擎自带 demo entity_defs 冒烟通过）、`scripts/digest_v8.py`（服务器 273 .def 实算输入）。
- **修订**：对服务器 defs 实算 = `EBE966BE4B0DF76A9374DE0C2AC8AFF9` ≠ 目标值（2026-09-24 复跑确认可复现）。根因：**WoT fork 重写了 digest**（entity_description_digests.cpp，vanilla 14.4.1 无此文件，详见 §3）→ "配方=0x3D 算法"的结论作废。
- **仍然有效的部分**：配方里的 csi / 累积序 / flags / 类型宽度规则链全部成立——正是 §1 csi 表的构造基础（14 锚点验证）。一句话：**属性体系规则保留，摘要的序列化方式被 fork 重写**。

### 2.2 ② 0x3D 实际值解码 → ✅ 有效

回放 pkt#3 = `[u32 32]["5DF886F75E73B33CFF9D87FB9C69389C"]`，即 BigWorld `MD5::Digest::quote()` 的大写 hex 格式。2026-09-24 在 replay.jsonl 复验：第 4 行（t=61=0x3D，clk=0，len=32），全流唯一出现。目标值与存储格式双确证。

### 2.3 ③ digest 生命周期闭环 → ✅ 有效

LogOnParams HAS_DIGEST 机制：客户端登录时上报本地 defs 摘要 → 服务器比对 → 回放头存储（反编译 FUN_140576380 一次性守卫，随 0x18 版本 / 0x2D 构建 / 0x30 目录 / 0x3D 摘要"头部四件套"写出）→ 播放校验（错误码枚举实证：STOPPED=0 / VERSION=1 / **ENTITYDEF=2** / METADATA=3 / CORRUPTED=4）。引擎源码 + 客户端反编译双重证据。

### 2.4 ④ 消息族全景对账 → ✅ 有效（vanilla 语义确证）

| 类型 | vanilla 语义（确证） | 备注 |
|---|---|---|
| 0x04 | **leaveAoI**：[u32 id][EventNumber×N]；本文件 4B 载荷 = N=0 | v5/v6 裁决获引擎背书；工具命名表 handleEntityPropertyChange 系误导 |
| 0x05 | **createEntity**：[压缩流][u32 id][u16 type][f32×3 pos][PackedYPR 3B][属性流] | |
| 0x06 | **createCellPlayer**：[spaceID][vehicleID][pos][xzScale][dir]+属性；全量属性=[u8 count][u8 idx+value]×N | |
| 0x07 / 0x24 | **slice/nestedEntityProperty**，作用于 selectEntity 选中实体（解释为何不带实体 ID） | topLevelIndex = csi（§1 已闭环） |
| 0x0A | **avatarUpdate\* 家族**（24 变体）：PackedXYZ / PackedXZ 量化 + IDAlias(u8) + relativePosition 参考体系 | 完美解释实测 v20 量化格点与 ref≠0 相对坐标（Avatar 骑挂自己车） |
| 0x0F | **spaceData**：[u32 spaceID=7085][u32 entryID=84][u8 pathLen=18]["spaces/37_caucasus"][4×4 单位阵][u8 01] | = SpaceData_MappingData（矩阵为单位阵）；WoT 把字符串改为长度前缀 |

**WoT fork 进化点清单**（与 vanilla 的差异，全部实证）：
1. 消息编号重排（vanilla spaceData=#7 → WoT 0x0F）；
2. PackedXYZ 量化参数改为 20 bit/通道；
3. 字符串改长度前缀；
4. entityDefs digest 重写（§3）。

---

## 3. WoT fork digest（entity_description_digests.cpp）——当前唯一开放主线 ◐

### 3.1 根因（反编译实证）

WoT 在 `D:\BuildAgent\work\wotd_ci_release\wc\programming\shared_libs\entitydef\entity_description_digests.cpp` 重写了 digest：Visitor 体系（AbstractMD5Visitor / ClientServerTypesMD5Visitor / IMD5Calculator / MD5Calculator）。vanilla 14.4.1 无此文件 → 一切 vanilla 配方对算注定失败（已实测证明）。

### 3.2 已映射结构（~95%，键值序列化）

```text
for 每实体（entities.xml 顺序，isClientType）:
  [若上一实体未闭合: end()]
  name 键 + "name" = 实体名
  "properties" 节: 每 CS 属性（flags & 0x106）:
    raw_i32(csi); name 键
    [isForClient && streamSize<0 && vlh!=1: "varLenHeaderSize" = vlh]
    "name" = 属性名; "dataDistributionFlags" = u32(flags & 0x5F); "isVolatile" = bool ★fork 扩展
    类型块: key(DAT_1435e0950) + "name"="Int"等 + size/dbLen/elementType/allowNone/
            fields/moduleName/instanceName + end()
    end()
  "clientMethods" 节: 每方法（flags & 0xC）:
    name 键; [vlh 条件同上]; "name" = 方法名; "flags" = u8
    "args" 节（DAT_143665890）: 每参数 "Arg" 键 + "name" + 类型块 + end
    "returnValues" 节 ★fork 扩展（非空时）; end(); raw_i32(count)
  "baseMethods" / "cellMethods" 节: 仅 exposed; 接口方法后置 ★
```

### 3.3 MD5 原语与 IMD5Calculator 槽位（★★本轮已全部破译，见 §3.6）

- **原语**：FUN_1403e8140=Init / FUN_1403e82f0=Update / FUN_1403e8620=transform / FUN_1403e82e0=Final
- **槽位**：+0x18 begin / +0x20 end / +0x28 命名 u32 / +0x40 命名 varLen / +0x50 命名 u8 / +0x58 命名 bool / +0x60 命名 std::string / +0x68 命名 cstr / +0x70 getState
- **字面量**：DAT_1435d2d24="name"、DAT_1435e92e4="size"

### 3.4 已排除路径

- vanilla 完整复刻（`scripts/digest_v8.py`）→ `EBE966BE...` ✗
- fork 结构 + **15,552 编码组合暴力**（`scripts/digest_fork.py`）→ ✗
- fork 终版结构（§3.6）+ **84 组合暴力**（`scripts/digest_v9.py`）→ ✗（差距收窄到单一细节）

### 3.5 待闭合

1. 剩余未知量极小：begin 槽位字节语义（已证明不可能是 name 哈希；∈{空操作, flag 字节 u8/u16/u32}均已试）与 +0x40 vlh 宽度（u8/u16/u32 均已试）均已枚举——**实际剩余嫌疑是某个数据层细节**（见 3.7 验证神器）
2. 可选终极裁决：用户在 Ghidra 里读 `BW::MD5Calculator::vftable` 的 15 个函数指针（2 分钟），一次性确认全部槽位→原语映射

### 3.6 ★fork digest 终版结构（2026-09-24 decomp 深挖定案，全部从反编译提取）

**入口链**（客户端 `BW::EntityType::init`，c_1402c13f0.c:143725）：`entities.xml 解析 → EntityDescriptionMap → FUN_142a9b640(栈上 MD5Calculator{vptr,ctx@+8} → visitor 回调 → Final)`。服务器侧同代码同 defs → 同值。

**IMD5Calculator 原语语义**（FUN_1403e8xxx，穷举法证明无其他 Update 调用者）：
- e81e0 cstr：**带 NUL**（strlen+1）｜ e8210 stdstr：**内容无 NUL**（len=u32 size）｜ e8230 u8 1B ｜ e8260 u16 2B ｜ e8290 u32 4B LE ｜ e82c0 ctx 裸 Update（getState 后直接用）
- **begin(name,flag)/end() = 不可能哈希 name**（根 begin 传 NULL；且全部 Update 调用者已审计）→ begin ∈ {空操作, flag 字节}；end = 空操作（穷举证明）

**序列化结构**（每实体，entities.xml vector_ 原序，isClientType 过滤）：
```
begin(name,0) str(name)            ← 实体名无 NUL
begin("properties",1)
  每 CS 属性: rawU32(csi) begin(name,0) [vlh 若 isForClient&&s2c<0&&vlh≠1]
    str(name) u32(flags&0x5F) u8(isVolatile恒0) TYPE(节名"type") end
end
begin("clientMethods",1) 每方法: MBODY rawU32(idx++) end   ← 全部方法计数
begin("baseMethods",1)   每暴露方法: MBODY rawU32(idx++) end ← 仅暴露计数
begin("cellMethods",1)   同 base end
MBODY: begin(name,0) [vlh] str(name) u8(flags) [args非空: begin("args",1) 每参 begin(?,0) TYPE(无节名) end end] [returnValues非空: 同构] end
TYPE: begin(节名,0) cstr(类型名带NUL) [u32(size)] [dbLen永不触发] [元素TYPE("elementType")] 
  FixedDict: cstr u8(allowNone) begin("fields",1) 每字段 begin(名,0) str(名) TYPE(无) end end end
```

**类型名表**（vanilla 驼峰命名逐字一致，长度铁证）：Int/Uint+u32尺寸、Float、Float64、String、UnicodeString、Blob、Python、MailBox(仅服务器构建,客户端=UnsupportedDataType)、UserDataObjectLinkDataType、Vector+u32(2/3/4)、Array/Tuple+u32(size)+元素、FixedDict

**关键裁决**：
- DAT_1435e0950="type"（len4 铁证：GetAttr 配 local_198=4 两处）
- DAT_143665890="args"（len4 铁证：rttr/Py/VScript 四处独立佐证）
- DAT_143676a60="Int"（len3 铁证）、DAT_143928948="Uint"、DAT_1437d083c="Blob"（BlobDataType::vftable 毗邻）
- **MAILBOX 对 digest 无关**：客户端构建无 MailboxDataType（vanilla `#if MF_SERVER` 条件编译），但全部 MAILBOX 成员非 CS/非暴露（属性 0x8/0x0 十 21 处、参数仅非暴露 base/cell 方法 59 处）→ 永不进 digest
- **isVolatile 恒 0**：`<Volatile>` 节仅列 position/yaw/roll/pitch 自动属性（8/7/4/4 处），不在声明属性列表
- **FixedDict module/instance = 0 字节**（WoT 零 implementedBy，空串与否皆 0B）
- **persistAsBlob 零使用** → dbLen 分支永不触发
- **vlh 分布 {1:342, 2:5}**：仅 5 个 client 方法（showGUI/updateSpawnList/explodeProjectile/updateQuestProgress/setUpdatedGoodiesSnapshot）触发 varLenHeaderSize
- **方法 flags u8** = 组件位(&7: client=0/cell=1/base=2) | Exposed(''→0xC, OWN_CLIENT→0x8, ALL_CLIENTS仅cell→0x4) | **AllowUnsafeData→0x10**（8 处，v8 曾遗漏）+ client 自动 |=0x4
- **属性 flags&0x5F**：0x5F=GHOSTED|OTHER|OWN|BASE|CLIENT_ONLY|EDITOR，**不含 PERSISTENT(0x20)**（v8 曾误补，已回退语义确认）；Backupable→0x200/AllowUnsafeData(属性)→0x400/Identifier→0x80 均被掩掉
- **方法重名去重**：同名同签名合并（先到先得）；全树仅 Account.requestToken 1 处接口遮蔽；同名属性覆盖保留原位（vanilla parseProperties 实证，无 CS→非CS 情形）
- **客户端与服务器 defs 字节级相同**（103 文件+entities.xml md5 全同）→ 双侧同摘要
- **实体迭代 = vector_ 解析序**（vanilla addToMD5 实证，非按名排序）

**数据模型已验证**：Login 实体逐项与 def 吻合；csi 全 40 实体稠密 0..N-1；streamSize 范围 [-1,60] 无 int16 溢出；Vehicle/Avatar 14 锚点 + AreaDestructibles（回放 0x05 尾巴 [count][csi+len+value] 解码 = 4 个空串属性 csi0-3）✓

### 3.7 下一轮攻坚路径（已就绪的神器）

1. **0x05/0x06 创建块属性流 = csi 全类型验证神谕**：1833 个 0x05 块尾部 `[u8 count][每属性: u8 csi + 长度前缀值]`——可对全部实体类型逐一对账 csi 集合与类型形状（AreaDestructibles 已验证）；0x06 块 369B 全量属性流同理
2. 0x08 methodID 验证方法序（需先核实工具命名表来源；setClientReady=1/updateArena=58 与 M1 序部分吻合部分矛盾，待解）
3. 可选：Ghidra 读 `BW::MD5Calculator::vftable` 15 指针一次性裁决全部槽位
4. `scripts/digest_v9.py`：终版实现 + 84 组合暴力（begin×4 × vlh×3 × 方法序×7），改一处跑一遍即出结果

→ 材料到手后：补进 `digest_fork.py` → 对 273 个 .def 全量实算 → 对比 `5DF886F75E73B33CFF9D87FB9C69389C`。**输入侧已就绪**（服务器 .def 可用用户版 bwxml_decode.py 全量解码，digest_v8 管线已跑通全实体累积）。

---

## 4. 历史轮次已确认结论总表（v1–v7）

### 4.1 容器与包流（v1–v2）

- `[u32 magic=0x11343212][u32 blockCount=2]`；block0 = 80,068B 回放头 JSON（玩家/车辆/服务器设置），block1 = 110,228B 战斗结果 JSON（全量结果 + 更新后车辆表 + 击杀摘要）。
- 两块之后 gap 8B = `[u32 zlib 解压长 7,106,831][u32 有效加密流长 1,834,785]`；主流区 @190,320 起 1,834,792B（末 7B 为 Blowfish 填充）→ **Blowfish-ECB 解密 + 前向异或（CBC 式，IV=0）→ zlib** → 7,106,831B 包流。
- 156,482 包 100% 消费、5,229,047 载荷字节；容器层 2,025,112B 100% 定界；JSON 块 100% 读取。

### 4.2 38 种包类型速查（37 内容 + 0xFFFFFFFF 终止符；字段级布局见报告 §6/附录 C）

| 类型 | 语义（已确证） | 包数 |
|---|---|---|
| 0x0A | avatarUpdate* 家族（位置/朝向增量；IDAlias + 相对参考，20bit 量化） | 82,439（52.7%） |
| 0x07 | sliceEntityProperty（csi 属性更新，selectEntity 目标） | 37,105（23.7%） |
| 0x1A | 相机/玩家状态（10Hz 记录主循环，9 参无条件） | 6,321 |
| 0x1F | 性能遥测：fps u8 + ping 18bit + 卡顿标志（播放中不写） | 6,321 |
| 0x36 | 游戏 tick 标记（10Hz 节拍器；战斗窗 6,014 个 ≈ 601.4s） | 6,092 |
| 0x26 | 瞄准圈遥测（gun marker，门控变化 ≥0.0004） | 5,107 |
| 0x1D / 0x1C | 输入/视角增量 B / A | 2,824 / 1,985 |
| 0x32 | 视觉部件 CGF 状态 + 载具表/档案/开关（组件路由号打头） | 1,837 |
| 0x05 | createEntity | 1,833 |
| 0x04 | leaveAoI | 1,710 |
| 0x08 | entityMethod（17 种方法号；1=setClientReady、58=updateArena、65=剧情事件串） | 1,265 |
| 0x37 | deathOrder 击杀事件（25 条，序号+击杀者/被杀者）+ 节点变换 | 1,148 |
| 0x24 | nestedEntityProperty（csi） | 282 |
| 0x31 | 客户端回调（chat2.onActionReceived / vehicle_state 等） | 84 |
| 0x1B | 相机模式串（arty/strategic/arcade/prebattleHighlights） | 48 |
| 0x20 | setGunReloadTime（装填计时器，斜率精确 -1.00/s，饱和 B=26.419s=261 装填时长） | 37 |
| 0x35 | 空标记（散布战斗中段，推断为批量实体状态刷新点） | 8 |
| 0x16 / 0x17 | arenaPeriod（1 等待/2 倒计时/3 战斗/4 结算）/ 阶段倒计时 f32 | 4 / 4 |
| 0x2B / 0x1E / 0x2E | 标记 / 状态标记 / 标记（u8=0） | 4 / 4 / 3 |
| 0x0D | NRL battle space 创建 | 3 |
| 0x0 | avatar/arena 聚合（arenaExtraData pickle） | 1 |
| 0x06 | createCellPlayer | 1 |
| 0x0F | spaceData 地图装载（spaceID=7085，MappingData 4×4 单位阵） | 1 |
| 0x11 | 战斗结果信封 (size, zlib.crc32) + 3 段嵌套 zlib（储备/任务加成/结算明细） | 1 |
| 0x15 | 时间基（f64 服务器单调钟 141,061.04，录制起点读数） | 1 |
| 0x22 | 玩家车辆 ID 标记（受控实体锁定 546611525） | 1 |
| 0x18 / 0x2D / 0x30 / 0x3D | 头部四件套：版本串 "2.4.0.0" / 构建四元组 "17, 1, 0, 5" / 脚本目录 "sd" / **entityDefs 摘要** | 各 1 |
| 0x12 | 录制启动标记 | 1 |
| 0x1 / 0x2 | 各 1 次（详见报告 §6） | 1 / 1 |
| 0xFFFFFFFF | 结束符，16B = MD5(block0‖block1) 精确命中 | 1 |

### 4.3 时钟与时间轴（v3 定论）

- **clock = float32 秒**（比特模式被整数视角误读过两代），源出服务器时间估计，录制起点 0.0。
- .wotreplay = **正常战斗的客户端 1x 实时录制**；v1"变速观看"、v2"4→64x 阶梯"均为整数误读浮点比特的伪影（94.90% 增量吻合伪影公式 `(0.1×2^(23-⌊log2 t⌋))`），已全部撤回。
- 绝对锚点：倒计时 p2→p3 = 30.0000s 精确；战斗 p3→p4 = 612.495s（战果 duration=612）；录制起点反推 18:01:05.3–05.5 = 回放头 dateTime；25 击杀三条时间轴逐对一致（差 ≤0.23s）。
- 方法论遗产：u32 字段出现多种自洽整数单位解读时，**必须先排除浮点比特**；绝对锚点一票否决。

### 4.4 实体与战斗叙事

- 160 实体；车辆 = 类型 6×30（546611517–546611546），玩家 Avatar = 546611552；7 个实测类型与 entities.xml 1-based 编号全对齐（3=ArenaInfo / 6=Vehicle / 7=AreaDestructibles / 18=EmptyEntity / 28=TeamInfo / 29=AvatarInfo / 40=NetworkEntity）。
- 击杀链 25 条（15:10），队 2 全歼获胜；玩家（261 工程火炮）1 击杀 / 1669 伤害 / 15 发 4 直接命中 14 溅射，351s 击杀 Deiiv1，眩晕 192.18s/14 次。

### 4.5 覆盖度与交叉验证（v4–v6）

- **覆盖度**：结构层 100%；载荷语义 A 级 99.48% / B 级 0.52%（字段级命名残留）。
- replay.jsonl（27.8MB 播放捕获，156,482 行 = 包数）= 第三方语义仲裁者：type+clock 全流零失配；尾包 0xFFFFFFFF 的 16B = MD5(block0‖block1)。
- 10Hz 记录主循环架构：一拍内 0x26（门控）→ 0x1A（无条件）→ 0x1F（仅 ping≠-1），一举解释三者计数关系与差分分布。
- 三方数据归一：实时会话 = 录制会话（录制窗嵌于其战斗段）；回放 = 第一手记录；播放会话 = 1x 重演。

---

## 5. 资料与工具资产清单

### 5.1 upload/（持久区，不受平台快照回退影响）

| 资产 | 说明 | 校验/状态 |
|---|---|---|
| 20260911_1801_...wotreplay | 原始回放（分析对象） | — |
| replay.jsonl | 播放捕获逐包 JSON（27.8MB，156,482 行） | 全流对比零失配 |
| session_20260911_175934.jsonl / session_20260923_140427.jsonl | 实时会话日志 / 播放会话日志 | 三方归一完成 |
| wot_src.7z.001/.002 | 客户端源码（wotstat/wot-src，wot-cn 2.4.0.0，19,248 文件） | — |
| decomp.zip | 客户端 exe Ghidra 全量反编译（180,027 函数） | — |
| scripts.7z | **WoT 服务器 scripts 全量**（12,857 文件，273 .def，cgf_names.xml 等） | md5 3291a19748a129bf8e16cd5983fda4c4 |
| BigWorld-Engine-14.4.1_src.tar.gz | vanilla 引擎全源码 | md5 decb04dbadb8ec82a04c175a334a592c |
| tools/bwxml_decode.py | **用户权威版** EN/BWXML 解码器（勿替换） | Account.def 7137/7137 验证 |
| tools/def_dump.py | 用户 .def 分析工具 | 客户端 mini_scripts.pkg --list 102 def 通过 |
| tools/file_server.py | 下载门户 v2 | 已按用户要求停用 |
| backup_v5 / v6 / v7 | 历轮交付全量备份 | — |

### 5.2 /tmp（快区：会话重启可能丢失；压缩原件均在 upload）

- `/tmp/wot_scripts`（192MB）：服务器 scripts 解包。**273 个 .def**（entity_defs 41 + component_defs 127 + user_data_object_defs 40 + 其余散布全树）；entities.xml（EN 格式，与客户端 XML 版 40 实体逐项同序）；alias.xml（42,884B）；**cgf_names.xml（1,921B，0x32/0x37 节点名候选材料，未展开）**；destructibles*.xml、arena_defs、item_defs 等。
- `/tmp/wot_src`（653MB）：客户端源码解包。`/tmp/archive`（441MB）：BigWorld tar.gz + scripts.7z 原件。

### 5.3 scripts/（工作脚本，复现入口）

- **解析库**：wot_replay_lib.py（容器+解密+包流）、bw_pickle.py（BW 定制 pickle 安全解码）
- **digest 线**：bigworld_defs_digest.py（vanilla 复刻）→ digest_v8.py（vanilla + 服务器 273 .def 实算，可复现 EBE966BE...）→ digest_fork.py（fork 结构 + 15,552 组合暴力，待补槽位编码）→ csi_tables.py（→ download/csi_tables_v8.json）
- **解码器**：upload/tools/bwxml_decode.py（用户权威版）；run_def_dump.py（def_dump 本地化驱动）
- **其他**：coverage_audit*.py（覆盖度审计）、extract_writers.py（Ghidra 写入函数提取）、vlm_check_chart08.mjs 等

---

## 6. 开放项与下一步

| # | 事项 | 状态 | 所需材料 |
|---|---|---|---|
| 1 | 0x3D fork digest 字节编码 → 全量对算 | **等用户**（提取中） | IMD5Calculator vtable 槽位实现（+0x18/+0x20/+0x28/+0x40/+0x50/+0x58/+0x60/+0x68）+ DAT_1435e0950 / DAT_143665890 值 |
| 2 | 0x32/0x37 视觉节点名映射 | 未展开 | cgf_names.xml（在位）；可能需 destructibles 系 xml 辅助 |
| 3 | 0x08 的 17 种方法号批量命名 | 候选 | 服务器 .def 方法表（在位）；需先定方法编号方案 |
| 4 | csi1=isStrafing 触发条件细化 | 次要 | 回放数据行为学分析 |

---

## 附录：更新记录

- **2026-09-24（第一轮）**：登记制度建立（用户指令："后续调查出的成果只要确认是没问题的都及时写到文件里"）。首批收录 v1–v8 全部已确认结论。复验项：0x3D 值在 replay.jsonl 定位（t=61 行，全流唯一）；csi 表 14 锚点（12 Vehicle + 2 Avatar）全部通过；vanilla digest 复跑可复现（EBE966BE...）；273 .def 全树计数；cgf_names.xml 在位（1,921B）。
- **2026-09-24（第二轮）**：decomp 深挖收官——全部待补数据从 decomp 提取（无需 .gbf/exe）：DAT 字符串 5 个全部破译（type/args/Int/Uint/Blob，长度铁证法）；MD5Calculator 原语语义定案；begin/end 空操作穷举证明；MAILBOX=客户端 UnsupportedDataType 但对 digest 无关；AllowUnsafeData→flags|0x10 补遗；Persistent 不在 0x5F 内（虚惊）；客户端=服务器 defs 字节级相同；digest_v9.py 终版实现+84 组合暴力；0x05 尾巴=[count][csi+len+value] csi 验证神谕发现（AreaDestructibles 验证通过）。

---
*AI生成*
