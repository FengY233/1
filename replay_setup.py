# -*- coding: utf-8 -*-
"""replay_setup.py — WoT v2 replay 战斗启动序列挖掘(官方剧本提取)。

用法:
  py -3 tools/replay_setup.py [replay路径] [--dump N] [--pkt N]

帧格式(2026-09-14 修正,156482 包 100% 消费):
  [u32 载荷长][u32 类型][u32 时钟][载荷 ×载荷长]
类型实证(同场 jsonl 交叉):
  0x18=版本串  0x2D=构建串  0x3D=哈希  0x0=avatar/arena 聚合(arenaExtraData
  pickle)  0x8=arena 配置 pickle  0xF=空间设置([spaceID][?][len]路径
  [恒等4x4][flag])  0x5=车辆实体数据  0x32=实体可视化/列表数据
  (#99=arena 车辆列表 24 条)  0xA=位置更新  0x7=车辆状态
注意:该 replay 带 SERVER_REPLAY bonus cap(服务器回放模式)。
"""
import struct
import sys
import zlib
from collections import Counter

from Crypto.Cipher import Blowfish

KEY = bytes([0xDE, 0x72, 0xBE, 0xA0, 0xDE, 0x04, 0xBE, 0xB1,
             0xDE, 0xFE, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF])
DEFAULT = ('//vmware-host/Shared Folders/World_of_Tanks_CN/replays/'
           '20260911_1801_ussr-R52_Object_261_37_caucasus.wotreplay')


def load(path):
    data = open(path, 'rb').read()
    (magic, bc) = struct.unpack_from('<II', data, 0)
    assert magic == 0x11343212
    pos = 8
    for _ in range(bc):
        (blen,) = struct.unpack_from('<I', data, pos)
        pos += 4 + blen
    pos += 8
    main = data[pos:]
    cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
    prev = b'\x00' * 8
    out = bytearray()
    for i in range(0, len(main) - 7, 8):
        d = cipher.decrypt(main[i:i + 8])
        d = bytes(a ^ b for a, b in zip(d, prev))
        prev = d
        out += d
    stream = zlib.decompress(bytes(out))
    pkts = []
    q = 0
    while q + 12 <= len(stream):
        size, ty, clock = struct.unpack_from('<III', stream, q)
        pkts.append((ty, clock, stream[q + 12:q + 12 + size]))
        q += 12 + size
    return pkts


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else DEFAULT
    pkts = load(path)
    print('%d packets, %d bytes' % (len(pkts), sum(len(p[2]) for p in pkts)))
    types = Counter(p[0] for p in pkts)
    for t, c in types.most_common(15):
        print('  type 0x%-3X: %d' % (t, c))
    # dump 前 N 个 setup 包
    n = 130
    for i, (ty, clk, pl) in enumerate(pkts[:n]):
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in pl[:48])
        print('#%-4d t=0x%-3X sz=%-5d clk=%-8d %s' % (i, ty, len(pl), clk, txt))
