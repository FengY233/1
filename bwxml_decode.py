# -*- coding: utf-8 -*-
"""bwxml_decode.py — WoT BWXML(EN A1 62)编译 XML 解码器。

格式(③ wgtk pxml/de.rs 定义,已对我方 Avatar.def/karelia.xml 解码验证):
  [magic 4B: 45 4E A1 62][1B unknown]
  字典: NUL 结尾串,读到空串为止
  元素: [u16 子数][u32 自描述 = type<<28 | end_offset]
        子数 × { [u16 名字索引][u32 描述] }
        数据: 自身,然后各子(按序);标量长度 = end_offset - 前一 end_offset
  类型: 0=Element 1=String 2=Integer 3=Vector 4=Boolean 5=base64
"""
import base64
import struct
import sys


class R:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def u8(self):
        v = self.d[self.p]; self.p += 1; return v

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.p)[0]; self.p += 2; return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]; self.p += 4; return v

    def blob(self, n):
        v = self.d[self.p:self.p + n]; self.p += n; return v

    def cstr(self):
        e = self.d.index(b'\x00', self.p)
        s = self.d[self.p:e].decode('utf-8', 'replace')
        self.p = e + 1
        return s


TYP = {0: 'el', 1: 'str', 2: 'int', 3: 'vec', 4: 'bool', 5: 'b64'}


def read_data(r, ty, length):
    if ty == 0:
        return read_element(r)
    if ty == 1:
        return r.blob(length).decode('utf-8', 'replace') if length else ''
    if ty == 2:
        if length == 0:
            return 0
        if length == 1:
            return struct.unpack('<b', r.blob(1))[0]
        if length == 2:
            return struct.unpack('<h', r.blob(2))[0]
        if length == 4:
            return struct.unpack('<i', r.blob(4))[0]
        if length == 8:
            return struct.unpack('<q', r.blob(8))[0]
        raise ValueError('int len %d' % length)
    if ty == 3:
        n = length // 4
        return [struct.unpack('<f', r.blob(4))[0] for _ in range(n)]
    if ty == 4:
        return r.u8() == 1 if length else False
    if ty == 5:
        return base64.b64encode(r.blob(length)).decode()
    raise ValueError('type %d' % ty)


def read_element(r):
    n_children = r.u16()
    self_desc = r.u32()
    self_ty = self_desc >> 28
    self_end = self_desc & 0x0FFFFFFF
    children = []
    for _ in range(n_children):
        name_idx = r.u16()
        desc = r.u32()
        children.append((name_idx, desc >> 28, desc & 0x0FFFFFFF))
    value = read_data(r, self_ty, self_end - 0)
    out = [value] if self_ty != 0 else []
    offset = self_end
    for name_idx, ty, end in children:
        v = read_data(r, ty, end - offset)
        offset = end
        out.append((name_idx, v))
    return out


def decode(data):
    assert data[:4] == b'\x45\x4E\xA1\x62', 'bad magic: %r' % data[:5]
    r = R(data)
    r.p = 5
    rdict = []
    while True:
        s = r.cstr()
        if s == '':
            break
        rdict.append(s)
    tree = read_element(r)
    return rdict, tree, r.p


def dump(node, rdict, depth=0, label=None):
    pad = '  ' * depth
    if isinstance(node, list):
        if not node:
            return
        first = node[0]
        if not isinstance(first, tuple):
            # element 自身值(非 Element 类型时)
            print('%s= %r' % (pad, first))
        for name_idx, v in [c for c in node if isinstance(c, tuple)]:
            name = rdict[name_idx] if name_idx < len(rdict) else '?%d' % name_idx
            if isinstance(v, list):
                print('%s<%s>' % (pad, name))
                dump(v, rdict, depth + 1)
                print('%s</%s>' % (pad, name))
            else:
                print('%s<%s> = %r' % (pad, name, v))
    else:
        print('%s%r' % (pad, node))


if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    rdict, tree, consumed = decode(data)
    print('# dict %d entries, consumed 0x%X / 0x%X' % (len(rdict), consumed, len(data)))
    dump(tree, rdict)
