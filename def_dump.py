# -*- coding: utf-8 -*-
"""解 scripts.pkg 里的 .def（bwxml 二进制 XML）。

用法：
  py -3 tools/def_dump.py --list                    # 列全部 def
  py -3 tools/def_dump.py Avatar                    # 整棵树
  py -3 tools/def_dump.py Avatar --grep Ammo        # 只看名字/内容含 Ammo 的子树
  py -3 tools/def_dump.py Avatar --methods          # 方法表（名 + 参和 + 定长/变长）
  py -3 tools/def_dump.py interfaces/Chat --methods
  py -3 tools/def_dump.py Vehicle --section CellMethods

bwxml 格式见 tools/bwxml_decode.py 头部（③ wgtk pxml/de.rs 定义）。
"""
import argparse
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bwxml_decode as B  # noqa: E402

PKG = u'//vmware-host/Shared Folders/World_of_Tanks_CN/res/packages/scripts.pkg'
PREFIX = 'scripts/entity_defs/'


def open_pkg():
    if not os.path.isfile(PKG):
        sys.exit('找不到 scripts.pkg：%s' % PKG)
    return zipfile.ZipFile(PKG)


def load(z, name):
    """按名字找 def：'Avatar' / 'Avatar.def' / 'interfaces/Chat'。"""
    if not name.endswith('.def'):
        name += '.def'
    for c in (PREFIX + name, PREFIX + 'interfaces/' + name):
        try:
            raw = z.read(c)
        except KeyError:
            continue
        rdict, tree, consumed = B.decode(raw)
        return c, rdict, tree, consumed, raw
    near = [n for n in z.namelist()
            if n.startswith(PREFIX) and name[:-4].lower() in n.lower()]
    sys.exit('没找到 %s。相近的有：%s' % (name, near or '（无）'))


# ---------------------------------------------------------------- 树工具

def kids(node):
    """[(名字索引, 值)]，跳过裸值。"""
    out = []
    if isinstance(node, list):
        for c in node:
            if isinstance(c, tuple):
                out.append((c[0], c[1]))
    return out


def first_scalar(node):
    """节点自身的裸值（非 Element 类型时）。"""
    if not isinstance(node, list):
        return node
    for c in node:
        if not isinstance(c, tuple):
            return c
    return None


class Doc(object):
    def __init__(self, rdict, tree):
        self.rdict = rdict
        self.tree = tree

    def nm(self, idx):
        return self.rdict[idx] if 0 <= idx < len(self.rdict) else '?%d' % idx

    def section(self, name):
        for idx, v in kids(self.tree):
            if self.nm(idx) == name:
                return v
        return None

    def find(self, want, node=None):
        node = self.tree if node is None else node
        out = []
        for idx, v in kids(node):
            if self.nm(idx) == want:
                out.append(v)
            out += self.find(want, v)
        return out


# ---------------------------------------------------------------- 类型求长

VAR = {'STRING', 'PYTHON', 'BLOB', 'UNICODE_STRING', 'USER_TYPE'}
SZ = {
    'INT8': 1, 'UINT8': 1, 'BOOL': 1, 'EXTRA_ID': 1,
    'INT16': 2, 'UINT16': 2,
    'INT32': 4, 'UINT32': 4, 'OBJECT_ID': 4, 'SHOT_ID': 4,
    'FLOAT32': 4, 'FLOAT': 4,
    'INT64': 8, 'UINT64': 8, 'DB_ID': 8, 'FLOAT64': 8,
    'VECTOR3': 12, 'VECTOR2': 8,
    # ★ BigWorld 引擎内建类型（不在 alias.xml 里）。宽度来自 ③：
    #   MAILBOX = EntityMailBoxRef = EntityID(int32,4) + Mercury::Address(8)
    #   Address = ip(u32,4) + port(u16,2) + salt(u16,2)
    #   见 ③ basictypes.hpp:322 / :271 与 basictypes.cpp:199 的 << 实现。
    'MAILBOX': 12,
}


def load_aliases(z):
    raw = z.read(PREFIX + 'alias.xml')
    rdict, tree, _ = B.decode(raw)
    doc = Doc(rdict, tree)
    out = {}
    for idx, v in kids(tree):
        out[doc.nm(idx)] = v
    return out, doc


def arg_size(name, aliases, doc, seen=()):
    """返回 (字节数, 是否变长)。解不出 → (None, None)。"""
    if not isinstance(name, str):
        return None, None
    if name in VAR:
        return -1, True
    if name in SZ:
        return SZ[name], False
    if name in seen:
        return -1, True
    if name not in aliases:
        return None, None

    node = aliases[name]
    spec = first_scalar(node)
    seen = seen + (name,)

    if spec in ('FIXED_DICT', 'FIXED_DICT_SIMPLE'):
        props = None
        for idx, v in kids(node):
            if doc.nm(idx) == 'Properties':
                props = v
        if props is None:
            return None, None
        # ★ ③ fixed_dict_data_type.cpp:452-461 的规则：
        #   从 streamSize_=0 累加，**任一字段 == -1 就把整个 dict 置为 -1（变长）**。
        #   注意顺序：**变长优先于解不出** —— 只要有一个字段是变长，
        #   整体就是变长，之后解不解得出都不影响这个结论。
        #   （实测：ATTACK_RESULTS 含 ARRAY 成员 ⇒ 变长，而它内部还有
        #     别的未解类型 —— 若先判 None 就会错报成「解不出」。）
        total = 0
        for _, pv in kids(props):
            t = pv
            if isinstance(pv, list):
                inner = None
                for idx, v in kids(pv):
                    if doc.nm(idx) == 'Type':
                        inner = v
                t = first_scalar(inner) if inner is not None else first_scalar(pv)
            # ARRAY 成员：直接判变长，不必再解 of
            if isinstance(pv, list):
                inner_spec = None
                for idx, v in kids(pv):
                    if doc.nm(idx) == 'Type':
                        inner_spec = first_scalar(v)
                t_spec = inner_spec if inner_spec is not None else t
            else:
                t_spec = t
            if isinstance(t_spec, str) and (
                    t_spec in VAR or t_spec in ('ARRAY', 'LIST_OF_COMP_DESCRS')):
                return -1, True
            s, var = arg_size(t, aliases, doc, seen)
            if var:
                return -1, True
            if s is None:
                return None, None
            total += s
        return total, False

    if spec in ('ARRAY', 'LIST_OF_COMP_DESCRS'):
        return -1, True

    # ★ 简单别名：节点就是个裸字符串（如 VEH_TYPE_CD 节点 == 'UINT32'）。
    #   不递归的话会一路掉到 None —— 实测这是 ATTACKER_INFO / ATTACK_RESULTS
    #   解不出的真因（不是 MAILBOX，MAILBOX 是另一处）。
    if spec is not None and not isinstance(node, list):
        return arg_size(spec, aliases, doc, seen)

    return None, None


# ---------------------------------------------------------------- 命令

def cmd_list(z):
    for n in sorted(x for x in z.namelist()
                    if x.startswith(PREFIX) and x.endswith('.def')):
        print(n[len(PREFIX):])


def cmd_dump(z, name, grep, maxdepth, section):
    path, rdict, tree, consumed, raw = load(z, name)
    print('# %s   (%d 字节 bwxml, 解出 %d/%d, 字典 %d 项)'
          % (path, len(raw), consumed, len(raw), len(rdict)))
    print()

    node = tree
    label = '<root>'
    if section:
        sec = None
        for idx, v in kids(tree):
            if rdict[idx] == section:
                sec = v
                break
        if sec is None:
            sys.exit('没有 <%s> 节' % section)
        node, label = sec, section

    def hit(n, lb, rdict_):
        """★ 名字存在字典里（节点里存的是**索引**），所以不能只 grep repr(node) ——
        必须把**所有后代的名字**也解出来一起比。"""
        if grep is None:
            return True
        g = grep.lower()
        if g in str(lb).lower() or g in repr(n).lower():
            return True
        # 后代名字
        for idx, v in kids(n):
            if hit(v, rdict_[idx] if idx < len(rdict_) else '?', rdict_):
                return True
        return False

    def walk(n, depth, lb):
        if not hit(n, lb, rdict):
            return
        if maxdepth is not None and depth > maxdepth:
            return
        pad = '  ' * depth
        scal = first_scalar(n)
        if not isinstance(n, list):
            print('%s<%s> = %r' % (pad, lb, n))
            return
        print('%s<%s>%s' % (pad, lb, (' = %r' % scal) if scal is not None else ''))
        for idx, v in kids(n):
            walk(v, depth + 1, rdict[idx] if idx < len(rdict) else '?')
        print('%s</%s>' % (pad, lb))

    walk(node, 0, label)


def cmd_methods(z, name, only_section):
    aliases, adoc = load_aliases(z)
    path, rdict, tree, _, _ = load(z, name)
    doc = Doc(rdict, tree)
    print('# %s —— 方法表（下标序；元素号 = 0x4E + 下标）' % path)
    print('# ★★ 下标由 BigWorld 排序规则算（定长按 size 升序、变长在后，'
          'stable 保定义序，同名 dedup 先到先得）。')
    print('# ★★ **未与客户端 mevt 实测核对之前，不得当作元素号使用**'
          '（第 278 轮：静态表与回放 methodID 不是同一编号空间）。')
    print()
    for sec in ('ClientMethods', 'BaseMethods', 'CellMethods'):
        if only_section and sec != only_section:
            continue
        s = doc.section(sec)
        if s is None:
            continue
        rows = []
        for idx, body in kids(s):
            mname = doc.nm(idx)
            args, vln, exposed = [], 1, False
            for aidx, av in kids(body):
                an = doc.nm(aidx)
                if an == 'Arg':
                    args.append(av)
                elif an == 'VariableLengthHeaderSize':
                    vln = first_scalar(av) if isinstance(av, list) else av
                elif an == 'Exposed':
                    exposed = True
            total, var, bad = 0, False, None
            for a in args:
                if isinstance(a, list):        # <Arg> = ARRAY + <of>
                    var = True
                    break
                sz, v = arg_size(a, aliases, adoc)
                if sz is None:
                    bad = a
                    break
                if v:
                    var = True
                    break
                total += sz
            rows.append(dict(name=mname, n=len(args), size=total,
                             var=var, vln=vln, exp=exposed, bad=bad))
        fix = sorted([r for r in rows if not r['var']], key=lambda r: r['size'])
        varr = sorted([r for r in rows if r['var']], key=lambda r: r['vln'])
        print('=== <%s> %d 项（定长 %d / 变长 %d）===' % (sec, len(rows), len(fix), len(varr)))
        for i, r in enumerate(fix + varr):
            tag = ('VAR(h=%d)' % r['vln']) if r['var'] else ('Fixed(%d)' % r['size'])
            bad = ('   ★解不出: %r' % r['bad']) if r['bad'] else ''
            print('  %3d %#04x  %-44s %-11s %d 参%s%s'
                  % (i, 0x4E + i, r['name'], tag, r['n'],
                     ' [Exposed]' if r['exp'] else '', bad))
        print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('name', nargs='?')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--methods', action='store_true')
    ap.add_argument('--grep', default=None)
    ap.add_argument('--maxdepth', type=int, default=None)
    ap.add_argument('--section', default=None)
    a = ap.parse_args()

    z = open_pkg()
    if a.list:
        cmd_list(z)
    elif not a.name:
        sys.exit('给个 def 名，或用 --list')
    elif a.methods:
        cmd_methods(z, a.name, a.section)
    else:
        cmd_dump(z, a.name, a.grep, a.maxdepth, a.section)


if __name__ == '__main__':
    main()
