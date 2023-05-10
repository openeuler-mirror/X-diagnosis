#!/usr/bin/python3
# coding: utf-8
import sys
import re
import os
import glob
from collections import OrderedDict
from subprocess import getstatusoutput


__all__ = ['EftraceModule', 'read_source_file',
           'parse_multi_cmds', 'xd_make_cmd']

cur_dir = os.path.abspath(os.path.dirname(__file__))
uname_r = ''
uname_m = 'x86_64'

kp_func_file = None
kp_type_file = None

kp_regs = {
    'x86_64': ['%di', '%si', '%dx', '%cx', '%r8', '%r9', '%r10'],
    'aarch64': ['%x0', '%x1', '%x2', '%x3', '%x4', '%x5', '%x6']
}

kp_params = []
kp_args = OrderedDict()

kp_flt = ''
kp_sym = ''
kp_event = ''
kp_final = []

kp_cast = {}
kp_spec = {}
kp_struct = {}
kp_sizeof = {}
kp_mem = {}


class EftraceModule(object):
    def __init__(self, args):
        self.args = args

    def run(self):
        if self.args.clear:
            self.clear()
            return

        if self.args.ef_expression:
            parse_env()
            ftrace_cmds = parse_multi_cmds(' '.join(self.args.ef_expression))
            for cmd in ftrace_cmds:
                print(cmd)
                if self.args.run:
                    os.system(cmd)
            clear_env()

    @staticmethod
    def clear():
        kp_events = '/sys/kernel/debug/tracing/kprobe_events'
        kp_enable = '/sys/kernel/debug/tracing/events/kprobes/enable'

        if os.path.exists(kp_enable):
            with open(kp_enable, 'w') as f:
                f.write('0')

        with open(kp_events, 'w') as f:
            f.write('')

    def stop(self):
        pass


def parse_env():
    global uname_r
    global uname_m
    global kp_func_file
    global kp_type_file

    uname_r = getstatusoutput('uname -r')[1]
    uname_m = getstatusoutput('uname -m')[1]

    kver = re.search(r'\d+\.\d+\.\d+-', uname_r)
    kdir = os.path.join(cur_dir, 'kernel')

    type_files = glob.glob(os.path.join(kdir, kver.group() + '*%s.h' % uname_m))
    func_files = glob.glob(os.path.join(kdir, kver.group() + '*%s.f' % uname_m))
    kp_type_file = open(type_files[0], 'r')
    kp_func_file = open(func_files[0], 'r')


def clear_env():
    if kp_type_file:
        kp_type_file.close()
    if kp_func_file:
        kp_func_file.close()


def parse_cmd(cmd_str):
    global kp_flt
    global kp_event
    global kp_sym

    if 'f:' in cmd_str:
        if cmd_str.count('f:') != 1:
            raise Exception('filter should be one')

        temp = cmd_str.split('f:')
        kp_flt = temp[1].strip()
        cmd_str = temp[0].strip()

    if cmd_str.startswith('p:') and cmd_str.count('p:') == 1:
        is_kp = True
    elif cmd_str.startswith('r:') and cmd_str.count('r:') == 1:
        is_kp = False
    else:
        raise Exception('no kprobe or rprobe found')

    if cmd_str:
        if is_kp:
            probe_re = r'p:\s*(\w+)\s+(\w+)\s+(.*)'
        else:
            probe_re = r'r:\s*(\w+)\s+(\w+)\s+(.*)'

        res = re.search(probe_re, cmd_str, re.DOTALL)
        if res:
            kp_event = res.group(1)
            kp_sym = res.group(2)
            fetchargs = res.group(3)

            args_list = re.split(r'(\S+)\s*=', fetchargs)
            name = arg = ''
            for elem in args_list:
                elem = elem.strip()
                if not elem:
                    continue

                if not name:
                    name = elem
                elif not arg:
                    arg = elem

                if name and arg:
                    if ':' in arg:
                        tmp = arg.split(':')
                        arg = tmp[0].strip()
                        kp_spec[name] = tmp[1].strip()

                    kp_args[name] = arg
                    name = arg = ''
        else:
            raise Exception('kprobe format error')

    kp_final.append('%s%s %s' %
                    ('p:' if is_kp else 'r:', kp_event, kp_sym))


def get_func_params(func_name):
    global kp_params

    kp_func_file.seek(0)
    for line in kp_func_file.readlines():
        decl = re.search(r'\W%s\(' % func_name, line)
        if decl:
            params = re.search(r'(?<=\().*(?=\))', line)
            if params:
                kp_params = params.group().split(',')

    if not kp_params:
        raise Exception('%s parameters not found' % func_name)


def get_config_func_params(func_decl):
    global kp_params
    params = re.search(r'(?<=\().*(?=\))', func_decl)
    if params:
        kp_params = params.group().split(',')

    if not kp_params:
        raise Exception('config function parameters not found')


def get_struct(name):
    struct_lines = []
    f = kp_type_file
    f.seek(0)
    s = re.search(r'(?:(?:struct)|(?:union))\s+(%s)\s*{' % name, f.read())
    if not s:
        if name and name.endswith('_t'):
            f.seek(0)
            s = re.search(r'(?:(?:struct)|(?:union))\s+(%s)\s*{' % name[:-2],
                          f.read())
            if not s:
                raise Exception('struct %s not found in type file' % name)
    start = s.span()[0]
    f.seek(start)

    brace = 0
    l = f.readline()
    struct_lines.append(l)
    while True:
        lb = l.count('{')
        brace += lb
        rb = l.count('}')
        brace -= rb
        if rb and brace == 0:
            break
        l = f.readline()
        if not l:
            break
        struct_lines.append(l)

    return struct_lines


def get_member(struct_lines, member):
    # member in line
    member_re = re.compile(r'.*\W%s[\W].*' % member)
    # member is struct or union
    struct_re = re.compile(r"""
    (?:(?:struct)|(?:union))*   # composite type
    \s+                         # space
    (\w+)                       # identifier
    \s+                         # space
    \W+                         # non identifier
    \s*                         # opt space
    %s                          # variable name
    \W+                         # non identifier
    """ % member, re.X)

    i = 0
    inner = False
    inner_offset_line = ''
    for i, line in enumerate(struct_lines):
        sch = member_re.search(line)
        if sch:
            sch = struct_re.search(line)
            if sch:
                return sch.group(1), line
            # inner struct or union
            elif re.search(r'\}\W*%s\W' % member, line):
                inner = True
                inner_offset_line = line
                break
            else:
                return '', line

    res = []
    brace = 0
    if inner:
        for j in range(i, -1, -1):
            line = struct_lines[j]
            res.append(line)
            if line.count('}'):
                brace += 1
            if line.count('{'):
                brace -= 1
                if brace == 0:
                    break
        return list(reversed(res)), inner_offset_line

    raise Exception('get member failed: %s' % member)


def get_member_offset(line):
    # unsigned int sk_kern_sock:1; /* 536: 1 4 */
    offset_re = re.compile(r"""
    (?::(\d+))?;            # sk_kern_sock:1;
    \s+                     # space
    /\*                     # /*  start comment
    \s+                     # space
    (\d+)                   # offset 536
    (?::(?:\s+)?(\d+))?     # bitfield offset 1
    \s+                     # space
    (\d+)                   # member length 4
    \s+                     # space
    \*/                     # */   end comment
    """, re.X)
    offset = offset_re.search(line)
    if not offset:
        raise Exception('get member offset failed: %s' % line)
    return offset.groups()


def get_length(type_name):
    if type_name not in kp_struct:
        kp_struct[type_name] = get_struct(type_name)

    for line in kp_struct[type_name]:
        str_len = re.search(r'/\*\s+size:\s+(\d+)', line)
        if str_len:
            return str_len.group(1)
    raise Exception('get length failed: %s' % type_name)


def get_ftrace_offset(accs_mems):
    offsets = []
    mem_len = 0
    inner_start = 0
    bit_len = ''
    is_mem_str = False
    struct_re = re.compile(r'(?:(?:struct)|(?:union))\W+(\w+)[*\s]*')

    # register
    if accs_mems[0] not in kp_cast:
        ty = struct_re.search(kp_params[int(accs_mems[0][2:])])
        if ty:
            kp_cast[accs_mems[0]] = ty.group(1)

    for i, mem in enumerate(accs_mems):
        if i == 0 or mem in ['.', '->']:
            continue

        prev_m = accs_mems[i - 2]
        prev_t = kp_cast[prev_m]
        if type(prev_t) == str:
            if prev_t not in kp_struct:
                kp_struct[prev_t] = get_struct(prev_t)
            if (prev_t, mem) in kp_mem:
                m_type, m_line = kp_mem[(prev_t, mem)]
            else:
                m_type, m_line = get_member(kp_struct[prev_t], mem)
                kp_mem[(prev_t, mem)] = [m_type, m_line]
        elif type(prev_t) == list:
            m_type, m_line = get_member(prev_t, mem)
        else:
            raise Exception('struct type not specified')

        if mem not in kp_cast and m_type:
            kp_cast[mem] = m_type

        mem_offs = get_member_offset(m_line)

        ext = kp_sizeof[prev_m] if prev_m in kp_sizeof else 0

        # bitfields
        if mem_offs[0]:
            # b<bit-width>@<bit-offset>/<container-size>
            bit_width, mem_off, bit_offset, c_size = mem_offs
            mem_off = int(mem_off) + ext
            mem_len = int(c_size) * 8
            bit_len = 'b%s@%s/%s' % (bit_width, bit_offset, str(mem_len))
        else:
            mem_off = int(mem_offs[1]) + ext
            mem_len = int(mem_offs[3]) * 8

            if i == len(accs_mems) - 1:
                str_sch = re.search(r'char[^\w*]+(%s)\W*\[(.*)\]' % mem, m_line)
                if str_sch:
                    is_mem_str = True

        if type(m_type) == list:
            inner_start = int(mem_offs[1])

        if type(prev_t) == list and inner_start:
            mem_off -= inner_start
            inner_start = 0

        if accs_mems[i - 1] == '.':
            if not offsets:
                offsets = [mem_off]
            else:
                offsets[-1] += mem_off
        elif accs_mems[i - 1] == '->':
            offsets.append(mem_off)

    return is_mem_str, bit_len, mem_len, offsets


def align(x):
    container = [8, 16, 32, 64]

    for s in container:
        if x < s:
            return s
    return 0


def get_ftrace_cmd():
    # get 'struct iphdr *'
    s_struct = r'(?:(?:struct)|(?:union))\W+(\w+)[\*\s]*'

    # get 'sizeof(struct iphdr)'
    r_sizeof = re.compile(r'sizeof\(\s*%s\)' % s_struct)

    # sub 'sizeof(struct %s)'
    sub_sizeof = r'sizeof\(\s*(?:(?:struct)|(?:union))\W+%s\s*\)'

    # get 'struct iphdr *)'
    r_struct = re.compile(r'(?:(?:struct)|(?:union))\W+(\w+)[*\s]*\)')

    # get '(struct sock *)%di'
    r_cast = re.compile(s_struct + r'\)([^-.()\s]+)')

    # get cast members
    r_cast_mem = re.compile(r'(?:\.|(?:->))(\w+)\s*(?:([+-]\s*\d+))?\s*\)')

    for k, v in kp_args.items():
        oldv = v
        kp_cast.clear()
        kp_sizeof.clear()

        if kp_final[0].startswith('r:'):
            kp_final.append(k + '=' + v)
            continue

        siz = r_sizeof.findall(v)
        for t in siz:
            t_len = get_length(t)
            v = re.sub(sub_sizeof % t, t_len, v)

        reg_cast = r_cast.findall(v)
        if reg_cast:
            kp_cast[reg_cast[0][1]] = reg_cast[0][0]

        cast_types = r_struct.findall(v)
        if cast_types:
            if reg_cast:
                cast_types.pop()

        cast_mems = r_cast_mem.findall(v)
        if cast_mems:
            for i, m in enumerate(reversed(cast_mems)):
                kp_cast[m[0]] = cast_types[i]
                if m[1]:
                    kp_sizeof[m[0]] = int(m[1].replace(' ', ''))

        # remove sizeof
        oldv = re.sub(r'[+-]\s*' + sub_sizeof % '\w+', '', oldv)
        # remove '+ 20'
        oldv = re.sub(r'[+-]\s*\d+\s*', '', oldv)
        # remove 'struct iphdr *'
        oldv = re.sub(s_struct, '', oldv)
        # remove parenthesis
        oldv = re.sub(r'\(|\)|\s', '', oldv)

        accs_mems = re.split(r'((?:->)|(?:\.))', oldv)
        is_mem_str, bit_len, mem_len, offsets = get_ftrace_offset(accs_mems)
        reg = kp_regs[uname_m][int(accs_mems[0][2:])]
        arg_list = [reg]

        for off in offsets:
            arg_list.append('%+d(' % off)
        arg_list.append(k + '=')
        arg_list.reverse()
        arg_list.append(')' * len(offsets))

        if is_mem_str:
            if k in kp_spec:
                spec = kp_spec[k]
                if spec == 'b':
                    arg_list.append(
                        ':' + 'b%s@0/%s' % (mem_len, align(mem_len)))
                else:
                    arg_list.append(':' + spec)
            else:
                arg_list.append(':string')
        elif bit_len:
            arg_list.append(':' + bit_len)
        elif mem_len != 0:
            arg_list.append(':x' + str(mem_len))

        kp_final.append(''.join(arg_list))


def gen_ftrace_cmd():
    cmds = [
        "echo '{0}'>>{1}".format(' '.join(kp_final),
                                 '/sys/kernel/debug/tracing/kprobe_events')
    ]
    if kp_flt:
        cmds.append(
            "echo '{0}'>{1}".format(kp_flt,
            '/sys/kernel/debug/tracing/events/kprobes/%s/filter' % kp_event))
    return cmds


def clear_params():
    global kp_event
    global kp_final
    global kp_flt
    global kp_sym
    global kp_params

    kp_event = ''
    kp_sym = ''
    kp_flt = ''
    kp_final = []
    kp_params = []

    kp_args.clear()
    kp_cast.clear()
    kp_sizeof.clear()
    kp_spec.clear()


def parse_config_one_cmd(cmd):
    parse_cmd(cmd)
    get_ftrace_cmd()
    cmds = gen_ftrace_cmd()
    clear_params()
    return cmds


def parse_multi_cmds(cmd_str):
    parse_env()
    res = []
    cmds = []
    elems = re.split(r'(p:|r:)', cmd_str)
    for e in elems:
        e = e.strip()
        if not e:
            continue
        if e in ['p:', 'r:']:
            cmds.append(e)
        else:
            cmds[-1] += e

    for cmd in cmds:
        parse_cmd(cmd)
        get_func_params(kp_sym)
        get_ftrace_cmd()
        res.extend(gen_ftrace_cmd())
        clear_params()
    clear_env()

    return res


def get_function(decl):
    func_decl = []
    for line in decl.split('\n'):
        if '=' not in line:
            func_decl.append(line)
        else:
            break
    func_decl = ''.join(func_decl)

    strip_params = re.sub(r'(?<=\().*(?=\))', '', func_decl)
    func_name = re.search(r'\W*(\w+)\(\)', strip_params)
    return func_decl, func_name.group(1)


def read_func_decl(func_decl):
    para_dict = {}
    brackets = []
    count = 0

    for m, v in enumerate(func_decl):
        if v in ['(', ')']:
            brackets.append(m)
            count += 1

    if count > 2:
        num = (count - 2) // 4
        temp = func_decl[0:brackets[1]]
        for i in range(num):
            temp += func_decl[brackets[i + 1] + 1:brackets[i + 2]]
        func_line = temp + func_decl[brackets[-2] + 1:brackets[-1] + 1]
    else:
        func_line = func_decl

    para_list = func_line[brackets[0] + 1:-1].split(',')
    for m, v in enumerate(para_list):
        v = v.replace('*', '')
        v_l = v.split()
        para_dict[v_l[-1]] = [m, v_l[-2]]
    return para_dict


def trans_kprobe(probe):
    regs = ['%r0', '%r1', '%r2', '%r3', '%r4', '%r5', '%r6']

    func_decl, func_name = get_function(probe)
    para_dict = read_func_decl(func_decl)
    get_config_func_params(func_decl)

    one_cmd = ['p:{0} {0}'.format(func_name)]
    for line in probe.split('\n'):
        line = line.strip()
        if line.startswith('#'):
            continue
        par = re.search(r'(=.*?)(\w+)\)*[.-]', line)
        par_line = False
        if par:
            line = re.sub(
                r'(=.*?)(%s)(\)*[.-])' % par.group(2),
                r'\1%s\3' % regs[para_dict[par.group(2)][0]], line)
            par_line = True
        else:
            par = re.search(r'(=\s*)(\w+)', line)
            if par:
                line = re.sub(
                    r'(=\s*)(\w+)',
                    r'\1%s' % regs[para_dict[par.group(2)][0]], line)
                par_line = True

        if par_line:
            one_cmd.append(line)
    return parse_config_one_cmd(' '.join(one_cmd))


def trans_rprobe(probe):
    _, func_name = get_function(probe)
    rprobe = "echo 'r:{0}_r {0} ret=$retval'>>" \
             "/sys/kernel/debug/tracing/kprobe_events".format(func_name)

    r_filter = re.compile(r'FILTER\s*\'(.*?)\'')

    res = [rprobe]
    for line in probe.split('\n'):
        line = line.strip()
        if line.startswith('#'):
            continue
        rf = r_filter.search(line)
        if rf:
            res.append(
                "echo '{0}'>{1}".format(rf.group(1),
           '/sys/kernel/debug/tracing/events/kprobes/%s_r/filter' % func_name))
    return res


def read_source_file(file):
    src_file = open(file, 'r')
    text = src_file.read()

    kprobes = re.findall(r'p start\n(.*?)\nend', text, re.S)
    rprobes = re.findall(r'r start\n(.*?)\nend', text, re.S)

    cmds = []
    for kpro in kprobes:
        cmd = trans_kprobe(kpro)
        cmds.extend(cmd)

    for rpro in rprobes:
        cmd = trans_rprobe(rpro)
        cmds.extend(cmd)

    src_file.close()
    return cmds


def xd_make_cmd(source, save_file):
    save_file_dir = os.path.dirname(save_file)
    if not os.path.exists(save_file_dir):
        os.mkdir(save_file_dir)

    parse_env()
    source_file = os.path.join(cur_dir, 'source', source)
    cmds = read_source_file(source_file)
    clear_env()
    with open(save_file, 'w') as f:
        f.write('\n'.join(cmds))


if __name__ == '__main__':
    print(parse_multi_cmds(sys.argv[1]))
