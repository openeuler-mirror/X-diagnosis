import re
from struct import unpack
from socket import inet_pton, htons, AF_INET, AF_INET6


def is_valid_ipv4(ip):
    try:
        inet_pton(AF_INET, ip)
    except Exception:
        return False
    return ip.count('.') == 3


def is_valid_ipv6(ip):
    try:
        inet_pton(AF_INET6, ip)
    except Exception:
        return False
    return True


def is_valid_ip(ip):
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def parse_expression(filter_str):
    ipv4_flag = False
    ipv6_flag = False
    protos = ['tcp', 'udp', 'icmp', 'icmp6']
    keywords = ['host', 'src', 'dst', 'port', 'sport', 'dport']

    logic_map = {'and': '&&', 'or': '||'}
    proto_map = {'icmp': 1, 'tcp': 6, 'udp': 17, 'icmp6': 58}

    new_parse = []
    raw_parse = re.split('(' + '|'.join(keywords) + '|' + '|'.join(protos) + ')', filter_str)

    for i, token in enumerate(raw_parse):
        token = token.strip()
        if not token:
            continue
        if token in protos or token in keywords:
            new_parse.append(token)
            continue

        if token.endswith('and'):
            new_parse += [t.strip() for t in re.split('(and)$', token) if t.strip()]
        elif token.endswith('or'):
            new_parse += [t.strip() for t in re.split('(or)$', token) if t.strip()]
        elif i == len(raw_parse) - 1:
            new_parse.append(token)
        else:
            raise Exception('Format error')

    prefix, keyword = None, None
    statement = []

    for token in new_parse:
        if token in protos:
            statement.append('(ip_proto==%s)' % str(proto_map[token]))

        elif token in ['and', 'or']:
            statement.append(logic_map[token])

        elif token in keywords:
            keyword = token
            if token == 'host':
                prefix = '(srcip==HOLDER||dstip==HOLDER)'
            elif token == 'src':
                prefix = '(srcip==HOLDER)'
            elif token == 'dst':
                prefix = '(dstip==HOLDER)'
            elif token == 'port':
                prefix = '(srcport==HOLDER||dstport==HOLDER)'
            elif token == 'sport':
                prefix = '(srcport==HOLDER)'
            elif token == 'dport':
                prefix = '(dstport==HOLDER)'
        else:
            substatement = []
            tmp = re.split(r'(and|or)', token)
            tmp = [t.strip() for t in tmp if t.strip()]

            if keyword in ['host', 'src', 'dst']:
                for t in tmp:
                    if t == 'and':
                        substatement.append('&&')
                    elif t == 'or':
                        substatement.append('||')
                    elif is_valid_ipv4(t):
                        ipv4_flag = True
                        substatement.append(prefix.replace('HOLDER', str(unpack('I', inet_pton(AF_INET, t))[0])))
                    elif is_valid_ipv6(t):
                        ipv6_flag = True
                        src_prefix = '((srcip==HOLDER0)&&' +\
                                     '(srcip2==HOLDER1)&&' +\
                                     '(srcip3==HOLDER2)&&' +\
                                     '(srcip4==HOLDER3))'

                        dst_prefix = '((dstip==HOLDER0)&&' +\
                                     '(dstip2==HOLDER1)&&' +\
                                     '(dstip3==HOLDER2)&&' +\
                                     '(dstip4==HOLDER3))'

                        host_prefix = '(' + src_prefix + '||' + dst_prefix + ')'

                        ip6 = unpack('IIII', inet_pton(AF_INET6, t))
                        if keyword == 'host':
                            substatement.append(
                                host_prefix.replace('HOLDER0', str(ip6[0]))\
                                           .replace('HOLDER1', str(ip6[1]))\
                                           .replace('HOLDER2', str(ip6[2]))\
                                           .replace('HOLDER3', str(ip6[3])))
                        elif keyword == 'src':
                            substatement.append(
                                src_prefix.replace('HOLDER0', str(ip6[0]))\
                                          .replace('HOLDER1', str(ip6[1]))\
                                          .replace('HOLDER2', str(ip6[2]))\
                                          .replace('HOLDER3', str(ip6[3])))
                        elif keyword == 'dst':
                            substatement.append(
                                dst_prefix.replace('HOLDER0', str(ip6[0]))\
                                          .replace('HOLDER1', str(ip6[1]))\
                                          .replace('HOLDER2', str(ip6[2]))\
                                          .replace('HOLDER3', str(ip6[3])))

                    else:
                        raise Exception('Address wrong format')

            elif keyword in ['port', 'sport', 'dport']:
                for t in tmp:
                    if t == 'and':
                        substatement.append('&&')
                    elif t == 'or':
                        substatement.append('||')
                    elif t.isdigit() and 0 < int(t) < 65536:
                        substatement.append(prefix.replace('HOLDER', str(htons(int(t)))))
                    else:
                        raise Exception('Port wrong format')

            statement.append(''.join(substatement))

        if ipv4_flag and ipv6_flag:
            raise Exception('Not support both ipv4 and ipv6')

    return statement, ipv4_flag
