#coding: utf-8
import argparse


# xdiagnose argument parser
parser = argparse.ArgumentParser(prog='xdiag', description='x-diagnose tool')

# inspect module
parser.add_argument('--inspect', action='store_true', help='inspector module')

# module parser
subparser = parser.add_subparsers(dest='module', title='select module')

# tcp hand check module
parser_thc = subparser.add_parser('tcphandcheck', help='tcp_hand_check module')

# eftrace module subparser
parser_ef = subparser.add_parser('eftrace', help='eftrace module')
parser_ef.add_argument('-r', '--run', action='store_true',
                       help='set system ftrace')
parser_ef.add_argument('-c', '--clear', action='store_true',
                       help='clear system ftrace')
parser_ef.add_argument('ef_expression',nargs='*', type=str,
                        help='eftrace expression')

# net module subparser
parser_net = subparser.add_parser('ntrace', help='net trace module')

# net common arguments
parser_net.add_argument('-r',
                        '--read_file',
                        type=str, default='',
                        help='read an existing trace file')
parser_net.add_argument('-w',
                        '--write_file',
                        type=str, default='',
                        help='trace write to a specified file')
parser_net.add_argument('-t',
                        '--timeout',
                        type=int, default=0,
                        help='specify a running time of process')
parser_net.add_argument('--qlen',
                        type=int, default=50,
                        help='specify a tc queue length to monitor')
parser_net.add_argument('--cpu_mask',
                        type=str, default='',
                        help='set ftrace cpu tracing_mask')
parser_net.add_argument('-b',
                        '--brief',
                        action='store_true',
                        help='brief output')
parser_net.add_argument('-i', '--interface', type=str,
                        help='specify an interface')

# net protocol arguments, support [tcp udp icmp]
net_subparser = parser_net.add_subparsers(dest='protocol',
                                          title='select protocol',
                                          required=True)

# net protocol tcp arguments
parser_tcp = net_subparser.add_parser('tcp', help='tcp protocol')
parser_tcp.add_argument('--retrans',
                        type=int, help='TCP retransmit limit')
parser_tcp.add_argument('-m',
                        '--mode',
                        type=int, default=1,
                        help='the amount of trace functions, '
                             'default 1, full mode 8')
parser_tcp.add_argument('expression',
                        nargs='*', type=str,
                        help='filter expression')

# net protocol udp arguments
parser_udp = net_subparser.add_parser('udp', help='udp protocol')
parser_udp.add_argument('expression', nargs='+', type=str,
                        help='filter expression')

# net protocol icmp arguments
parser_icmp = net_subparser.add_parser('icmp', help='icmp protocol')
parser_icmp.add_argument('-pingt',
                         '--pingtimeout',
                         type=float, default=1,
                         help='ping timeout')
parser_icmp.add_argument('expression',
                         nargs='*', type=str,
                         help='filter expression')

# hook module
parser_hook = subparser.add_parser('hook', help='hook module')
parser_hook.add_argument('--dev', type=str, default='', help='net devname')
parser_hook.add_argument('--host', type=str, default='', help='ip-address')
