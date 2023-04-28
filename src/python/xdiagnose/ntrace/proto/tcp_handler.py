# coding: utf-8
import re
import time
import threading
from collections import OrderedDict
from struct import pack
from socket import ntohl, inet_ntoa, ntohs

from xdiagnose.utils.logger import logger


tcp_state = {
    '0': '',
    '1': 'ESTABLISHED',
    '2': 'SYN_SENT',
    '3': 'SYN_RECV',
    '4': 'FIN_WAIT1',
    '5': 'FIN_WAIT2',
    '6': 'TIME_WAIT',
    '7': 'CLOSE',
    '8': 'CLOSE_WAIT',
    '9': 'LAST_ACK',
    'a': 'LISTEN',
    'b': 'CLOSING',
    'c': 'NEW_SYN_RECV'
}

FLOW_START = 1
FLOW_END = 2
func_type = {
    '__ip_local_out':      FLOW_START,
    'dev_hard_start_xmit': FLOW_END,
    'napi_gro_receive':    FLOW_START,
    'tcp_v4_rcv':          FLOW_END
}

nf_inet_hooks = {'0': 'NF_INET_PRE_ROUTING',
        '1': 'NF_INET_LOCAL_IN',
        '2': 'NF_INET_FORWARD',
        '3': 'NF_INET_LOCAL_OUT',
        '4': 'NF_INET_POST_ROUTING',
        '5': 'NF_INET_NUMHOOKS'}

queue_state = {
    1 << 0: "QUEUE_STATE_DRV_XOFF",
    1 << 1: "QUEUE_STATE_STACK_XOFF",
    1 << 2: "QUEUE_STATE_STACK_XOFF",
}

check_timer = None
queue_lock = threading.Lock()
pack_queue = OrderedDict()


class TcpPackNode(object):
    def __init__(self):
        self.skb = None
        self.pack_list = []
        self.line_list = []
        self.enque_time = 0.0


def tcp_flag_state(pkt_dict):
    return '%s%s%s%s' % (
            'S' if pkt_dict.get('tcp_flag_syn') == '1' else '.',
            'A' if pkt_dict.get('tcp_flag_ack') == '1' else '.',
            'F' if pkt_dict.get('tcp_flag_fin') == '1' else '.',
            'R' if pkt_dict.get('tcp_flag_rst') == '1' else '.')


def packet_loss_print(npara, skb):
    last_line = pack_queue[skb].line_list[-1]
    tcp_extra = ['ip_id', 'tcp_seq', 'tcp_ack', 'devname', 'function', 'hook',
                 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst']

    pkt_dict = npara.analysis_traceline(last_line, tcp_extra)
    logger.error('tcp %s:%s > %s:%s ipid=%s seq=%s ack=%s '
                'flags=%s dev=%s packet loss after %s %s'  %
                (
                    pkt_dict.get('srcip', ''), pkt_dict.get('srcport', ''),
                    pkt_dict.get('dstip', ''), pkt_dict.get('dstport', ''),
                    pkt_dict.get('ip_id', ''), pkt_dict.get('tcp_seq', ''),
                    pkt_dict.get('tcp_ack', ''), tcp_flag_state(pkt_dict),
                    pkt_dict.get('devname', ''), pkt_dict.get('function', ''),
                    nf_inet_hooks.get(pkt_dict.get('hook', ''), '')
                ))


def tcp_check_incomplete(npara):
    global check_timer

    if not npara.running:
        return

    cur_time = time.time()

    queue_lock.acquire()
    while len(pack_queue):
        oldest_pack = list(pack_queue.values())[0]
        if cur_time < oldest_pack.enque_time + 1.0:
            break

        packet_loss_print(npara, oldest_pack.skb)
        pack_queue.pop(oldest_pack.skb)
    queue_lock.release()

    check_timer = threading.Timer(1, tcp_check_incomplete, (npara,))
    check_timer.start()


def tcp_pktnode_init(line, pkt_dict):
    """
    should be called with queue_lock
    """
    skb = pkt_dict['skb']

    pack_queue[skb].skb = skb
    pack_queue[skb].line_list = [line]
    pack_queue[skb].pack_list = [pkt_dict]
    pack_queue[skb].enque_time = time.time()


def func_tcp_conn_request(npara, line, pkt_dict):
    backlog = {
        'synrcv_qlen': r'icsk_accept_queue_qlen=(?:0x)?([a-f0-9]+)',
        'accept_qlen': r'sk_ack_backlog=(?:0x)?([a-f0-9]+)',
        'accept_qlen_max': r'sk_max_ack_backlog=(?:0x)?([a-f0-9]+)',
        }
    backlog_2 = {}
    for k, v in backlog.items():
        bak2_re = re.search(v, line)
        if bak2_re:
            backlog_2[k] = bak2_re.group(1)

    accept_qlen_max = int(backlog_2.get('accept_qlen_max', 0), 16)

    if 'accept_qlen' in backlog_2:
        accept_qlen = int(backlog_2['accept_qlen'], 16)
        if accept_qlen > accept_qlen_max:
            pkt_dict_2 = npara.analysis_traceline(line)

            logger.error("tcp %s:%s > %s:%s listen accept queue full,"
                    " qlen:%d max:%d func:%s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    accept_qlen, accept_qlen_max, pkt_dict['function']),
                )

    if 'synrcv_qlen' in backlog_2:
        synrcv_qlen = int(backlog_2['synrcv_qlen'], 16)
        if synrcv_qlen > accept_qlen_max:
            pkt_dict_2 = npara.analysis_traceline(line)

            logger.error("tcp %s:%s > %s:%s syn recv queue full,"
                    " qlen:%d mask:%d func:%s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    synrcv_qlen, accept_qlen_max, pkt_dict['function'])
            )


def func_tcp_rcv_established(npara, line, pkt_dict):
    if npara.args.mode == 1:
        return

    linelist = re.split(' ', line[line.find('sk='):])
    for ll in linelist:
        temp = re.split('=', ll)
        pkt_dict[temp[0]] = temp[1]

    # 乱序队列reordering
    if int(pkt_dict['reordering'], 16) > 10:
        pkt_dict_2 = npara.analysis_traceline(line)

        logger.info("tcp %s:%s > %s:%s reordering is %s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    pkt_dict['reordering'])
                )

    # 发送缓冲区满
    if int(pkt_dict['sk_wmem_queued'], 16) >= \
            int(pkt_dict['sk_sndbuf'], 16) - 10:
        pkt_dict_2 = npara.analysis_traceline(line)

        logger.info('tcp %s:%s > %s:%s '
                    'sendbuf full, sk_wmem_queued:%s sk_sndbuf:%s' % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    pkt_dict['sk_wmem_queued'], pkt_dict['sk_sndbuf'])
                    )

    # 发送空间不够
    if int(pkt_dict['sock_flags'], 16) & 2:
        pkt_dict_2 = npara.analysis_traceline(line)

        logger.info("tcp %s:%s > %s:%s send memory no space" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'])
                )


def func_tcp_retransmit_timer(npara, line, pkt_dict):
    retrans_search = re.search('icsk_retransmits=(?:0x)?([a-f0-9]+) ', line)
    if retrans_search:
        retrans = retrans_search.group(1)
        retrans_num = int(retrans, 16) + 1

        if npara.args.retrans and retrans_num >= npara.args.retrans:
            pkt_dict_2 = npara.analysis_traceline(line)

            logger.warning( "tcp %s:%s > %s:%s retransmits:%d func:%s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    retrans_num, pkt_dict['function'])
                )


def func_tcp_v4_send_synack(npara, line, pkt_dict):
    if npara.args.brief:
        pkt_dict_2 = npara.analysis_traceline(line)

        logger.info("tcp %s:%s > %s:%s event: send synack packet, func:%s" % (
                pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                pkt_dict['function'])
            )


def func_tcp_set_state(npara, line, _):
    old_state_search = re.search(' skc_state=(?:0x)?([a-f0-9]+)', line)
    new_state_search = re.search(' nstate=(?:0x)?([a-f0-9]+)', line)

    if old_state_search and new_state_search:
        old_state = old_state_search.group(1)
        new_state = new_state_search.group(1)

        # change to CLOSE
        if new_state == '7' and old_state not in ['5', '6', '9', 'a']:
            pkt_dict_2 = npara.analysis_traceline(line)

            logger.error("tcp %s:%s > %s:%s state %s change to %s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    tcp_state[old_state], tcp_state[new_state])
                )

        elif npara.args.brief:
            pkt_dict_2 = npara.analysis_traceline(line)

            logger.info("tcp %s:%s > %s:%s state %s change to %s" % (
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    tcp_state[old_state], tcp_state[new_state])
                )


def func_tcp_rcv_state_process(npara, line, _):
    if npara.args.brief:
        skc_state_s = re.search(' skc_state=(?:0x)?([a-f0-9]+) ', line).group(1)
        pkt_dict_2 = npara.analysis_traceline(line,
                                              ['tcp_flag_syn', 'tcp_flag_ack',
                                               'tcp_flag_fin', 'tcp_flag_rst'])

        logger.info("tcp %s:%s > %s:%s "
                    "state %s, receive flags [%s] packet" % (
                    pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                    pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                    tcp_state[skc_state_s], tcp_flag_state(pkt_dict_2))
               )


def func_tcp_drop(npara, line, pkt_dict):
    cpu = pkt_dict['cpu']
    skc_state_re = re.compile(r' skc_state=(?:0x)?([a-f0-9]+)')

    skc_state = skc_state_re.search(line).group(1)
    if npara.cpu_last_func[cpu][0]['function'] == 'tcp_rcv_state_process':
        prev_state = skc_state_re.search(npara.cpu_last_func[cpu][1]).group(1)
        if prev_state in ['0', '2', 'a']:
            pkt_dict_2 = npara.analysis_traceline(line,
                                            ['tcp_flag_syn', 'tcp_flag_ack',
                                             'tcp_flag_fin', 'tcp_flag_rst'])

            logger.error("tcp %s:%s > %s:%s state %s "
                         "tcp_rcv_state_process rcv %s pkt, drop skb" % (
                         pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                         pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                         tcp_state[prev_state], tcp_flag_state(pkt_dict_2))
                   )

    elif skc_state != '1':
        pkt_dict_2 = npara.analysis_traceline(line)

        logger.error("tcp %s:%s > %s:%s "
                     "%s drop one packet. func:%s, last trace func:%s" % (
                     pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                     pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                     tcp_state[skc_state], pkt_dict['function'],
                     npara.cpu_last_func[cpu][0]['function'])
               )

    if npara.cpu_last_func[cpu][0]['function'] == 'tcp_rcv_state_process':
        prev_state = skc_state_re.search(npara.cpu_last_func[cpu][1]).group(1)
        if prev_state in ['0', '2', 'a']:
            pkt_dict_2 = npara.analysis_traceline(line,
                                            ['tcp_flag_syn', 'tcp_flag_ack',
                                             'tcp_flag_fin', 'tcp_flag_rst'])

            logger.error("tcp %s:%s > %s:%s state %s "
                         "tcp_rcv_state_process rcv %s pkt, drop skb" % (
                         pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                         pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                         tcp_state[prev_state], tcp_flag_state(pkt_dict_2))
                   )


def func_tcp_reset(npara, line, pkt_dict):
    skc_state = re.search(' skc_state=(?:0x)?([a-f0-9]+) ', line).group(1)
    pkt_dict_2 = npara.analysis_traceline(line)

    logger.error("tcp %s:%s > %s:%s "
                 "%s receive remote RST func:%s, last trace func:%s" % (
                 pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                 pkt_dict_2['dstip'], pkt_dict_2['dstport'],
                 tcp_state[skc_state], pkt_dict['function'],
                 npara.cpu_last_func[pkt_dict['cpu']][0]['function']),
           )


def tcp_element_default(_, line, pkt_dict):
    queue_lock.acquire()

    skb = pkt_dict['skb']
    func = pkt_dict['function']

    if skb in pack_queue:
        pack_queue[skb].pack_list.append(pkt_dict)
        pack_queue[skb].line_list.append(line)

        if func_type.get(func) == FLOW_END:
            pack_queue.pop(skb)

    queue_lock.release()


def func___ip_local_out(npara, line, pkt_dict):
    """
    Send flow start
    """
    skb = pkt_dict['skb']
    queue_lock.acquire()
    if skb in pack_queue:
        packet_loss_print(npara, skb)
        pack_queue.pop(skb)

    if skb not in pack_queue:
        pack_queue[skb] = TcpPackNode()

    tcp_pktnode_init(line, pkt_dict)
    queue_lock.release()


def func_ip_output(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func___dev_queue_xmit(npara, line, pkt_dict):
    skb_len = re.search(' skb_len=(?:0x)?([a-f0-9]+) ', line).group(1)
    if skb_len and int(skb_len, 16) > 65535:
        logger.info("Send a big packet")

    tcp_element_default(npara, line, pkt_dict)


def func_dev_hard_start_xmit(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_sch_direct_xmit(npara, line, pkt_dict):
    txq_state = 0
    pkt_dict2 = npara.analysis_traceline(line, ['devname', 'txq_state'])

    if 'txq_state' in pkt_dict2:
        txq_state = int(pkt_dict2['txq_state'], 16)

    if txq_state != 0:
        logger.warning("dev(%s) txq_state:%s reason:%s"
                        % (pkt_dict2['devname'], pkt_dict2['txq_state'],
                           queue_state[txq_state]))

    tcp_element_default(npara, line, pkt_dict)


def func_nf_hook_slow(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_napi_gro_receive(npara, line, pkt_dict):
    """
    Receive flow start
    """
    global check_timer

    if not check_timer:
        check_timer = threading.Timer(1, tcp_check_incomplete, (npara,))
        check_timer.start()

    skb = pkt_dict['skb']
    queue_lock.acquire()
    if skb in pack_queue:
        packet_loss_print(npara, skb)
        pack_queue.pop(skb)

    pack_queue[skb] = TcpPackNode()
    tcp_pktnode_init(line, pkt_dict)
    queue_lock.release()


def func___netif_receive_skb_one_core(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_ip_rcv(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_ip_rcv_finish(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_ip_local_deliver(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_ip_local_deliver_finish(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_tcp_v4_rcv(npara, line, pkt_dict):
    tcp_element_default(npara, line, pkt_dict)


def func_tcp_v4_syn_recv_sock(_1, _2, pkt_dict):
    """
    Receive flow end
    """
    queue_lock.acquire()
    if pkt_dict['skb'] in pack_queue:
        pack_queue.pop(pkt_dict['skb'])
    queue_lock.release()


# -----------------------------------------------------------------------------
# Kretprobe handler functions
# -----------------------------------------------------------------------------

def clear_prev(npara, pkt_dict):
    cpu = int(pkt_dict['cpu'])

    prev_pack = npara.cpu_last_func[cpu]
    prev_dict = prev_pack[0]
    prev_skb = prev_dict.get('skb')

    queue_lock.acquire()
    if prev_skb in pack_queue:
        packet_loss_print(npara, prev_skb)
        pack_queue.pop(prev_skb)
    queue_lock.release()


def func_inet_reqsk_alloc_r(npara, _1, pkt_dict, _2):
    logger.error('inet_reqsk_alloc return NULL, request sock alloc failed')
    clear_prev(npara, pkt_dict)


def func_tcp_filter_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and int(pkt_dict['ret'], 16) == 0xffffffee:
        logger.error('tcp_filter return -ENOMEM(%s). '
                     'Because the skb was allocated from pfmemalloc reserves' %
                     pkt_dict['ret'])
    else:
        logger.error('tcp_filter return %s, drop skb' % pkt_dict['ret'])
    clear_prev(npara, pkt_dict)


def func_inet_bind_r(npara, _, pkt_dict, prev_pkt):
    addr = re.search('daddr=(?:0x)?([a-f0-9]+)', prev_pkt[1]).group(1)
    port = re.search('dport=(?:0x)?([a-f0-9]+)', prev_pkt[1]).group(1)
    sk_bound_dev_if = re.search('sk_bound_dev_if=(?:0x)?([a-f0-9]+)',
                                prev_pkt[1]).group(1)

    log_str = 'inet_bind ip:%s sport:%d if:%s ' % (
                inet_ntoa(pack("=I", int(addr, 16))),
                ntohs(int(port, 16)),
                ntohl(int(sk_bound_dev_if, 16)))

    ret = pkt_dict['ret']
    if ret == 'ffffff9f':
        logger.error(log_str + 'ret -EAFNOSUPPORT(%s). '
                    'Family is not AF_INET' % ret)
    elif ret == 'fffffff3':
        logger.error(log_str + 'ret -EACCES(%s). '
                    'User namespace do not support CAP_NET_BIND_SERVICE' % ret)
    elif ret == 'ffffff9e':
        logger.error(log_str + 'ret -EADDRINUSE(%s). '
                    'Check SO_REUSEADDR and SO_REUSEPORT option' % ret)
    elif ret == 'ffffff9d':
        logger.error(log_str + 'ret -EADDRNOTAVAIL(%s). '
                    'Check sysctl_ip_nonlocal_bind and addr type' % ret)
    else:
        logger.info(log_str + 'ret %s' % ret)
    clear_prev(npara, pkt_dict)


def func_tcp_add_backlog_r(npara, _1, pkt_dict, _2):
    logger.error('tcp_add_backlog drop packet')
    clear_prev(npara, pkt_dict)


def func_tcp_v4_send_synack_r(npara, _1, pkt_dict, _2):
    logger.error('tcp_v4_send_synack return error')
    clear_prev(npara, pkt_dict)


def func___inet_lookup_listener_r(npara, _1, pkt_dict, prev_pkt):
    pkt_dict_2 = npara.analysis_traceline(prev_pkt[1])
    logger.info("tcp %s:%s > %s:%s find tcp failed" % (
                        pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                        pkt_dict_2['dstip'], pkt_dict_2['dstport']),
            )
    clear_prev(npara, pkt_dict)


def func_ip_route_input_noref_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffee':
        logger.error('func ip_route_input_noref ret -EXDEV. '
                     'Please check rp_filter, route and rule')
    clear_prev(npara, pkt_dict)


def func_pfifo_fast_enqueue_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == '2':
        logger.error('pfifo_fast_enqueue ret drop, some drv is full')
    clear_prev(npara, pkt_dict)


def func_ip_finish_output_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffea':
        logger.error('func ip_finish_output ret -EINVAL, arp entry is full')
    clear_prev(npara, pkt_dict)
