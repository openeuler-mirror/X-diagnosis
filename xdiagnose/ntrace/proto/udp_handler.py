# coding: utf-8
import re
import time
import threading
from collections import OrderedDict
from struct import pack
from socket import ntohl, inet_ntoa, ntohs

from xdiagnose.common.logger import logger


FLOW_START = 1
FLOW_END = 2
func_type = {
    '__ip_local_out':      FLOW_START,
    'dev_hard_start_xmit': FLOW_END,
    'napi_gro_receive':    FLOW_START,
    'udp_queue_rcv_skb':   FLOW_END
}

nf_inet_hooks = {'0': 'NF_INET_PRE_ROUTING',
        '1': 'NF_INET_LOCAL_IN',
        '2': 'NF_INET_FORWARD',
        '3': 'NF_INET_LOCAL_OUT',
        '4': 'NF_INET_POST_ROUTING',
        '5': 'NF_INET_NUMHOOKS'}

check_timer = None
queue_lock = threading.Lock()
pack_queue = OrderedDict()


class UdpPackNode(object):
    def __init__(self):
        self.skb = None
        self.finish = False
        self.pack_list = []
        self.line_list = []
        self.enque_time = 0.0


def packet_loss_print(npara, skb):
    last_line = pack_queue[skb].line_list[-1]
    udp_extra = ['ip_id', 'devname', 'function', 'hook']

    pkt_dict = npara.analysis_traceline(last_line, udp_extra)
    logger.error('udp %s:%s > %s:%s ipid=%s dev=%s packet loss after %s %s' %
                (
                    pkt_dict.get('srcip', ''), pkt_dict.get('srcport', ''),
                    pkt_dict.get('dstip', ''), pkt_dict.get('dstport', ''),
                    pkt_dict.get('ip_id', ''), pkt_dict.get('devname', ''),
                    pkt_dict.get('function', ''), nf_inet_hooks.get(pkt_dict.get('hook', ''), '')
                ))


def udp_check_incomplete(npara):
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

    check_timer = threading.Timer(1, udp_check_incomplete, (npara,))
    check_timer.start()


def udp_pktnode_init(line, pkt_dict):
    """
    should be called with queue_lock
    """
    skb = pkt_dict['skb']

    pack_queue[skb].skb = skb
    pack_queue[skb].finish = False
    pack_queue[skb].line_list = [line]
    pack_queue[skb].pack_list = [pkt_dict]
    pack_queue[skb].enque_time = time.time()


def udp_element_default(_, line, pkt_dict):
    queue_lock.acquire()

    skb = pkt_dict['skb']
    func = pkt_dict['function']

    if skb in pack_queue:
        pack_queue[skb].pack_list.append(pkt_dict)
        pack_queue[skb].line_list.append(line)

        if func_type.get(func) == FLOW_END:
            pack_queue[skb].finish = True
            pack_queue.pop(skb)

    queue_lock.release()


def func___ip_local_out(npara, line, pkt_dict):
    skb = pkt_dict['skb']
    queue_lock.acquire()
    if skb in pack_queue:
        if not pack_queue[skb].finish:
            packet_loss_print(npara, skb)
            pack_queue.pop(skb)

    if skb not in pack_queue:
        pack_queue[skb] = UdpPackNode()

    udp_pktnode_init(line, pkt_dict)
    queue_lock.release()


def func_ip_output(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func___dev_queue_xmit(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_dev_hard_start_xmit(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_sch_direct_xmit(npara, line, pkt_dict):
    pkt_dict2 = npara.analysis_traceline(line, ['devname', 'txq_state'])
    if 'txq_state' in pkt_dict2 and int(pkt_dict2['txq_state'], 16) != 0:
        logger.warning("dev(%s) txq_state:%s"
                        % (pkt_dict2['devname'], pkt_dict2['txq_state']))

    udp_element_default(npara, line, pkt_dict)


def func_nf_hook_slow(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_napi_gro_receive(npara, line, pkt_dict):
    global check_timer

    if not check_timer:
        check_timer = threading.Timer(1, udp_check_incomplete, (npara,))
        check_timer.start()

    skb = pkt_dict['skb']
    queue_lock.acquire()
    if skb in pack_queue:
        if not pack_queue[skb].finish:
            packet_loss_print(npara, skb)
            pack_queue.pop(skb)

    if skb not in pack_queue:
        pack_queue[skb] = UdpPackNode()

    udp_pktnode_init(line, pkt_dict)
    queue_lock.release()


def func___netif_receive_skb_one_core(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_ip_rcv(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_ip_rcv_finish(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_ip_local_deliver(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_ip_local_deliver_finish(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func___udp4_lib_rcv(npara, line, pkt_dict):
    udp_element_default(npara, line, pkt_dict)


def func_udp_queue_rcv_skb(_1, _2, pkt_dict):
    skb = pkt_dict['skb']
    queue_lock.acquire()
    if skb in pack_queue and skb == pack_queue[skb].skb:
        pack_queue[skb].finish = True
        pack_queue.pop(skb)
    queue_lock.release()

# -----------------------------------------------------------------------------
# Kretprobe handler functions
# -----------------------------------------------------------------------------


def clear_prev(npara, pkt_dict):
    """
    Kretprobe trace accurred when abnormal cases happen, so find the
    previous kprobe function of same cpu and clear from packet queue.
    """
    cpu = int(pkt_dict['cpu'])

    prev_pack = npara.cpu_last_func[cpu]
    prev_dict = prev_pack[0]
    prev_skb = prev_dict.get('skb')

    queue_lock.acquire()
    if prev_skb in pack_queue:
        packet_loss_print(npara, prev_skb)
        pack_queue.pop(prev_skb)
    queue_lock.release()


def func_inet_bind_r(npara, _, pkt_dict, prev_pkt):
    addr = re.search('addr=(?:0x)?([a-f0-9]+)', prev_pkt[1]).group(1)
    srcport = re.search('srcport=(?:0x)?([a-f0-9]+)', prev_pkt[1]).group(1)
    sk_bound_dev_if = re.search('sk_bound_dev_if=(?:0x)?([a-f0-9]+)', prev_pkt[1]).group(1)

    log_str = 'inet_bind ip:%s sport:%d if:%s ' % (
                inet_ntoa(pack("=I", int(addr, 16))),
                ntohs(int(srcport, 16)),
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


def func___udp4_lib_lookup_r(npara, _, pkt_dict, prev_pkt):
    pkt_dict_2 = npara.analysis_traceline(prev_pkt[1])
    logger.info("udp %s:%s > %s:%s find udp failed" % (
                        pkt_dict_2['srcip'], pkt_dict_2['srcport'],
                        pkt_dict_2['dstip'], pkt_dict_2['dstport']),
            )
    clear_prev(npara, pkt_dict)


def func_ip_route_input_noref_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffee':
        logger.error('func ip_route_input_noref ret -EXDEV. Please check rp_filter, route and rule')
        clear_prev(npara, pkt_dict)


def func_pfifo_fast_enqueue_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == '2':
        logger.error('pfifo_fast_enqueue ret drop, some drv is full')
        clear_prev(npara, pkt_dict)


def func_ip_finish_output_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffea':
        logger.error('func ip_finish_output ret -EINVAL, arp entry is full')
        clear_prev(npara, pkt_dict)


def func___udp_enqueue_schedule_skb_r(npara, _1, pkt_dict, _2):
    if 'ret' in pkt_dict:
        logger.error('func __udp_enqueue_schedule_skb ret %s, rcv_buf is full' % pkt_dict['ret'])
        clear_prev(npara, pkt_dict)
