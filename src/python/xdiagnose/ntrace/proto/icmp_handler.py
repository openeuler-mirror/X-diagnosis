# coding: utf-8
import re

from xdiagnose.utils.logger import logger


nf_inet_hooks = {0: 'NF_INET_PRE_ROUTING',
                 1: 'NF_INET_LOCAL_IN',
                 2: 'NF_INET_FORWARD',
                 3: 'NF_INET_LOCAL_OUT',
                 4: 'NF_INET_POST_ROUTING',
                 5: 'NF_INET_NUMHOOKS'}


class IcmpSeqNode:
    def __init__(self, seq):
        self.icmpseq = seq
        self.rcvtime = 0
        self.rcvconsum = 0
        self.sendtime = 0
        self.sendconsum = 0


class ElementNode:
    def __init__(self, seq):
        self.icmpseq = seq
        self.isactive = False
        self.islocal = False
        self.requestfull = False
        self.replyfull = False
        self.requestdev = ''
        self.inputmac = ''
        self.replydev = ''
        self.request = []
        self.reply = []
        self.requestdata = []
        self.replydata = []


packetdict = dict()
icmpseqdict = dict()
lasticmpseq = dict()


class IcmpPackNode(object):
    def __init__(self):
        self.skb = None
        self.finish = False
        self.pack_list = []
        self.line_list = []
        self.enque_time = 0.0


def get_line_para(line, name):
    s_line = re.search('%s=(?:0x)?([a-f0-9]+)' % name, line)
    if s_line:
        hook = int(s_line.group(1), 16)
        return True, hook
    else:
        return False, 0


# 获取内核调用栈的处理时间
def gettimeout(funclist):
    begin = last = 0
    try:
        if funclist:
            begin = last = funclist[0]['timestamp']
            for func in funclist:
                begin = min(begin, func['timestamp'])
                last = max(last, func['timestamp'])
    except Exception as e:
        print('gettimeout has an error.', e, funclist)

    return begin, last


# 下一个seq已经到来，prev seq还未处理完
def icmp_prevseq(pkt_dict):
    try:
        prevseq = pkt_dict['icmp_seq'] - 1
        if (pkt_dict['icmp_id'], prevseq) not in packetdict:
            return

        if packetdict[pkt_dict['icmp_id'], prevseq].requestfull:
            if not packetdict[pkt_dict['icmp_id'], prevseq].reply:
                icmpseqdict[pkt_dict['icmp_id'], prevseq] = IcmpSeqNode(prevseq)
                begin, last = gettimeout(packetdict[pkt_dict['icmp_id'], prevseq].request)
                icmpseqdict[pkt_dict['icmp_id'], prevseq].sendtime = begin
                icmpseqdict[pkt_dict['icmp_id'], prevseq].sendconsum = last-begin

                logger.error("%s > %s, id=%d, seq=%d, dev=%s. request finish, but not any reply packet." %
                      (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                       packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                       pkt_dict['icmp_id'],
                       prevseq, packetdict[pkt_dict['icmp_id'], prevseq].requestdev))
                if not packetdict[pkt_dict['icmp_id'], prevseq].isactive:
                    logger.error("    Check sysctl icmp_echo_ignore_all\n")
                else:
                    logger.error("    Check network or peer\n")
                # print("Possible reasons:\n"
                #       "1. Check sysctl icmp_echo_ignore_all\n"
                #       "2. Peer does not exist.\n"
                #       "3. Drop packet(drv, network or Peer)\n"
                #       "4. Check peer route and rule\n")
                del (packetdict[pkt_dict['icmp_id'], prevseq])
                return

            log = 'reply'
            lastfunc = packetdict[pkt_dict['icmp_id'], prevseq].reply[-1]['function']
        else:
            log = 'request'
            lastfunc = packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['function']

        if lastfunc:
            if lastfunc == 'neigh_resolve_output':
                logger.error("%s > %s, id=%d, seq=%d, dev=%s, send arp request and wait arp reply\n" %
                      (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                       packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                       pkt_dict['icmp_id'], prevseq,
                       packetdict[pkt_dict['icmp_id'], prevseq].requestdev))
                # print("Possible reasons:\n"
                #       "1. Route error or peer does not exist.\n"
                #       "2. Drop packet(drv, network or Peer)\n"
                #       "3. Arp entry is full(check gc_thresh)\n")
            elif lastfunc == '__dev_queue_xmit':
                logger.error("%s > %s, id=%d, seq=%d, dev=%s, packet lost after __dev_queue_xmit" %
                      (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                       packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                       pkt_dict['icmp_id'], prevseq,
                       packetdict[pkt_dict['icmp_id'], prevseq].requestdev))
                logger.error("Possible reasons:\n"
                      "   Maybe tc drop packet, please check tc rule(tc qdisc).\n")
            elif lastfunc == 'nf_hook_slow':
                if log == 'request':
                    prev_line = packetdict[pkt_dict['icmp_id'], prevseq].requestdata[-1]
                else:
                    prev_line = packetdict[pkt_dict['icmp_id'], prevseq].replydata[-1]

                is_get, hook = get_line_para(prev_line, 'hook')
                if is_get:
                    logger.error("%s > %s, id=%d, seq=%d, %s maybe lost in %s, hook is %s." %
                          (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                           packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                           pkt_dict['icmp_id'], prevseq,
                           log, lastfunc, nf_inet_hooks[hook]))
                else:
                    logger.error("%s > %s, id=%d, seq=%d, %s maybe lost after %s." %
                          (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                           packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                           pkt_dict['icmp_id'], prevseq, log, lastfunc))
            else:
                logger.error("%s > %s, id=%d, seq=%d, %s maybe lost after %s." %
                      (packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['srcip'],
                       packetdict[pkt_dict['icmp_id'], prevseq].request[-1]['dstip'],
                       pkt_dict['icmp_id'], prevseq, log, lastfunc))
        else:
            logger.error("%s > %s, id=%d, seq=%d, maybe error" %
                  (packetdict[pkt_dict['icmp_id'], prevseq].reply[-1]['srcip'],
                   packetdict[pkt_dict['icmp_id'], prevseq].reply[-1]['dstip'],
                   pkt_dict['icmp_id'], prevseq))
            logger.error(packetdict[pkt_dict['icmp_id'], prevseq].requestdata)
            logger.error(packetdict[pkt_dict['icmp_id'], prevseq].replydata)

        del(packetdict[pkt_dict['icmp_id'], prevseq])
    except Exception as e:
        print('icmp_prevseq has an error.', e, pkt_dict)
    return


# 被ping端的打印
def icmp_warn(pkt_dict, icmptime):
    try:
        requestdev = packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestdev
        replydev = packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].replydev
        # 收发的网口不一致
        if requestdev and replydev and requestdev != replydev:
            logger.error("%s > %s, id=%d, seq=%d, time=%.3fms, requestdev:%s, replydev:%s." %
                  (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                   icmptime * 1000, requestdev, replydev))
            print("    Please check in/output dev.\n")
            return False

        # 收发的mac不一致
        if 'src_mac' in pkt_dict and packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].inputmac and \
                pkt_dict['src_mac'] != packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].inputmac:
            log = 'inputmac:%s outputmac:%s' % \
                    (packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].inputmac, pkt_dict['src_mac'])
            logger.error("%s > %s, id=%d, seq=%d, %s time=%.3fms" %
                  (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                   log, icmptime * 1000))
            return False
    except Exception as e:
        print('icmp_passive has an error.', e, pkt_dict)
    return True


def icmp_passive(npara, line, pkt_dict, icmptime, dev):
    try:
        if not npara.args.brief or (icmptime > npara.args.pingtimeout):
            logger.error("%s > %s, id=%d, seq=%d, time=%.3fms, dev=%s" %
                  (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                   icmptime * 1000, dev))
    except Exception as e:
        print('icmp_passive has an error.', e, pkt_dict)
    return


# 主动ping端的打印
def icmp_active(npara, line, pkt_dict, icmptime, ostime, dev):
    # 超过设置的阈值，打印内核消耗的时间
    if not npara.args.brief or (icmptime > npara.args.pingtimeout):
        logger.error("%s > %s, id=%d, seq=%d, time=%.3fms, ostime=%.3fms, dev=%s" %
              (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
               icmptime * 1000, ostime * 1000, dev))
    return


# 处理完整调用栈的icmp
def icmp_full_stack(npara, line, pkt_dict):
    try:
        if pkt_dict['icmp_type'] in [0, 129] and \
                pkt_dict['function'] in ['ping_rcv', 'dev_hard_start_xmit']:
            if packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].islocal and \
                    pkt_dict['function'] == 'dev_hard_start_xmit':
                return
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].replyfull = True
            if npara.args.brief:
                action = 'Recv'
                if pkt_dict['function'].startswith('dev'):
                    action = 'Send'
                logger.error('%s icmp seq %d reply success at func %s' % (action, pkt_dict['icmp_seq'], pkt_dict['function']))
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']] = IcmpSeqNode(pkt_dict['icmp_seq'])
            rcv_begin, rcv_last = gettimeout(packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].reply)
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].rcvtime = rcv_begin
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].rcvconsum = rcv_last - rcv_begin

            send_begin, send_last = gettimeout(packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].request)
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].sendtime = send_begin
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].sendconsum = send_last - send_begin

            icmptime = rcv_last - send_begin
            ostime = send_last - send_begin
            ostime += rcv_last - rcv_begin

            if icmp_warn(pkt_dict, icmptime):
                if pkt_dict['function'] == 'ping_rcv':
                    icmp_active(npara, line, pkt_dict, icmptime,
                                ostime, packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].replydev)
                else:
                    icmp_passive(npara, line, pkt_dict, icmptime,
                                 packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestdev)

            del(packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']])
        elif pkt_dict['function'] in ['icmp_echo', 'icmpv6_echo_reply', 'dev_hard_start_xmit']:
            if packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].islocal and \
                    pkt_dict['function'] == 'dev_hard_start_xmit':
                return
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestfull = True
            if pkt_dict['function'].startswith('dev'):
                packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].isactive = True
            if npara.args.brief:
                action = 'Recv'
                if pkt_dict['function'].startswith('dev'):
                    action = 'Send'
                    packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].isactive = True
                logger.error('\n%s icmp seq %d request success at func %s' % (action, pkt_dict['icmp_seq'], pkt_dict['function']))
            for funcinfo in packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].request:
                if 'skb' in funcinfo and funcinfo['skb'] != pkt_dict['skb']:
                    packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].request.remove(funcinfo)
    except Exception as e:
        print('icmp_full_stack has an error.', e, pkt_dict)
    return


# 只有reply调用栈的处理
def icmp_reply_only(npara, line, pkt_dict):
    try:
        if icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].rcvtime:
            if not npara.args.brief and pkt_dict['function'] == 'dev_hard_start_xmit':
                icmp_time = pkt_dict['timestamp'] - icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].sendtime
                logger.error("%s > %s, id=%d, seq=%d, time=%.3fms, dev=%s." %
                      (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                       icmp_time * 1000, pkt_dict['devname']))
        elif pkt_dict['function'] not in ['__netif_receive_skb_core', 'ip_rcv', 'ipv6_rcv']:
            icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].rcvtime = pkt_dict['timestamp']
            icmp_time = pkt_dict['timestamp'] - icmpseqdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].sendtime
            logger.error("%s > %s, id=%d, seq=%d, time=%.3fms, maybe wait to long." %
                  (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                   icmp_time * 1000))
    except Exception as e:
        print('icmp_reply_only has an error.', e, pkt_dict)
    return


# skb, seq为key
def icmp_element(npara, line, pkt_dict):
    if not pkt_dict or not pkt_dict['icmp_seq']:
        return
    try:
        if pkt_dict['icmp_type'] in [0, 129]:
            pkt_dict['dstip'], pkt_dict['srcip'] = pkt_dict['srcip'], pkt_dict['dstip']
            if (pkt_dict['icmp_id'], pkt_dict['icmp_seq']) not in packetdict:
                if pkt_dict['function'] != 'start_xmit' and (pkt_dict['icmp_id'], pkt_dict['icmp_seq']) in icmpseqdict:
                    icmp_reply_only(npara, line, pkt_dict)
                return

        if (pkt_dict['icmp_id'], pkt_dict['icmp_seq']) not in packetdict:
            global lasticmpseq
            if pkt_dict['icmp_id'] in lasticmpseq and pkt_dict['icmp_seq'] > lasticmpseq[pkt_dict['icmp_id']] + 1:
                logger.error("\nNo trace for icmp packets in seq range of (%d, %d), id is %d.\n" % (lasticmpseq[pkt_dict['icmp_id']], pkt_dict['icmp_seq'], pkt_dict['icmp_id']))

            lasticmpseq[pkt_dict['icmp_id']] = pkt_dict['icmp_seq']
            icmp_prevseq(pkt_dict)
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']] = ElementNode(pkt_dict['icmp_seq'])

        if not packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].islocal and \
                pkt_dict['function'] == '__ip_local_out' and \
                pkt_dict['srcip'] == pkt_dict['dstip']:
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].islocal = True

        if pkt_dict['icmp_type'] in [0, 129]:
            if 'devname' in pkt_dict:
                packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].replydev = pkt_dict['devname']
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].reply.append(pkt_dict)
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].replydata.append(line)
        elif not packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestfull:
            if 'devname' in pkt_dict:
                packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestdev = pkt_dict['devname']
            if not packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].inputmac and \
                    'dst_mac' in pkt_dict:
                packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].inputmac = pkt_dict['dst_mac']

            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].request.append(pkt_dict)
            packetdict[pkt_dict['icmp_id'], pkt_dict['icmp_seq']].requestdata.append(line)

        if 'src_mac' in pkt_dict:
            if (pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']) not in icmpseqdict:
                icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']] = [pkt_dict['src_mac'], pkt_dict['dst_mac']]
            else:
                if icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']][0] != pkt_dict['src_mac'] or \
                        icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']][1] != pkt_dict['dst_mac']:
                    logger.error("%s > %s, id=%d, seq=%d, icmp_type:%d, mac is change.\n"
                          "   func:%s     dev=%s\n"
                          "   old: src_mac=%s     dst_mac=%s\n"
                          "   new: src_mac=%s     dst_mac=%s" %
                          (pkt_dict['srcip'], pkt_dict['dstip'], pkt_dict['icmp_id'], pkt_dict['icmp_seq'],
                           pkt_dict['icmp_type'], pkt_dict['function'], pkt_dict['devname'],
                           icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']][0],
                           icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']][1],
                           pkt_dict['src_mac'], pkt_dict['dst_mac']))
                    icmpseqdict[pkt_dict['icmp_id'], 0, pkt_dict['icmp_type']] = [pkt_dict['src_mac'], pkt_dict['dst_mac']]

        icmp_full_stack(npara, line, pkt_dict)
    except Exception as e:
        print('icmp_element has an error.', e, pkt_dict)
    return


def icmp_trace(npara, line, pkt_dict):
    key_list = ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq', 'src_mac', 'dst_mac', 'ip_id', 'devname']
    pkt_dict.update(npara.analysis_traceline(line, key_list))

    if 'icmp_type' not in pkt_dict:
        return

    pkt_dict['icmp_type'] = int(pkt_dict['icmp_type'], 16)
    pkt_dict['icmp_code'] = int(pkt_dict['icmp_code'], 16)
    pkt_dict['icmp_seq'] = int(pkt_dict['icmp_seq'])
    pkt_dict['icmp_id'] = int(pkt_dict['icmp_id'])

    if pkt_dict['icmp_type'] not in [0x0, 0x8, 0x80, 0x81]:
        return

    if 'srcip' not in pkt_dict or 'dstip' not in pkt_dict:
        return

    try:
        icmp_element(npara, line, pkt_dict)
    except Exception as e:
        print('icmp_trace has an error.', e, pkt_dict)
    return


def func_raw_sendmsg(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_local_out_sk(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_output(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_neigh_resolve_output(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func___dev_queue_xmit(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_sch_direct_xmit(npara, line, pkt_dict):
    pkt_dict2 = npara.analysis_traceline(line, ['devname', 'txq_state'])
    if 'txq_state' in pkt_dict2 and int(pkt_dict2['txq_state'], 16) != 0:
        logger.warning("dev(%s) txq_state:%s"
                        % (pkt_dict2['devname'], pkt_dict2['txq_state']))

    icmp_trace(npara, line, pkt_dict)


def func_dev_hard_start_xmit(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_nf_hook_slow(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_napi_gro_receive(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func___netif_receive_skb_core(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_rcv(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_rcv_finish(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_local_deliver(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ip_local_deliver_finish(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_icmp_rcv(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_icmp_echo(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


def func_ping_rcv(npara, line, pkt_dict):
    icmp_trace(npara, line, pkt_dict)


# -----------------------------------------------------------------------------
# Kretprobe handler functions
# -----------------------------------------------------------------------------

#
# def clear_prev(npara, pkt_dict):
#     '''
#         Kretprobe trace accurred when abnormal cases happen, so find the
#         previous kprobe function of same cpu and clear from packet queue.
#     '''
#     cpu = int(pkt_dict['cpu'])
#
#     prev_pack = npara.cpu_last_func[cpu]
#     prev_dict = prev_pack[0]
#     prev_skb = prev_dict.get('skb')
#
#     queue_lock.acquire()
#     if prev_skb in pack_queue:
#         packet_loss_print(npara, prev_skb)
#         pack_queue.pop(prev_skb)
#     queue_lock.release()


def func_ip_route_input_noref_r(npara, line, pkt_dict, prev_pkt):
    if prev_pkt['function'] == 'ip_rcv_finish' and 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffee':
        logger.error('func ip_route_input_noref ret -EXDEV. Please check rp_filter, route and rule')


def func_pfifo_fast_enqueue_r(npara, line, pkt_dict, prev_pkt):
    if prev_pkt['function'] == '__dev_queue_xmit' and 'ret' in pkt_dict and pkt_dict['ret'] == '2':
        logger.error('pfifo_fast_enqueue ret drop, some drv is full')


def func_ip_finish_output_r(npara, line, pkt_dict, prev_pkt):
    if prev_pkt['function'] == 'ip_output' and 'ret' in pkt_dict and pkt_dict['ret'] == 'ffffffea':
        logger.error('func ip_finish_output ret -EINVAL, arp entry is full')
