# coding: utf-8
import re
from xdiagnose.common.logger import logger


scsi_err =  {
        "1":    "host state err, please check host state!",
        "2":    "target busy",
        "3":    "host queue busy",
        "4":    "scsi prep cmnd failed",
        "5":    "scsi command failed, please check scsi lower!",
        }

blk_err =  {
        "-1":    "operation not supported",
        "-2":    "timeout",
        "-3":    "critical space allocation",
        "-4":    "recoverable transport",
        "-5":    "critical target",
        "-6":    "critical nexus",
        "-7":    "critical medium",
        "-8":    "protection",
        "-9":    "kernel resource",
        "-10":   "device resource",
        "-11":   "nonblocking retry",
        "-12":   "dm internal retry",
        "-13":   "I/O",
        }


def print_proc_timestamp(procs_list):
    for proc in procs_list:
        logger.error('[%f]: %s %s' % (
            proc['timestamp'], proc['function'],
            proc['data'] if 'data' in proc else ''
        ))


def search_bio_key(npara, key):
    if key in npara.bio_list:
        return key
    elif key in npara.bio_remap:
        return search_bio_key(npara, npara.bio_remap[key])
    return ''


def get_data_from_line(pkt_dict, line):
    function = pkt_dict['function']
    re_data = re.search(r'%s: (.+)' % function, line)
    return re_data.group(1) if re_data else None


def func_block_bio_frontmerge(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[2]
    sector = str(int(data[2]) + int(data[4]))
    if sector in npara.bio_list:
        frontbio = npara.bio_list.pop(sector)
        npara.bio_list[key] = frontbio
        npara.bio_list[key].append(pkt_dict)
    else:
        npara.bio_list[key] = [pkt_dict]


def func_block_getrq(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[2]
    npara.bio_list[key] = [pkt_dict]


def func_block_rq_insert(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[4]
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_block_rq_issue(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[4]
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_block_rq_requeue(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[3]
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_scsi_dispatch_cmd_start(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    re_data = re.search(
        r'host_no=([0-9]+) channel=([0-9]+) id=([0-9]+) lun=([0-9]+)', data)
    host = "[%s:%s:%s:%s]" % (
        re_data.group(1), re_data.group(2), re_data.group(3), re_data.group(4))
    if host not in npara.host_dict:
        logger.info("%s not exist!" % host)
        return

    re_data = re.search(r'lba=([0-9]+)', data)
    if not re_data:
        return

    key = npara.host_dict[host] + re_data.group(1)
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_scsi_dispatch_cmd_done(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    re_data = re.search(
        r'host_no=([0-9]+) channel=([0-9]+) id=([0-9]+) lun=([0-9]+)', data)
    host = "[%s:%s:%s:%s]" % (
        re_data.group(1), re_data.group(2), re_data.group(3), re_data.group(4))
    if host not in npara.host_dict:
        logger.info("%s not exist!"%host)
        return

    re_data = re.search(r'lba=([0-9]+)', data)
    if not re_data:
        return

    key = npara.host_dict[host] + re_data.group(1)
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_scsi_dispatch_cmd_error(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    re_data = re.search(
        r'host_no=([0-9]+) channel=([0-9]+) id=([0-9]+) lun=([0-9]+)', data)
    host = "[%s:%s:%s:%s]" % (
        re_data.group(1), re_data.group(2), re_data.group(3), re_data.group(4))
    if host not in npara.host_dict:
        logger.info("%s not exist!"%host)
        return

    re_data = re.search(r'lba=([0-9]+)', data)
    if not re_data:
        return

    key = npara.host_dict[host] + re_data.group(1)
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_scsi_dispatch_cmd_timeout(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    cmnd = re.search(r'cmnd=\(.+\)', data) 
    re_data = re.search(
        r'host_no=([0-9]+) channel=([0-9]+) id=([0-9]+) lun=([0-9]+)', data)
    host = "[%s:%s:%s:%s]" % (
        re_data.group(1), re_data.group(2), re_data.group(3), re_data.group(4))
    logger.error("[%f]:%s scsi %s timeout!" % (pkt_dict['timestamp'], host, cmnd))

    if host not in npara.host_dict:
        logger("%s not exist!"%host)
        return

    re_data = re.search(r'lba=([0-9]+)', line)
    if not re_data:
        return

    key = npara.host_dict[host] + re_data.group(1)
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_scsi_queue_rq(npara, line, pkt_dict):
    cpu = pkt_dict['cpu']
    if 'err_no' in line:
        re_data = re.search(r'err_no=([0-9]+)', line)
        err = re_data.group(1)
        strerr = scsi_err[err] if err in scsi_err else err
        scsiid = ''
        if cpu in npara.cpu_last_func:
            scsiid = npara.cpu_last_func[cpu][0]['scsiid'] if 'scsiid' in npara.cpu_last_func[cpu][0] else ''
        logger.error("[%f]:sd %s scsi error %s"%(pkt_dict['timestamp'], scsiid, strerr))
    elif 'channel' in line:
        re_data = re.search(
            r'host=(0x[a-z0-9]+) channel=(0x[a-z0-9]+) id=(0x[a-z0-9]+) lun=(0x[a-z0-9]+)', line)
        host = int(re_data.group(1), 16)
        channel = int(re_data.group(2), 16)
        scsi_id = int(re_data.group(3), 16)
        lun = int(re_data.group(4), 16)
        scsiid = '[%d:%d:%d:%d]' % (host, channel, scsi_id, lun)
        pkt_dict['scsiid'] = scsiid


def func_scsi_wakup_eh(_1, line, _2):
    re_data = re.search(r'host_no=([0-9]+)', line)
    logger.error("[%f]:host [%s] scsi_wakup_eh!!", re_data.group(1))


def func_scsi_softirq_done(npara, line, pkt_dict):
    re_data = re.search(
        r'maj=(0x[a-z0-9]+) min=(0x[a-z0-9]+) sector=(0x[a-z0-9]+)', line)
    if not re_data:
        return

    dev_maj = re_data.group(1)
    dev_maj = str(int(dev_maj, 16))
    dev_min = re_data.group(2)
    dev_min = str(int(dev_min, 16))
    sector = re_data.group(3)
    sector = str(int(sector, 16))
    key = dev_maj + ',' + dev_min + sector
    if key in npara.bio_list:
        npara.bio_list[key].append(pkt_dict)


def func_block_rq_complete(npara, line, pkt_dict):
    data = get_data_from_line(pkt_dict, line)
    pkt_dict['data'] = data
    data = data.split()
    key = data[0] + data[3]
    err = re.search(r'\[([\-0-9]+)\]', data[-1]).group(1)
    if int(err):
        logger.error("[%f]:%s %s error device %s sector %s" % (
            pkt_dict['timestamp'], pkt_dict['function'],
            blk_err[err], data[0], data[3]))

    if key not in npara.bio_list:
        return 

    bio_procs = npara.bio_list[key]
    bio_procs.append(pkt_dict)
    ctime = pkt_dict['timestamp']
    stime = bio_procs[0]['timestamp']
    # ms
    dtime = (ctime - stime) * 1000

    if dtime >= npara.args.delaytime:
        logger.warning("[%f]:%s %s bio delay time %f ms" % (
            ctime, data[0], data[3], dtime))
        print_proc_timestamp(bio_procs)
    npara.bio_list.pop(key)
