# coding: utf-8
import os
import io

from subprocess import getstatusoutput as get_output
from xdiagnose.iostack.xdiag import pub
from . import sd_handler as handlers

sd_trace_key = {
    'scsi':[
        'scsi_dispatch_cmd_done',
        'scsi_dispatch_cmd_start',
        'scsi_dispatch_cmd_error',
        'scsi_dispatch_cmd_timeout',
        'scsi_queue_rq'],
    'block':[
        'block_bio_backmerge',
        'block_bio_complete',
        'block_bio_frontmerge',
        'block_bio_queue',
        'block_bio_remap',
        'block_getrq',
        'block_mq_rq_timed_out',
        'block_plug',
        'block_rq_complete',
        'block_rq_insert',
        'block_rq_issue',
        'block_rq_remap',
        'block_rq_requeue',
        'block_unplug'],
    }

TRACE_EVENT = "/sys/kernel/debug/tracing/events/%s/%s/enable"

class SdProbe(pub.DiagParam):
    def __init__(self, args):
        super(SdProbe, self).__init__(args)
        self.cmd_file = 'sd_cmd.sh'
        self.cmd_source = 'sd_kprobe.src'
        self.bio_list = {}

        self.kprobe_func = {}
        self.kretprobe_func = {}
        self.update_regex()
        self.parse_scsi()

    def write_events(self, file):
        with io.open(file, 'w+', encoding='utf-8') as f: 
            for key, events in sd_trace_key.items():
                for event in events: 
                    event_cmd = TRACE_EVENT%(key, event)
                    event_cmd = "echo 1 > %s"%event_cmd 
                    f.write(event_cmd)
                    f.write("\n")
        if f:
            f.close()

    def enable_events(self):
        for key, events in sd_trace_key.items():
            for event in events: 
                event_cmd = TRACE_EVENT%(key, event)
                self.all_func[event] = 1
                os.system("echo 1 > %s"%event_cmd) 

    def unable_events(self):
        for key, events in sd_trace_key.items():
            for event in events: 
                event_cmd = TRACE_EVENT%(key, event)
                os.system("echo 0 > %s"%event_cmd) 

    def parse_scsi(self):
        status, scsi_list = get_output("lsscsi -b")
        if status:
            print("lsscsi failed!")
            return

        for scsi in scsi_list.splitlines():
            scsi = scsi.split()
            host = scsi[0]
            dev = scsi[1]
            status, devno = get_output(
                "lsblk %s | grep -v NAME | head -1 | awk '{print $2}'"%dev)
            if status:
                print("%s not exist!"%dev)
                return

            devno = devno.replace(":", ",")
            self.host_dict[host] = devno

    def _register_kprobe(self):
        for item in dir(handlers):
            if item.startswith('func_') and not item.endswith('_r'):
                self.kprobe_func[item[5:]] = getattr(handlers, item)

    def _register_kretprobe(self):
        for item in dir(handlers):
            if item.startswith('func_') and item.endswith('_r'):
                self.kretprobe_func[item[5:-2]] = getattr(handlers, item)
    
    def proto_init(self):
        self._register_kprobe()
        self._register_kretprobe()

    def proto_trace(self, line, pkt_dict):
        cpu = pkt_dict['cpu']
        function = pkt_dict['function']

        if function in self.kprobe_func:
            self.kprobe_func[function](self, line, pkt_dict)
        self.cpu_last_func[cpu] = [pkt_dict, line]

    def proto_ret(self, line, pkt_dict):
        cpu = int(pkt_dict['cpu'])
        func = pkt_dict['function']
        orig_func = func[:-2]

        if orig_func not in self.kretprobe_func:
            return 0

        prev_pack = self.cpu_last_func[cpu]
        self.kretprobe_func[orig_func](self, line, pkt_dict, prev_pack)
        return 1
