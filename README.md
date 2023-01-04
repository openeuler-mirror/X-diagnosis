# x-diagnose

## 概述
X-diagnose基于EulerOS维护团队多年运维经验，通过对案例的总结/分析形成的系统运维工具集，
主要功能包含问题定位、系统巡检/监控、ftrace增强、一键收集日志等功能，是一款集成分析、
流程跟踪、信息定时记录、历史经验固化等功能于一体的OS内核问题定位工具。

## 安装x-diagnose
**(1) 依赖软件**
* python 3.7+

**(2) 下载rpm包**
```
rpm -ivh xdiagnose-1.x-x.rpm
```


## 1.   命令汇总
* xdiag
* xd_tcpreststack
* xd_tcpskinfo
* xd_arpstormcheck
* xd_netvringcheck
* xd_sysinspect
* xd_scsiiocount
* xd_scsiiotrace
* xd_ext4fsstat

### 1.0 xdiag
```shell
usage: xdiag [-h] [--inspect] {tcphandcheck,eftrace,ntrace,hook} ...

xdiagnose tool

optional arguments:
  -h, --help            show this help message and exit
  --inspect             inspector module

select module:
  {tcphandcheck,eftrace,ntrace,hook}
    tcphandcheck        tcp_hand_check module
    eftrace             eftrace module
    ntrace              net trace module
    hook                hook module
```

**--inspect ：系统异常巡检(可以和select module一起使用)支持如下检测项：**
* ipv6路由缓存满
* TIMEWAIT状态链接满
* arp、连接跟踪满
* snmp或者stat异常
* 网卡异常统计pause帧、tx_timeout、drop、error
* bond4异常检测:
1)网卡速率不相等
2)lacp协商没有成功
* tcp、udp、ip分片等内存满
* dns无法解析(gethostbyname)
* cron没法运行
* ntp时钟不准
* ip冲突检测
* cpu冲高检测
* 磁盘满、inode句柄不足
* 内存不足、sysctl/sshd配置运行过程中修改

**tcphandcheck：跟踪tcp的3次握手阶段经常会出现问题，支持定位如下问题：**
* 连接队列满
* bind失败
* timewait链接复用失败
* 文件句柄超出导致无法创建socket
* 端口复用场景下链接闪断后seq序号异常导致的无法建链

**eftrace**
#### 概述
eftrace是ftrace命令生成的偏移计算辅助工具。用户可以使用eftrace方便地生成不同内核版本下的ftrace命令。

#### 使用方法
#### (1) 举例：
生成在协议栈调用`ip_rcv_core`函数时打印源地址为`192.168.56.102`的命令：
```shell
xdiag eftrace 'p:ip_rcv_core ip_rcv_core srcip=(struct iphdr *)($r0->data)->saddr f:srcip==0x6638a8c0'
```
生成在协议栈调用`inet_csk_accept`函数结束时返回值为0的命令：
```shell
xdiag eftrace 'r:inet_csk_accept inet_csk_accept ret=$retval f:ret==0'
```
#### (2) 命令解析：
* `p:` 表示kprobe event
* `r:` 表示kretprobe event
* `f:` 表示kprobe filter过滤
* `$rx` 表示函数参数，x为参数位置，第一个参数为`$r0`

#### (3) 可以使用强制类型转换，以及手动指定偏移：
```shell
xdiag eftrace 'p:ip_rcv_finish ip_rcv_finish
srcip=(struct iphdr *)($r2->data)->saddr
srcport=(struct tcphdr *)($r2->data + 20)->source'
```
在函数`ip_rcv_finish`中，`sk_buff`的`data`成员是`unsigned char *`类型，指向报文的ip头，可以强制转换为`iphdr *`获取ip头的内容。

当想获取tcp头的内容时，对`data`进行ip头长度的偏移后可指向tcp头并获取信息。

额外的偏移可以直接指定，或者使用`sizeof`的方式获取偏移长度：

`srcport=(struct tcphdr *)($r2->data + sizeof(struct iphdr))->source`

**sysinspect**
#### 参数说明
sysinspect [-i interval] [-r rotate] [-d dest] [-z gzip] [-s size] [-c cpu_thresh] [-m mem_thresh] [-o]

* -i interval:
  收集日志的时间间隔，单位秒
* -r rotate:
  保留日志的份数
* -d dest:
  日志文件保存的路径
* -z gzip:
  用于压缩日志文件的命令，默认gzip
* -s size:
  指定该参数后使用日志文件的大小(MB)进行日志分割，超过设定值后会被压缩保存。不指定该参数默认按照小时压缩分割
* -o:
  只记录触发CPU、内存阈值门限时的日志。如不指定该参数，则按照时间间隔收集日志
* -c cpu_thresh:
  CPU使用率的阈值，超过阈值、恢复阈值会触发日志记录
* -m mem_thresh:
  内存使用率的阈值，超过阈值、恢复阈值会触发日志记录

#### 日志收集方式
* 每个interval在系统内收集一次信息
* cpu,mem统计以interval为间隔，通过读取/proc下的数据计算使用率

#### 使用示例
#### 以时间为单位抓取日志
`sysinspect -i 30 -r 48`
* -i 30:
  每30秒收集一次日志
* -r 48:
  每小时分割一次日志文件，保留48份日志

#### 以CPU、内存使用率阈值抓取日志
`sysinspect -i 30 -r 20 -s 10 -c 80`
* -i 30
  CPU、内存检查时间间隔30秒
* -r 20
  日志文件保留20份
* -s 10
  日志文件分割大小10(MB)。当日志文件达到指定值10MB时会进行分割
* -c 80
  指定CPU阈值，CPU使用率达到80%时记录一次日志；当使用率降至阈值以下，并重新冲高超过阈值，会再次记录

**ntrace：**
```shell
usage: xdiag ntrace [-h] [-r READ_FILE] [-w WRITE_FILE] [-t TIMEOUT] [--qlen QLEN] [--cpu_mask CPU_MASK] [-b] [-i INTERFACE] {tcp,udp,icmp} ...

optional arguments:
  -h, --help            show this help message and exit
  -r READ_FILE, --read_file READ_FILE
                        read an existing trace file
  -w WRITE_FILE, --write_file WRITE_FILE
                        trace write to a specified file
  -t TIMEOUT, --timeout TIMEOUT
                        specify a running time of process
  --cpu_mask CPU_MASK   set ftrace cpu tracing_mask
  -i INTERFACE, --interface INTERFACE
                        specify an interface

select protocol:
  {tcp,udp,icmp}
    tcp                 tcp protocol
    udp                 udp protocol
    icmp                icmp protocol
```
**expression** ：指定一个过滤报文的表达式，协议[tcp|udp]，地址[host|src|dst]，端口号[port|sport|dport]，逻辑运算符[and|or]。   
**-r** READFILE：读取一个已存在的trace输出文件，比如/var/log/x-diagnose/rawlog/raw_diag.log    
**-w** WRITEFILE：将trace命令日志写入文件  
**-i** INTERFACE：指定抓取的网卡  
**-t** TIMEOUT：运行时间，单位为秒  
**--cpu_mask** CPU_MASK：设置ftrace的cpumask用以跟踪指定的cpu

***说明***：
由于使用ftrace实现，xdiag下的select module功能模块不能复用

**hook：在定位问题时，方便确认各hook点的流程，跟踪这些钩子函数：**
```shell
Usage: hook [ OPTIONS ]
    --dev            网络设备过滤
    --host           IP地址过滤
```
### 1.1 xd_tcpreststack
```shell
Usage: xd_tcpreststack [ OPTIONS ]
    -h,--help           this message
    -t,--time           The frequency of the probe/ms
    -d,--depth           Kernel stack Depth\n
```
#### 功能：
监控tcp协议栈(v4/v6)reset信息。
#### -t,--time
监控的时间间隔，单位ms, 建议保持默认值500ms；
#### -d,--depth
内核调用栈深度，默认3层

### 1.2 xd_tcpskinfo
```shell
Usage: xd_tcpskinfo [ OPTIONS ]
    -h,--help           this message
    -a,--addr           filter IP addr
    -p,--port           filter port
```
#### 功能：
查看tcp链接socket关键的信息，ss命令抓的信息不够全部一些关键信息没有包含。该工具总结tcp链接在debug过程
中经常需要的信息，用来辅助协议栈问题定位。包括如下信息：
#### -a,--addr
IP地址过滤，不区分源地址或者目的地。
####  -p,--port
端口过滤，不区分源端口或者目的端口。

### 1.3 xd_arpstormcheck

```shell
Usage: xd_arpstormcheck [ OPTIONS ]
    -h,--help           this message
    -i,--interval       The interval time of the probe/s
    -c,--count          check count, default 1
    -f,--freq           filter freq, $$ times per second
```
#### 功能：
监控当前网络是否发发生网络风暴。
#### -i,--interval
监控的时间间隔，默认1s。
#### -c,--count
总监控的次数，监控次数完成后监控工具自动退出。
#### -f,--freq 
监控的告警阈值，每秒收到的报文，超过了此阈值，则告警提示网络风暴相关信息；

### 1.4 xd_netvringcheck

```shell
Usage: xd_netvringcheck DEVNAME [rx/tx] [ OPTIONS ]
  [OPTIONS]
	-h,--help			this message
	-i,--interval			The interval time of the probe/s
	-q,--queueidx			filter virtnet queue idx
```

#### 功能：

用于监控virt_net 网卡前后端virtqueue ring的使用状态.

#### DEVNAME

指定需要监控的网卡名称，无默认值，强制指定.

#### [rx/tx]

指定收发队列（发送：tx，接收：rx），无默认值，强制指定.

#### -i,--interval

监控的时间间隔，默认1s.

#### -q,--queueidx

网卡队列的序号，默认监控此网卡的所有队列.

### 1.5 xd_scsiiotrace

```shell
USAGE: xd_scsiiotrace [--help] [-d h:c:t:l] [-E]

EXAMPLES:
    xd_scsiiotrace                 # Report all scsi cmnd result
    xd_scsiiotrace -E              # Report error/timeout scsi cmnd result
    xd_scsiiotrace -p 0x8000002    # Parse the scsi cmnd result.
    xd_scsiiotrace -d 0:0:0:1      # Trace the scsi device only.

  -d, --device=h:c:t:l       Trace this scsi device only
  -E, --error                Trace error/timeout scsi cmnd. (default trace all
                             scsi cmnd)
  -p, --parse=result         Parse the scsi cmnd result.(format hex)
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

#### 功能：
用于监控scsi命令执行结果:  
DRIVER_RESULT： 驱动返回结果  
SCSI_RESULT： SCSI转换后的结果。  
DISPOSION：  
1)SUCCESS:成功  
2)NEEDS_RETRY/ADD_TO_MLQUEUE:重新入队列  
3)TIMEOUT_ERROR: 命令超时  

#### -d,--device
指定需要监控的设备，默认监控所有。
#### -E,--error
只监控不成功的命令（错误或者超时），默认监控所有命令。
#### -p,--parse 
用于解析 DRIVER_RESULT或者SCSI_RESULT值具体含义. 默认显示hex值

### 1.6 xd_scsiiocount

```shell
USAGE: xd_scsiiocount [--help] [-t times] [-d device] [-i interval]

EXAMPLES:
    xd_scsiiocount		# report all scsi device I/O scsi cmnd count
    xd_scsiiocount -i 10	# print 10 second summaries
    xd_scsiiocount -d sdc	# Trace sdc only
    xd_scsiiocount -t 5		# report times

  -d, --device=device        Trace this disk only
  -i, --interval=interval    refresh interval(secs)
  -t, --times=times          report scsi device I/O times
  -?, --help                 Give this help list
      --usage                Give a short usage message
```
#### 功能：
用于监控scsi命令下发的命令统计.
#### -d,--device
指定需要监控的设备，默认监控所有。
#### -i,--interval
监控的时间间隔，默认5s。
#### -t,--times 
监控的次数. 次数达到后，则结束本次监控

### 1.7 xd_ext4fsstat

```shell
USAGE: xd_ext4fstat [--help] [-t times] [-i interval] [-s SORT] [-o opcode]

EXAMPLES:
    xd_ext4fsstat#Trace file read/write stat for ext4 filesystem
    xd_ext4fsstat -i 10#printf 10 second summaries
    xd_ext4fsstat -m /mnt/test#Trace the special mount point for ext4 filesystem.
    xd_ext4fsstat -s r#Sort the read bytes
    xd_ext4fsstat -o r#Trace read only, default read and wriete
    xd_ext4fsstat -t 5#Trace 5 times
    xd_ext4fsstat -v p#show the pid view

  -c, --clean                Clean the trace data
  -C, --clear                Clear the screen
  -i, --interval=INTERVAL    Refreash interval(secs), default 5s.
  -m, --mnt=MNTPOINT         the special mount point
  -o, --opcode=OPCODE        Trace file r/w, defalut both.
  -p, --pid=PID              Trace the pid only
  -s, --sort=SORT            Sort r/w/wb, default read
  -t, --times=TIMES          Trace times
  -T, --top=TOP              show the topN (1~8192)
  -v, --view=VIEW            p:pids view, f: files view, defaut file view
  -?, --help                 Give this help list
      --usage                Give a short usage message
```
#### 功能：
用于监控ext4 文件系统读/写数据量统计.
#### -c,--clean
每个周期统计完数据后，历史数据将被清空，重新统计，默认是累积.
#### -C,--clear
每个周期显示统结果后，清理屏幕
#### -i,--interval
监控的时间间隔，默认5s.
#### -m,--mnt
指定监控特定ext4挂载点数据.
#### -o,--opcode
指定监控read或者write,默认两者都监控.
#### -p,--pid
指定监控特定pid.
#### -s,--sort
指定对监控数据进行排序，默认对read进行排序.
#### -t,--times
监控的次数. 次数达到后，则结束本次监控.
#### -T,--top
指定只显示top数据，默认显示所有监控到的数据.
#### -v,--view
指定显示模式，p:进程模式，f:文件默认，默认只显示文件模式
注：进程模式下，多进程对同一有写入场景下，显示的writeback数据为文件写入总数据
    非该单进程写入总数据.
####
