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
* xd_sysinspect
* xd_scsiiocount
* xd_scsiiotrace

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
* connect失败
* timewait链接复用失败
* 文件句柄超出导致无法创建socket
* 端口复用场景下链接闪断后seq序号异常导致的无法建链
