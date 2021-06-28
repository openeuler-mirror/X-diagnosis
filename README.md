# X-diagnosis

#### 介绍
X-diagnosis 是操作系统开发和运维的工具集。

工具集包含下面工具：

cpuload  CPU冲高检测工具，使用该工具能够精确的将1秒以内CPU使用率高的进程打印出来。对于性能波动问题很有帮助。

memtool  glibc的内存管理被广泛使用，但调测定位手段有限。该工具可以检测用户态进程内存泄漏，收集用户态进程内存分布信息。

oom_debug_info  是一个内核模块, 该模块可以帮助维护人员, 在操作系统发生OOM的时候, 界定出问题出在哪里。

deadlock  D进程与死锁检查机制。

kernel_debug  精确定位内核模块内存泄漏工具。内核的伙伴系统, slab, LRU, vmalloc管理的内存, 如果内存泄漏, 如何方便定位。

debug_log  CPU冲高采集系统关键信息。方便更精确定位故障位置。




#### 安装教程

```shell
# 基于源码安装
git clone https://gitee.com/openeuler/X-diagnosis.git
cd X-diagnosis
make install

# 基于repo源安装

```



#### 使用说明

请查看每个工具的说明文档。



#### 参与贡献

1.  Fork 本仓库
2.  提交代码
3.  新建 Pull Request



#### 维护者邮件列表

gameoverboss@163.com

liuchao173@huawei.com

liuzixian4@huawei.com

snoweay@163.com



#### FAQ

1. BUG和需求请在这个地址 https://gitee.com/openeuler/X-diagnosis/issues 提issue。
2. 任何软件相关的问题都可以发邮件给维护者。期待你的邮件。

