# X-diagnosis

#### Introduction
X-diagnosis is a tool set for operating system development and operation and maintenance.

The tool set includes the following tools:

cpuload CPU flushing detection tool, using this tool can accurately print out processes with high CPU usage within 1 second. It is very helpful for performance fluctuations.

The memory management of memtool glibc is widely used, but the method of adjusting the position is limited. This tool can detect memory leaks in user-mode processes and collect memory distribution information in user-mode processes.

oom_debug_info is a kernel module that can help maintainers to define where the problem lies when the operating system is OOM.

deadlock D process and deadlock checking mechanism.

kernel_debug is a tool for accurately locating memory leaks in kernel modules. The kernel's partner system, memory managed by slab, LRU, vmalloc, if the memory leaks, how to locate it easily.

debug_log CPU rushes to collect the key information of the system. It is convenient to locate the fault location more accurately.




#### Installation tutorial

```shell
# Install based on source code
git clone https://gitee.com/openeuler/X-diagnosis.git
cd X-diagnosis
make install

# Install based on repo source

```



#### Instructions for use

Please check the documentation for each tool.



#### Participate in Contribution

1. Fork this warehouse
2. Submit the code
3. Create a new Pull Request



#### Maintainer mailing list

gameoverboss@163.com

liuchao173@huawei.com

liuzixian4@huawei.com

snoweay@163.com



#### FAQ

1. For bugs and requirements, please submit issues at https://gitee.com/openeuler/X-diagnosis/issues.
2. Any software related issues can be emailed to the maintainer. Looking forward to your mail.
