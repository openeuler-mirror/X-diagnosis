# X-diagnosis

#### Introduction

X-diagnosis is a tool set for operating system development and operation & maintenance.  

The tool set includes the following tools:  

cpuload CPU flushing detection tool, which can accurately print out processes with high CPU usage within 1 second. It is very helpful for handling performance fluctuations.  

memtool glibc memory management tool, which is widely used but has limited debugging and fault locating methods. It can detect memory leaks in user-mode processes and collect memory distribution information in user-mode processes.  

oom_debug_info, which is a kernel module that can help maintainers find where the problem lies when the operating system encounters OOM.  

deadlock D, which is a process and deadlock checking mechanism.  

kernel_debug, which is a tool for accurately locating memory leaks in kernel modules. It is effective for the kernel's partner systems, memory managed by slab, LRU, and vmalloc.  

debug_log, which collects key system information when CPUs rush. It helps to locate faults.  




#### Installation Tutorial

```shell
# Install based on source code
git clone https://gitee.com/openeuler/X-diagnosis.git
cd X-diagnosis
make install

# Install based on repo source

```



#### Instructions for Use

Please check the documentation for each tool.  



#### Contributing

1. Fork this warehouse.  
2. Submit the code.  
3. Create a new Pull Request.  



#### Maintainers

gameoverboss@163.com  

liuchao173@huawei.com  

liuzixian4@huawei.com  

snoweay@163.com  



#### FAQs

1. For bugs and requirements, please submit issues at https://gitee.com/openeuler/X-diagnosis/issues.  
2. Any software related issues can be emailed to a maintainer. Looking forward to your feedback.