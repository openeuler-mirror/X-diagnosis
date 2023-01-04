##main.c

	###编译方式:
	gcc -o daemon main.c -lpthread -g
	
	###参数说明: 
	第1个参数: g_sleep      控制线程执行周期内睡眠时间单位是秒
	第2个参数: g_cpu_num    控制创建线程个数

	###测试程序的功能：
	配合 inject_rwsem_block 驱动一起使用，测试读写锁对 mmap 的影响。
	创建 g_cpu_num 个线程，线程执行 mmap/munmap/sleep 。

##mm_populate

	echo 'p:enter_mm_populate __mm_populate start=%di len=%si' > /sys/kernel/debug/tracing/kprobe_events
	echo 'r:leave_mm_populate __mm_populate $retval' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:enter_get_user_pages __get_user_pages start=%dx nr_pages=%cx' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'r:leave_get_user_pages __get_user_pages $retval' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:enter handle_mm_fault start=%si fault_flags=%dx' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'r:leave handle_mm_fault $retval' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:enter __do_fault address=%si pgoff=%dx flags=%cx' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'r:leave __do_fault $retval' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:shmem_fault shmem_fault' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:shmem_getpage_gfp shmem_getpage_gfp' >> /sys/kernel/debug/tracing/kprobe_events
	echo 'p:shmem_alloc_page shmem_alloc_page' >> /sys/kernel/debug/tracing/kprobe_events

	echo '(comm=="a.out")' > /sys/kernel/debug/tracing/events/kprobes/filter
	echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable
	echo 1 > /sys/kernel/debug/tracing/tracing_on
	cat /sys/kernel/debug/tracing/trace_pipe
