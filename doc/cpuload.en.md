# cpuload

The CPU usage detection tool cpuload can be used to print processes with high CPU usage.
Implementation principle: Use the bcc tool to accurately trace scheduling tracks and collect statistics on processes with high CPU usage.
python /usr/share/bcc/tools/cpuload
-t Interval for calculating the CPU usage. The value ranges from 0 to 60000, in milliseconds. If the value is 0, thread information is printed each time a scheduling occurs. The default value is 1000.
-n Displays the top CPU usage. The default value is 3.
-p Sets the CPU usage threshold. When the CPU usage exceeds the threshold, the system displays information. The value ranges from 0 to 100. The default value is 90.
-m Sets the size of the circular buffer for recording scheduling tracks. 1000 to 1000000. The default value is 10000.


cpuload calculates the cpu usage, showing which tasks run out of cpu resource.

It display top N tasks when the cpu usage exceeds more than P% and calculates
every T ms.

This works by tracing the sched switch events using tracepoints.

Since this uses BPF, only the root user can use this tool.

optional arguments:
  -h, --help            show this help message and exit
  -t TIME, --time TIME  interval for calculating the CPU usage, in milliseconds(0 - 60000), default 1000
  -n NUMBER, --number NUMBER
                        display top n tasks with high cpu usage, default 3
  -p PERCENT_LIMIT, --percent_limit PERCENT_LIMIT
                        display when the usage of a cpu exceeds percent_limit(0 - 100), default 90
  -m MAX_ENTRY, --max_entry MAX_ENTRY
                        size of the cyclic buffer for recording the scheduling track(1000 - 1000000), default 10000

example:
[root@localhost ~]# ./cpuload.py -p 50 -n 2 -t 100
Tracing task switch. Output when cpu is overload. Ctrl-C to end.
DATE                COMM           PID     CPU  TIME(ms) %CPU
2021-01-27 10:40:39 stress-ng-cpu  33179   1    100.529  96.68%
2021-01-27 10:40:39 cpuload.py     395575  1    3.363    03.23%
---------------------------------------------------------------
2021-01-27 10:40:39 stress-ng-cpu  33175   3    107.704  99.73%
2021-01-27 10:40:39 sshd           2259    3    0.226    00.21%
---------------------------------------------------------------
2021-01-27 10:40:39 stress-ng-cpu  33176   0    131.978  99.99%
2021-01-27 10:40:39 kworker/0:0    388650  0    0.017    00.01%
---------------------------------------------------------------
2021-01-27 10:40:39 stress-ng-cpu  33178   2    183.987  99.99%
2021-01-27 10:40:39 kworker/2:0    391880  2    0.011    00.01%
---------------------------------------------------------------

