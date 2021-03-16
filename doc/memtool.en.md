# memtool

glibc memory debug
The memory management of the glibc is widely used, but the methods for fault locating are limited. A command-line tool is provided to detect memory leakage of user-mode processes and collect memory distribution information about user-mode processes.

Obtains the memory distribution information of user-mode processes.
The implementation principle is to use the gcore to save the memory copy of the process, and then analyze the memory allocation of the memory copy.
memtool show -p -e -f

Detects memory leaks of user-mode processes within a period of time.
The implementation principle is to enable the memory trace mechanism of the glibc through the gdb, and then disable the trace function after a period of time.
memtool trace -p -t -f

