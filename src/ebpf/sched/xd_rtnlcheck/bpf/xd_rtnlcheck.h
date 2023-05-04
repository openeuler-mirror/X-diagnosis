#ifndef __XD_RTNLCHECK_H__
#define __XD_RTNLCHECK_H__

#define TASK_COMM_LEN  16

struct event_rtnl {
	pid_t pid;
	char comm[TASK_COMM_LEN];
};

#endif
