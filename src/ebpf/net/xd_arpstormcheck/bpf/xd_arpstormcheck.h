#ifndef __XARPCHECK_H__
#define __XARPCHECK_H__

#define XDIAG_KERN_STACK_DEPTH 64

struct key_xarp {
	unsigned short family;
	unsigned int sip[4];
	unsigned int tip[4];
};

#endif
