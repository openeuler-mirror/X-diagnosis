#ifndef __COMMON_U_H__
#define __COMMON_U_H__
#include <sys/resource.h>
#include <sys/utsname.h>

struct kversion {
	unsigned int major;
	unsigned int minor;
	unsigned int patch;
};

static inline int utils_get_kversion(struct kversion *v)
{
	struct utsname info;

	uname(&info);
	if (sscanf(info.release, "%u.%u.%u", &v->major,
		   &v->minor, &v->patch) != 3) {
		return 1;
	}

	return 0;
}

static void memlock_rlimit(void)                                          
{                                                                               
    struct rlimit rlim_new = {                                                  
        .rlim_cur       = RLIM_INFINITY,                                        
        .rlim_max       = RLIM_INFINITY,                                        
    };                                                                          
                                                                                
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {                                 
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");          
        exit(1);                                                                
    }                                                                           
}

#endif
