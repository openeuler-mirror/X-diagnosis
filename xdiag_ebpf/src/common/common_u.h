#ifndef __COMMON_U_H__
#define __COMMON_U_H__
#include <sys/resource.h>
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
