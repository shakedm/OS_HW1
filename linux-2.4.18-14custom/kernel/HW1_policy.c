#ifndef _HW1_POLICY
#define _HW1_POLICY

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/uaccess.h>


int enable_policy(pid_t pid,int size,int password){
    if(pid<0 )
        return -EINVAL;
    if(size<0)
        return -EINVAL;
    if(password!= CORRECT_PASS)
        return -EINVAL;
    
    task_t t

    //check for faults
    return 0;
}


#endif