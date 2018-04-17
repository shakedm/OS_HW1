#ifndef _HW1_POLICY
#define _HW1_POLICY

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/uaccess.h>


int enable_policy(pid_t pid,int size,int password){
    if(pid<0 )
        return -ESRCH;
    if(size<0)
        return -EINVAL;
    if(password!= CORRECT_PASS)
        return -EINVAL;
    
    task_t* t=find_task_by_pid(pid);
    if(t==NULL)
        return -ESRCH;

    t->HW1_policy_enable = true;

    return 0;
}
int sys_disable_policy(pid_t pid, int password){
	if (pid<0) {
		return -ESRCH;
	}
	if (password != CORRECT_PASS){
		return -EINVAL;
	}
	task_t* p=find_task_by_pid(pid);
	if (!p)
	{
		return -ESRCH;
	}
	if (p->HW1_policy_enable==false)
	{
		return -EINVAL;
	}
	p->HW1_policy_enable=false;
	free_log(p);
	return 0;
}

int set_process_capabilities(pid_t pid, int new_level, int password){
    if(pid<0)
        return -ESRCH;
    
    if(new_level<0 || new_level>2)
        return -EINVAL;
    if(password!=CORRECT_PASS)
        return -EINVAL;
    task_t* t=find_task_by_pid(pid);
    if(!t)
        return -ESRCH;
    if(!t->HW1_policy_enable)
        return -EINVAL;
    t->HW1_Privilege_Level=new_level;
    return 0;
}

int get_process_log(pid_t pid, int size, struct forbidden_activity_info* user_mem){
    if(pid<0)
        return -ESRCH;
    if(size<0)
        return -EINVAL;
    task_t* t=find_task_by_pid(pid);
    if(!t)
        return -ESRCH; 
    if(size> HW1_count_log(t))//need to implement this func!!!
        return -EINVAL;
    for(int i=0; i<size ; i++){
        user_mem[i]=t->head_log->data;
        forbidden_log_HW1 next= t->head_log->next;
        kfree(t->head_log);
        head_log = next;
        head_log->prev=NULL;
    }
    return 0;

}


#endif