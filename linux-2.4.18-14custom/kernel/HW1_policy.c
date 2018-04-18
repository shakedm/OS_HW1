#ifndef _HW1_POLICY
#define _HW1_POLICY

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <asm/current.h>

// HW1 functions:
int add_to_log(int sysCall_thres)
{
    //allocating the new node in the linked list
	forbidden_log_HW1 newNode = (forbidden_log_HW1)kmalloc(sizeof(*newNode), GFP_KERNEL);
	if (!newNode)
	{
		return -1;
	}
    //copying the correct data to the new node
	newNode->data.syscall_req_level=sysCall_thres;
	newNode->data.proc_level=current->HW1_Privileg_Level;
	newNode->data.time=jiffies;
    //in case the list is empty spiecal treatment
	if(current->last_log==NULL){
		current->head_log=newNode;
		current->last_log=newNode;
		newNode->next=NULL;
		newNode->prev=NULL;
	}
    //otherwise insert him in the end of the list
	current->last_log->next=newNode;
	newNode->prev=current->last_log;
	current->last_log=newNode;
    newNode->next=NULL;
	return 0;
}
int HW1_count_log(task_t* t){
	int count = 0;
	forbidden_log_HW1 ptr= t->head_log;
	while(ptr!=NULL){
		count++;
		ptr=ptr->next;
	}
	return count;
}
void free_log(task_t* t){
	forbidden_log_HW1 ptr=t->head_log;
	forbidden_log_HW1 next=NULL;
	while(ptr!=NULL){
		next=ptr->next;
		kfree(ptr);
		ptr=next;
	}
}
//HW1 functions end

int sys_enable_policy(pid_t pid,int size,int password){
    if(pid<0 )
        return -ESRCH;
    if(size<0)
        return -EINVAL;
    if(password!= CORRECT_PASS)
        return -EINVAL;
    
    task_t* t=find_task_by_pid(pid);
    if(t==NULL)
        return -ESRCH;

    if(t->HW1_policy_enable)
        return -EINVAL;    

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

int sys_set_process_capabilities(pid_t pid, int new_level, int password){
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
    t->HW1_Privileg_Level=new_level;
    return 0;
}

int sys_get_process_log(pid_t pid, int size, struct forbidden_activity_info* user_mem){
    if(pid<0)
        return -ESRCH;
    if(size<0)
        return -EINVAL;
        printk("find the task\n");
    task_t* t=find_task_by_pid(pid);
    if(!t)
        return -ESRCH; 
        printk("count the list\n");
    if(size> HW1_count_log(t))
        return -EINVAL;
    int i;
    printk("process %d",t->pid);
    printk("start the bloody loop\n");
    for(i=0; i<size ; i++){
        //user_mem[i]=t->head_log->data;//could be bug
        copy_to_user(&(user_mem[i]),&(t->head_log->data),sizeof(struct forbidden_activity_info));
        printk("copy the %d data",i);
        forbidden_log_HW1 next= t->head_log->next;
        kfree(t->head_log);
        printk("free the %d log",i);
        t->head_log = next;
        t->head_log->prev=NULL;
    }
    return 0;

}

#endif
