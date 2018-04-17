#include <errno.h>
#include <termios.h>


//--------------------------------------------------

int enable_policy(pid_t pid, int size, int password){
	int __res;
	__asm__(
		"int $0x80;"
		: "=a" (__res)
		: "0" (243), "b" (pid), "c"(size), "d"(password)
		:"memory"
		);
	if ((__res) < 0){
		errno = (-__res);
		return -1;
	}
	return __res;
}

int disable_policy(pid_t pid, int password){
	int __res;
	__asm__(
		"int $0x80;"
		: "=a" (__res)
		: "0" (244), "b" (pid), "c"(password)
		:"memory"
		);
	if ((__res) < 0){
		errno = (-__res);
		return -1;
	}
	return __res;
}

int set_process_capabilities(pid_t pid, int new_level, int password){
	int __res;
	__asm__(
		"int $0x80;"
		: "=a" (__res)
		: "0" (245), "b" (pid), "c"(new_level), "d"(password)
		:"memory"
		);
	if ((__res) < 0){
		errno = (-__res);
		return -1;
	}
	return __res;
}

int get_process_log(pid_t pid, int size, struct forbidden_activity_info* user_mem){
	int __res;
	__asm__(
		"int $0x80;"
		: "=a" (__res)
		: "0" (246), "b" (pid), "c"(size), "d"(user_mem)
		:"memory"
		);
	if ((__res) < 0){
		errno = (-__res);
		return -1;
	}
	return __res;
}

//-------------------------------------------------------------------------

#include <linux/sched.h>

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
	if (p->HW1_policy_enable=false)
	{
		return -EINVAL;
	}
	p->HW1_policy_enable=false;
	free_log(p);
	return 0;
}