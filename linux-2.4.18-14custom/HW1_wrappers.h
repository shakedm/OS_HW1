#ifndef _HW1_WRAPPERS_
#define _HW1_WRAPPERS_

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


#endif