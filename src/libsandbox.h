
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

int libsandbox_fork(char * * command_argv, pid_t * new_process_pid);
// `command_argv` needs to be null-terminated

int libsandbox_next_syscall(pid_t sandboxed_process_pid, int * finished, int * return_code, int * processes_running, int * processes_failed);
// TODO there really should be a struct