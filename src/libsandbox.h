
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

int libsandbox_fork(char * command, char * * command_args, pid_t * new_process_pid);
// `command_argv` needs to be null-terminated
