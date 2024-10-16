
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

struct libsandbox_sandbox_data{
    int finished;
    int return_code;
};

int libsandbox_fork(char * * command_argv, void * * ctx_private);
// `command_argv` needs to be null-terminated

int libsandbox_next_syscall(struct libsandbox_sandbox_data * ctx, void * ctx_private);
