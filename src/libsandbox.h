
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

enum libsandbox_result{
    LIBSANDBOX_RESULT_CONTINUE = 0,
    LIBSANDBOX_RESULT_FINISHED,
    LIBSANDBOX_RESULT_ERROR,
};

struct libsandbox_summary{
    int return_code;
};

size_t libsandbox_get_ctx_private_size(void);

int libsandbox_fork(char * * command_argv, void * ctx_private);
// `command_argv` needs to be null-terminated
// `ctx_private` needs to be a pointer to memory of length `libsandbox_get_ctx_private_size()`

enum libsandbox_result libsandbox_next_syscall(void * ctx_private, struct libsandbox_summary * summary);
