
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

enum libsandbox_result{
    LIBSANDBOX_RESULT_FINISHED = 0,
    LIBSANDBOX_RESULT_ERROR,
    LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0,
    LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0_PATH1,
};

struct libsandbox_summary{
    int return_code;
    int auto_blocked_syscalls;
};

struct libsandbox_rules{
    int filesystem_allow_all;
    int filesystem_allow_metadata;
    int networking_allow_all;
};

void libsandbox_summary_init(struct libsandbox_summary * summary);

void libsandbox_rules_init(struct libsandbox_rules * rules, int permissive);

size_t libsandbox_get_ctx_private_size(void);

int libsandbox_fork(char * * command_argv, struct libsandbox_rules * rules, void * ctx_private);
// `command_argv` needs to be null-terminated
// `ctx_private` needs to be a pointer to memory of size `libsandbox_get_ctx_private_size()`

int libsandbox_syscall_allow(void * ctx_private);
int libsandbox_syscall_deny(void * ctx_private);
// called after `libsandbox_next_syscall` to signify access

enum libsandbox_result libsandbox_next_syscall(void * ctx_private, struct libsandbox_summary * summary, size_t path_size, char * path0, char * path1);
// `path0` and `path1` need to be buffers of size `path_size` each
