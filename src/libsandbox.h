
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

enum libsandbox_result{
    LIBSANDBOX_RESULT_CONTINUE = 0, // TODO make it so that this is no longer needed
    LIBSANDBOX_RESULT_ERROR,
    LIBSANDBOX_RESULT_FINISHED,
    LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH,
};

struct libsandbox_summary{
    int return_code;
};

struct libsandbox_rules{
    int filesystem_allow_all;
    int filesystem_allow_metadata;
    int networking_allow_all;
};

void libsandbox_rules_init(struct libsandbox_rules * rules, int permissive);

size_t libsandbox_get_ctx_private_size(void);

int libsandbox_fork(char * * command_argv, struct libsandbox_rules * rules, void * ctx_private);
// `command_argv` needs to be null-terminated
// `ctx_private` needs to be a pointer to memory of size `libsandbox_get_ctx_private_size()`

int libsandbox_syscall_allow(void * ctx_private);
int libsandbox_syscall_deny(void * ctx_private);
// called after `libsandbox_next_syscall` to signify access

enum libsandbox_result libsandbox_next_syscall(void * ctx_private, struct libsandbox_summary * summary, char * access_attempt_path, size_t access_attempt_path_size);
