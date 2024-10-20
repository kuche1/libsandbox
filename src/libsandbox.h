
#include <sys/types.h> // pid_t

#ifndef LIBSANDBOX_PRINT_PREFIX
#define LIBSANDBOX_PRINT_PREFIX "libsandbox: "
#endif

// TODO ideally we would have a macro for all output, and then another INFO macro that is used everywhere so that we don't drown ourselves with guards
#ifndef LIBSANDBOX_PRINT_BLOCKED_SYSCALLS
#define LIBSANDBOX_PRINT_BLOCKED_SYSCALLS 0
#endif

enum libsandbox_result{
    LIBSANDBOX_RESULT_FINISHED = 0,
    LIBSANDBOX_RESULT_ERROR,
    LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0,
    LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0_PATH1,
};

enum libsandbox_rule_default{
    LIBSANDBOX_RULE_DEFAULT_PERMISSIVE = 0,
    LIBSANDBOX_RULE_DEFAULT_RESTRICTIVE,
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

ssize_t libsandbox_str_to_path(char * str, char * path, size_t path_size);
// used for converting wishy-washy paths to paths that libsanadbox can work with
// returns (negative on error) or (length of resulting path, without the ending \0)
// TODO this is actually wrong, it actually CAN BE THE CASE that a syscall uses a symlink and not a full path as an argument (abviously) AND THIS CAN BE FIXED, THE APPROPRIATE FUNCTINO NEEDS TO BE FIXED

void libsandbox_rules_init(struct libsandbox_rules * rules, enum libsandbox_rule_default default_permissiveness);

size_t libsandbox_get_ctx_private_size(void);

int libsandbox_fork(char * * command_argv, struct libsandbox_rules * rules, void * ctx_private);
// `command_argv` needs to be null-terminated
// `ctx_private` needs to be a pointer to memory of size `libsandbox_get_ctx_private_size()`

void libsandbox_summary_init(struct libsandbox_summary * summary);

enum libsandbox_result libsandbox_next_syscall(
    void * ctx_private,
    struct libsandbox_summary * summary,
    size_t path_size,
    char * path0,
    size_t * path0_len,
    char * path1,
    size_t * path1_len
);
// `path0` and `path1` need to be buffers of size `path_size` each

int libsandbox_syscall_allow(void * ctx_private);
int libsandbox_syscall_deny(void * ctx_private);
// called after `libsandbox_next_syscall` to signify access
