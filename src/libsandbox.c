
#include "libsandbox.h"

#include <unistd.h> // fork
#include <sys/ptrace.h> // ptrace
#include <stdio.h> // fprintf
#include <signal.h> // raise
#include <sys/wait.h> // waitpid
#include <seccomp.h> // scmp_filter_ctx
#include <string.h> // strerror
#include <errno.h> // errno
#include <sys/user.h> // user_regs_struct
#include <sys/syscall.h> // SYS_*
#include <fcntl.h> // AT_FDCWD
#include <sys/stat.h> // stat
#include <sys/socket.h> // AF_LOCAL

//////////
////////// defines/macros
//////////

#define PRINT_PREFIX LIBSANDBOX_PRINT_PREFIX
#define ERR_PREFIX PRINT_PREFIX "ERROR: "

// `RW` means that we can both read and write to the register
// `R` means that the register is read-only
#if __WORDSIZE == 64
    #define CPU_REG_RW_SYSCALL_ID(cpu_regs)  (cpu_regs).orig_rax
    #define CPU_REG_R_SYSCALL_ARG0(cpu_regs) (cpu_regs).rdi
    #define CPU_REG_R_SYSCALL_ARG1(cpu_regs) (cpu_regs).rsi
    #define CPU_REG_R_SYSCALL_ARG2(cpu_regs) (cpu_regs).rdx
    #define CPU_REG_R_SYSCALL_ARG3(cpu_regs) (cpu_regs).r10
    #define CPU_REG_RW_SYSCALL_RET(cpu_regs) (cpu_regs).rax // the return code of the syscall
#else
    #error Only 64bit is supported for now
#endif

#define SECCOMP_RULE_ADD(...) { \
    int ret = seccomp_rule_add(__VA_ARGS__); \
    if((ret != 0) && (ret != -EACCES)){ \
        fprintf(stderr, ERR_PREFIX "call to `seccomp_rule_add` failed\n"); \
        return 1; \
    } \
}

//////////
////////// structures
//////////

struct ctx_private{
    pid_t root_process_pid;
    int processes_running;
    int processes_failed;

    pid_t evaluated_subprocess_pid;
    long evaluated_syscall_id;
    struct user_regs_struct evaluated_cpu_regs;
};

//////////
////////// functions: private
//////////

#include "get_syscall_name.c" // depends on the existing namespace for the SYS_* defines
#include "string_operations.c"
#include "path_extractors.c"
#include "set_seccomp_rules.c"

static inline void sigkill_or_print_err(pid_t pid){
    if(kill(pid, SIGKILL)){
        fprintf(stderr, ERR_PREFIX "could not SIGKILL process with pid `%d`\n", pid);
    }
}

static int libsandbox_syscall_deny_inner(void * ctx_private, int automatically_blocked){
    struct ctx_private * ctx_priv = ctx_private;

    const char * name = get_syscall_name(ctx_priv->evaluated_syscall_id);

    if(automatically_blocked){
        printf(PRINT_PREFIX "automatically ");
    }
    printf("blocking syscall with id `%ld` (%s)\n", ctx_priv->evaluated_syscall_id, name);

    CPU_REG_RW_SYSCALL_ID (ctx_priv->evaluated_cpu_regs) = -1; // invalidate the syscall by changing the ID
    CPU_REG_RW_SYSCALL_RET(ctx_priv->evaluated_cpu_regs) = -1; // also put bad return code, suprisingly this fixes some programs (example: python3)

    // there is might be a way to only set the syscall id reg, and not all of them
    // but it might not necessarily be portable
    if(ptrace(PTRACE_SETREGS, ctx_priv->evaluated_subprocess_pid, NULL, & ctx_priv->evaluated_cpu_regs)){
        printf(ERR_PREFIX "could not PTRACE_SETREGS\n");
        return 1;
    }

    if(ptrace(PTRACE_CONT, ctx_priv->evaluated_subprocess_pid, NULL, NULL)){
        fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
        return 1;
    }

    return 0;
}

//////////
////////// functions: public
//////////

// replaces windows separators (\\) with regular separators (/)
// replaces multiple separators (eg //) with a single separator (/)
// makes sure path doesn't end with /
ssize_t libsandbox_str_to_path(char * str, char * path, size_t path_size){

    // clean up the path

    size_t path_clean_cap = path_size;
    char path_clean[path_clean_cap];
    size_t path_clean_len = 0;

    char ch_prev = 0;

    for(;;){

        if(path_clean_len >= path_clean_cap){
            fprintf(stderr, ERR_PREFIX "not enough mem in buf\n");
            return -1;
        }

        char ch = str[0];

        if(ch == '\\'){
            ch = '/';
        }

        if((ch == '/') && (ch_prev == '/')){
            path_clean_len -= 1;
        }else{
            path_clean[path_clean_len] = ch;
        }

        if(ch == 0){
            break;
        }

        str += 1;

        path_clean_len += 1;
        ch_prev = ch;
    }

    if(path_clean_len > 0){
        if(path_clean[path_clean_len - 1] == '/'){
            path_clean_len -= 1;
            path_clean[path_clean_len - 1] = 0;
        }
    }

    // convert to real path

    ssize_t path_len_or_err = extract_pathlink(getpid(), path_clean, path, path_size);

    if(path_len_or_err < 0){
        fprintf(stderr, ERR_PREFIX "`extract_pathlink` failure\n");
        return -1;
    }

    size_t path_len = path_len_or_err;

    return path_len;
}

void libsandbox_rules_init(struct libsandbox_rules * rules, enum libsandbox_rule_default default_permissiveness){
    int allow = default_permissiveness == LIBSANDBOX_RULE_DEFAULT_PERMISSIVE;
    rules->filesystem_allow_all = allow;
    rules->filesystem_allow_metadata = allow;
    rules->networking_allow_all = allow;
}

size_t libsandbox_get_ctx_private_size(void){
    return sizeof(struct ctx_private);
}

int libsandbox_fork(char * * command_argv, struct libsandbox_rules * rules, void * ctx_private){
    struct ctx_private * ctx_priv = ctx_private;

    if(command_argv[0] == NULL){
        fprintf(stderr, ERR_PREFIX "command name not specified\n");
        return 1;
    }

    pid_t child = fork();

    if(child < 0){

        return 1;

    }else if(child == 0){

        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)){
            fprintf(stderr, ERR_PREFIX "could not trace flag for child\n");
            return 1;
        }

        // pause execution since TRACEME won't do that by itself
        if(raise(SIGSTOP)){
            fprintf(stderr, ERR_PREFIX "could not pause child execution\n");
            return 1;
        }

        if(set_seccomp_rules(rules)){
            return 1;
        }

        execvp(command_argv[0], command_argv);
        // no need to check return code, if the execution continues the call has failed for sure

        fprintf(stderr, ERR_PREFIX "call to `execvp` failed: could not run `%s`; error=`%s`\n", command_argv[0], strerror(errno));

        return 1;

    }else{

        // wait for the SIGSTOP
        int status;
        waitpid(child, & status, 0);

        if(!WIFSTOPPED(status)){ // was child stopped by a delivery of a signal
            fprintf(stderr, ERR_PREFIX "child was not stopped by a delivery of a signal\n");
            sigkill_or_print_err(child);
            return 1;
        }

        if(WSTOPSIG(status) != SIGSTOP){ // which was the signal that caused the child to stop
            fprintf(stderr, ERR_PREFIX "child was was stopped, but not due to SIGSTOP\n");
            sigkill_or_print_err(child);
            return 1;
        }

        // set some more restrictions

        if(ptrace(
            PTRACE_SETOPTIONS,
            child,
            0,
            PTRACE_O_EXITKILL | // make sure to kill the child if the parent exits
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | // trace any new processes created by the child
            PTRACE_O_TRACEEXIT | // get notified when a process exits
            PTRACE_O_TRACESECCOMP // trace syscalls based on seccomp rules
        )){
            fprintf(stderr, ERR_PREFIX "could not set ptrace restrictions for child\n");
            sigkill_or_print_err(child);
            return 1;
        };

        if(ptrace(PTRACE_CONT, child, NULL, NULL)){
            fprintf(stderr, ERR_PREFIX "could not continue child execution\n");
            sigkill_or_print_err(child);
            return 1;
        }

    }

    ctx_priv->root_process_pid = child;
    ctx_priv->processes_running = 1;
    ctx_priv->processes_failed = 0;

    return 0;

}

void libsandbox_summary_init(struct libsandbox_summary * summary){
    summary->return_code = -1;
    summary->auto_blocked_syscalls = 0;
}

// if the result is `LIBSANDBOX_RESULT_ERROR` none of the children are killed - this is the caller's responsibility if he so desires (however, if the caller exits they are going to die)
enum libsandbox_result libsandbox_next_syscall(
    void * ctx_private,
    struct libsandbox_summary * summary,
    size_t path_size,
    char * path0,
    size_t * path0_len,
    char * path1,
    size_t * path1_len
){
    struct ctx_private * ctx_priv = ctx_private;

    for(;;){

        int status;
        pid_t pid = waitpid(-1, & status, 0);
        // the first argument being -1 means: wait for any child process
        // `waitpid` returns when a child's state changes, and that means: the child terminated, the child was stopped by a signal, or the child was resumed by a signal

        // if(pid == -1){
        //     // we're never supposed to reach this
        //     fprintf(stderr, ERR_PREFIX "WTF something is wrong\n");
        //     * finished = 1;
        //     return 0;
        // }
        if(pid == -1){
            fprintf(stderr, ERR_PREFIX "call to `waitpid` failed\n");
            return LIBSANDBOX_RESULT_ERROR;
        }

        if(
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))  ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) )
        ){

            // new process was created

            ctx_priv->processes_running += 1;

            if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
                fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
                return LIBSANDBOX_RESULT_ERROR;
            }

            continue;

        }else if(
            status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))
        ){

            // process died

            ctx_priv->processes_running -= 1;

            unsigned long event_message;
            if(ptrace(PTRACE_GETEVENTMSG, pid, NULL, & event_message)){
                fprintf(stderr, ERR_PREFIX "could not PTRACE_GETEVENTMSG\n");
                return LIBSANDBOX_RESULT_ERROR;
            }

            int code = event_message >> 8;

            if(code){
                // note that it might be the case that the return code signifies something else
                // rather than success/failure
                ctx_priv->processes_failed += 1;
            }

            if(pid == ctx_priv->root_process_pid){
                summary->return_code = code;
            }

            if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
                fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
                return LIBSANDBOX_RESULT_ERROR;
            }

            if(ctx_priv->processes_running <= 0){
                return LIBSANDBOX_RESULT_FINISHED;
            }

            continue;

        }else if(
            status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))
        ){

            // generic syscall that we need to filter

        }else{

            if(!WIFSTOPPED(status)){
                // WIFSTOPPED(status): returns true if the child process was stopped by delivery of a signal; this is only possible if the call was done using WUNTRACED or when the child is being traced
                // so, this was NOT caused by us, and using PTRACE_CONT will do nothing and fail
                continue;
            }

            // TODO wtf is this, why is it needed
            if(WSTOPSIG(status) == SIGTRAP){
                if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
                    fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
                    return LIBSANDBOX_RESULT_ERROR;
                }
                continue;
            }

            // forward the signal to the child
            if(ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status))){
                fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
                return LIBSANDBOX_RESULT_ERROR;
            }

            continue;

        }

        // get CPU regs
        if(ptrace(PTRACE_GETREGS, pid, NULL, & ctx_priv->evaluated_cpu_regs)){
            fprintf(stderr, ERR_PREFIX "could not PTRACE_GETREGS\n");
            return LIBSANDBOX_RESULT_ERROR;
        }

        ctx_priv->evaluated_subprocess_pid = pid;
        ctx_priv->evaluated_syscall_id = CPU_REG_RW_SYSCALL_ID(ctx_priv->evaluated_cpu_regs);

        // functon pointer
        int (*path_extractor_fnc)(pid_t, struct user_regs_struct *, size_t, char *, size_t *, char *, size_t *);

        switch(ctx_priv->evaluated_syscall_id){

                // filesystem

                case SYS_creat:
                case SYS_open:
                case SYS_mknod:
                case SYS_truncate:
                case SYS_mkdir:
                case SYS_rmdir:
                case SYS_chdir:
                case SYS_chroot:
                case SYS_unlink:
                case SYS_readlink:
                case SYS_stat:
                case SYS_lstat:
                case SYS_chmod:
                case SYS_unlinkat:
                case SYS_readlinkat:
                case SYS_chown:
                case SYS_lchown: // does not dereference symlinks
                case SYS_utime:
                case SYS_utimes:
                case SYS_access:{
                    path_extractor_fnc = extract_arg0pathlink;
                }break;

                case SYS_openat:
                case SYS_name_to_handle_at:
                case SYS_mknodat:
                case SYS_mkdirat:
                case SYS_newfstatat:
                case SYS_fchmodat:
                case SYS_fchownat:
                case SYS_futimesat:
                case SYS_utimensat:
                case SYS_faccessat:
                case SYS_faccessat2:{
                    path_extractor_fnc = extract_arg0dirfd_arg1pathlink;
                }break;

                case SYS_rename:
                case SYS_link:
                case SYS_symlink:{
                    path_extractor_fnc = extract_arg0pathlink_arg1pathlink;
                }break;

                case SYS_symlinkat:{
                    path_extractor_fnc = extract_arg0pathlinkA_arg1dirfdB_arg2pathlinkB;
                }break;

                case SYS_renameat:
                case SYS_renameat2:
                case SYS_linkat:{
                    path_extractor_fnc = extract_arg0dirfdA_arg1pathlinkA_arg2dirfdB_arg3pathlinkB;
                }break;

                // networking

                case SYS_socket:
                case SYS_socketpair:{

                    // TODO this code block should not be here

                    // https://man7.org/linux/man-pages/man2/socket.2.html

                    int domain = CPU_REG_R_SYSCALL_ARG0(ctx_priv->evaluated_cpu_regs);

                    switch(domain){

                        case AF_LOCAL: // same as AF_UNIX
                        case AF_BRIDGE:
                        case AF_NETLINK:{

                            if(libsandbox_syscall_allow(ctx_priv)){
                                fprintf(stderr, ERR_PREFIX "unable to automatically allow syscall\n");
                                return LIBSANDBOX_RESULT_ERROR;
                            }
                            continue;

                        }break;

                        case AF_INET:
                        case AF_INET6:
                        case AF_DECnet:
                        case AF_ROSE:{

                            summary->auto_blocked_syscalls += 1;
                            if(libsandbox_syscall_deny_inner(ctx_priv, 1)){
                                fprintf(stderr, ERR_PREFIX "unable to automatically block syscall\n");
                                return LIBSANDBOX_RESULT_ERROR;
                            }
                            continue;

                        }break;

                        default:{

                            fprintf(stderr, ERR_PREFIX "unknown domain (%d)\n", domain);
                            return LIBSANDBOX_RESULT_ERROR;

                        }break;

                    }

                }break;

            default:{
                const char * name = get_syscall_name(ctx_priv->evaluated_syscall_id);
                fprintf(stderr, ERR_PREFIX "unknown syscal with id `%ld` (%s); this is a bug that needs to be reported\n", ctx_priv->evaluated_syscall_id, name);
                return LIBSANDBOX_RESULT_ERROR;
            }break;

        }

        int buffers_used = path_extractor_fnc(ctx_priv->root_process_pid, & ctx_priv->evaluated_cpu_regs, path_size, path0, path0_len, path1, path1_len);

        if(buffers_used < 0){

            summary->auto_blocked_syscalls += 1;
            if(libsandbox_syscall_deny_inner(ctx_priv, 1)){
                fprintf(stderr, ERR_PREFIX "unable to automatically block syscall\n");
                return LIBSANDBOX_RESULT_ERROR;
            }
            continue;

        }else if(buffers_used == 1){

            return LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0;

        }else if(buffers_used == 2){

            return LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0_PATH1;

        }

        fprintf(stderr, ERR_PREFIX "unknown return value of `path_extractor_fnc` (%d); this is a bug that needs to be reported\n", buffers_used);
        return LIBSANDBOX_RESULT_ERROR;

    }

}

int libsandbox_syscall_allow(void * ctx_private){
    struct ctx_private * ctx_priv = ctx_private;

    if(ptrace(PTRACE_CONT, ctx_priv->evaluated_subprocess_pid, NULL, NULL)){
        fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
        return 1;
    }

    return 0;
}

int libsandbox_syscall_deny(void * ctx_private){
    return libsandbox_syscall_deny_inner(ctx_private, 0);
}
