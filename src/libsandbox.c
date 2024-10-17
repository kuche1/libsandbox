
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
#include "error_util.c"
#include "string_operations.c"
#include "path_extractors.c"

static inline void sigkill_or_print_err(pid_t pid){
    if(kill(pid, SIGKILL)){
        fprintf(stderr, ERR_PREFIX "could not SIGKILL process with pid `%d`\n", pid);
    }
}

static inline int set_seccomp_rules(struct libsandbox_rules * rules){

    // SCMP_ACT_ALLOW - allow the syscall
    // SCMP_ACT_LOG - allow but log
    // SCMP_ACT_TRACE(69) - trigger a ptrace breakpoint

    // allow all syscalls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if(ctx == NULL){
        fprintf(stderr, ERR_PREFIX "could not initialise seccomp\n");
        return 1;
    }

    // do not send SIGSYS upon coming across an invalid syscall (fix for proton)
    if(seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ALLOW)){
        fprintf(stderr, ERR_PREFIX "could set seccomp attribute\n");
        return 1;
    }

    // set rules: filesystem
    {
        // https://linasm.sourceforge.net/docs/syscalls/filesystem.php

        uint32_t action = SCMP_ACT_TRACE(69);
        if(rules->filesystem_allow_all){
            action = SCMP_ACT_ALLOW;
        }

        uint32_t action_metadata = action;
        if(rules->filesystem_allow_metadata){
            action_metadata = SCMP_ACT_ALLOW;
        }

        // file operations

        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(close), 0); // harmless
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(creat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(open), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(openat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(name_to_handle_at), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(open_by_handle_at), 0); // depends on `name_to_handle_at`
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(memfd_create), 0); // the file lives in RAM
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(mknod), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(mknodat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(rename), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(renameat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(renameat2), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(truncate), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(ftruncate), 0); // depends on `open`
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fallocate), 0); // depends on `open`

        // directory operations

        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(mkdir), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(mkdirat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(rmdir), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(getcwd), 0); // gives info that the app should already have
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(chdir), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fchdir), 0); // depends on `open`
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(chroot), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(getdents), 0); // depend on `open`
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(getdents64), 0); // depend on `open`
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(lookup_dcookie), 0); // depends on `getdents64` for getting the cookie

        // link operations

        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(link), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(linkat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(symlink), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(symlinkat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(unlink), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(unlinkat), 0);
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(readlink), 0);
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(readlinkat), 0);

        // basic file attributes

        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(umask), 0); // depends on `open`
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(chmod), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fchmod), 0); // depends on `open`
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fchmodat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(chown), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(lchown), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fchown), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fchownat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(utime), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(utimes), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(futimesat), 0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(utimensat), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(futimens), 0); // depends on `open`

        // get file status
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(stat), 0);
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(lstat), 0);
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fstat), 0); // depends on `open`
        // SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(fstatat64), 0); // only 32bit
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(newfstatat), 0);

        // check user permission for file
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(access), 0);
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(faccessat), 0);
        SECCOMP_RULE_ADD(ctx, action_metadata, SCMP_SYS(faccessat2), 0);

        // extended file attributes // TODO
    }

    // set rules: networking
    {
        uint32_t action = SCMP_ACT_TRACE(69);

        if(rules->networking_allow_all){
            action = SCMP_ACT_ALLOW;
        }

        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(socket),     0);
        SECCOMP_RULE_ADD(ctx, action, SCMP_SYS(socketpair), 0);
    }

    // load the rules
    if(seccomp_load(ctx)){
        fprintf(stderr, ERR_PREFIX "could not load seccomp rules\n");
        return 1;
    }

    return 0;

}

//////////
////////// functions: public
//////////

void libsandbox_rules_init(struct libsandbox_rules * rules, int permissive){
    rules->filesystem_allow_all = permissive;
    rules->filesystem_allow_metadata = permissive;
    rules->networking_allow_all = permissive;
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

int libsandbox_syscall_allow(void * ctx_private){
    struct ctx_private * ctx_priv = ctx_private;

    if(ptrace(PTRACE_CONT, ctx_priv->evaluated_subprocess_pid, NULL, NULL)){
        fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
        return 1;
    }

    return 0;
}

int libsandbox_syscall_deny(void * ctx_private){
    struct ctx_private * ctx_priv = ctx_private;

    const char * name = get_syscall_name(ctx_priv->evaluated_syscall_id);
    printf(PRINT_PREFIX "blocking syscall with id `%ld` (%s)\n", ctx_priv->evaluated_syscall_id, name);

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

// TODO? make it so that if this exits with LIBSANDBOX_RESULT_ERROR it kills all processes
// perhaps do it also when finished just to be sure?
enum libsandbox_result libsandbox_next_syscall(void * ctx_private, struct libsandbox_summary * summary, size_t path_size, char * path0, char * path1){
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
        int (*path_extractor_fnc)(pid_t, struct user_regs_struct *, size_t, char *, char *);

        switch(ctx_priv->evaluated_syscall_id){

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

                // case SYS_renameat:
                // case SYS_renameat2:
                // case SYS_linkat:{
                //     path_extractor_fnc = extract_arg0dirfdA_arg1pathlinkA_arg2 TODO
                // }break;

                // TODO there are more syscalls mising here

            default:{
                const char * name = get_syscall_name(ctx_priv->evaluated_syscall_id);
                fprintf(stderr, ERR_PREFIX "unknown syscal with id `%ld` (%s); this is a bug that needs to be reported\n", ctx_priv->evaluated_syscall_id, name);
                return LIBSANDBOX_RESULT_ERROR;
            }break;

        }

        int bufferes_used = path_extractor_fnc(ctx_priv->root_process_pid, & ctx_priv->evaluated_cpu_regs, path_size, path0, path1);

        if(bufferes_used < 0){

            summary->auto_blocked_syscalls += 1;
            if(libsandbox_syscall_deny(ctx_priv)){
                fprintf(stderr, ERR_PREFIX "unable to automatically block syscall\n");
                return LIBSANDBOX_RESULT_ERROR;
            }
            continue;

        }else if(bufferes_used == 1){

            return LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0;

        }else if(bufferes_used == 2){

            return LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH0_PATH1;

        }

        fprintf(stderr, ERR_PREFIX "unknown return value of `path_extractor_fnc` (%d); this is a bug that needs to be reported\n", bufferes_used);
        return LIBSANDBOX_RESULT_ERROR;

    }

}