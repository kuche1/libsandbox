
#include "libsandbox.h"

#include <unistd.h> // fork
#include <sys/ptrace.h> // ptrace
#include <stdio.h> // fprintf
#include <signal.h> // raise
#include <sys/wait.h> // waitpid
#include <seccomp.h> // scmp_filter_ctx
#include <string.h> // strerror
#include <errno.h> // errno

#define ERR_PREFIX LIBSANDBOX_PRINT_PREFIX "ERROR: "

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
};

static inline void sigkill_or_print_err(pid_t pid){
    if(kill(pid, SIGKILL)){
        fprintf(stderr, ERR_PREFIX "could not SIGKILL process with pid `%d`\n", pid);
    }
}

static inline int set_seccomp_rules(int filesystem_allow_all, int filesystem_allow_metadata, int networking_allow_all){

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
        if(filesystem_allow_all){
            action = SCMP_ACT_ALLOW;
        }

        uint32_t action_metadata = action;
        if(filesystem_allow_metadata){
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

        if(networking_allow_all){
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

size_t libsandbox_get_ctx_private_size(void){
    return sizeof(struct ctx_private);
}

int libsandbox_fork(char * * command_argv, void * ctx_private){
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

        // TODO those args are too permissive
        if(set_seccomp_rules(1, 1, 1)){
            return 1;
        }

        execvp(command_argv[0], command_argv);
        // no need to check return code, if the execution continues the call has failed for sure

        fprintf(stderr, ERR_PREFIX "call to execvp failed: could not run `%s`; error=`%s`\n", command_argv[0], strerror(errno));

        return 1;

    }else{

        // wait for the SIGSTOP
        int status;
        waitpid(child, &status, 0);

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

enum libsandbox_result libsandbox_next_syscall(void * ctx_private, struct libsandbox_summary * summary){
    struct ctx_private * ctx_priv = ctx_private;

    int status;
    pid_t pid = waitpid(-1, &status, 0);
    // the first argument being -1 means: wait for any child process
    // `waitpid` returns when a child's state changes, and that means: the child terminated, the child was stopped by a signal, or the child was resumed by a signal

    // if(pid == -1){
    //     // we're never supposed to reach this
    //     fprintf(stderr, ERR_PREFIX "WTF something is wrong\n");
    //     * finished = 1;
    //     return 0;
    // }
    if(pid == -1){
        fprintf(stderr, ERR_PREFIX "call to waitpid failed\n");
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
        return LIBSANDBOX_RESULT_CONTINUE;

    }else if(
        status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))
    ){

        // process died

        ctx_priv->processes_running -= 1;

        unsigned long event_message;
        if(ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_message)){
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

        return LIBSANDBOX_RESULT_CONTINUE;

    }else if(
        status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))
    ){

        // generic syscall that we need to filter

    }else{

        if(!WIFSTOPPED(status)){
            // WIFSTOPPED(status): returns true if the child process was stopped by delivery of a signal; this is only possible if the call was done using WUNTRACED or when the child is being traced
            // so, this was NOT caused by us, and using PTRACE_CONT will do nothing and fail
            return LIBSANDBOX_RESULT_CONTINUE;
        }

        // TODO wtf is this
        if(WSTOPSIG(status) == SIGTRAP){
            if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
                fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
                return LIBSANDBOX_RESULT_ERROR;
            }
            return LIBSANDBOX_RESULT_CONTINUE;
        }

        // forward the signal to the child
        if(ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status))){
            fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
            return LIBSANDBOX_RESULT_ERROR;
        }

        return LIBSANDBOX_RESULT_CONTINUE;

    }

    // TODO the code for the filtering should go here
    // currently we're allowing everything
    if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
        fprintf(stderr, ERR_PREFIX "could not PTRACE_CONT\n");
        return LIBSANDBOX_RESULT_ERROR;
    }

    return LIBSANDBOX_RESULT_CONTINUE;

}