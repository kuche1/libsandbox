
#include "libsandbox.h"

#include <unistd.h> // fork
#include <sys/ptrace.h> // ptrace
#include <stdio.h> // fprintf
#include <signal.h> // raise
#include <sys/wait.h> // waitpid
#include <seccomp.h> // scmp_filter_ctx

#define LIBSANDBOX_ERR_PREFIX LIBSANDBOX_PRINT_PREFIX "ERROR: "

static inline void sigkill_or_print_err(pid_t pid){
    if(kill(pid, SIGKILL)){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not SIGKILL process with pid `%d`\n", pid);
    }
}

static inline int set_seccomp_rules(void){

    // SCMP_ACT_ALLOW - allow the syscall
    // SCMP_ACT_LOG - allow but log
    // SCMP_ACT_TRACE(69) - trigger a ptrace breakpoint

    // allow all syscalls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if(ctx == NULL){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not initialise seccomp\n");
        return -1;
    }

    // do not send SIGSYS upon coming across an invalid syscall (fix for proton)
    if(seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ALLOW)){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could set seccomp attribute\n");
        return -1;
    }

    // load the rules
    if(seccomp_load(ctx)){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not load seccomp rules\n");
        return -1;
    }

    return 0;

}

int libsandbox_fork(char * command, char * * command_args, pid_t * new_process_pid){

    pid_t child = fork();

    if(child < 0){

        return -1;

    }else if(child == 0){

        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not trace flag for child\n");
            return -1;
        }

        // pause execution since TRACEME won't do that by itself
        if(raise(SIGSTOP)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not pause child execution\n");
            return -1;
        }

        if(set_seccomp_rules()){
            return -1;
        }

        execvp(command, command_args);
        // no need to check return code, if the execution continues the call has failed for sure

        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "call to execvp failed: could not run `%s`\n", command);

        return -1;

    }else{

        // wait for the SIGSTOP
        int status;
        waitpid(child, &status, 0);

        if(!WIFSTOPPED(status)){ // was child stopped by a delivery of a signal
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "child was not stopped by a delivery of a signal\n");
            sigkill_or_print_err(child);
            return -1;
        }

        if(WSTOPSIG(status) != SIGSTOP){ // which was the signal that caused the child to stop
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "child was was stopped, but not due to SIGSTOP\n");
            sigkill_or_print_err(child);
            return -1;
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
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not set ptrace restrictions for child\n");
            sigkill_or_print_err(child);
            return -1;
        };

        if(ptrace(PTRACE_CONT, child, NULL, NULL)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not continue child execution\n");
            sigkill_or_print_err(child);
            return -1;
        }

    }

    * new_process_pid = child;

    return 0;

}
