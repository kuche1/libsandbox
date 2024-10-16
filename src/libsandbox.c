
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

    // TODO actually add those filters

    // load the rules
    if(seccomp_load(ctx)){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not load seccomp rules\n");
        return -1;
    }

    return 0;

}

int libsandbox_fork(char * * command_argv, pid_t * new_process_pid){

    if(command_argv[0] == NULL){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "command name not specified\n");
        return -1;
    }

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

        execvp(command_argv[0], command_argv);
        // no need to check return code, if the execution continues the call has failed for sure

        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "call to execvp failed: could not run `%s`\n", command_argv[0]);

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

int libsandbox_next_syscall(pid_t sandboxed_process_pid, int * finished, int * return_code, int * processes_running, int * processes_failed){

    int status;
    pid_t pid = waitpid(-1, &status, 0);
    // the first argument being -1 means: wait for any child process
    // `waitpid` returns when a child's state changes, and that means: the child terminated, the child was stopped by a signal, or the child was resumed by a signal

    // if(pid == -1){
    //     // we're never supposed to reach this
    //     fprintf(stderr, LIBSANDBOX_ERR_PREFIX "WTF something is wrong\n");
    //     * finished = 1;
    //     return 0;
    // }
    if(pid == -1){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "call to waitpid failed\n");
        return 1;
    }

    if(
        ( status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ) ||
        ( status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))  ) ||
        ( status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) )
    ){

        // new process was created
        * processes_running += 1;
        if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_CONT\n");
            return 1;
        }
        return 0;

    }else if(
        status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))
    ){

        // process died

        * processes_running -= 1;

        unsigned long event_message;
        if(ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_message)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_GETEVENTMSG\n");
            return 1;
        }

        int code = event_message >> 8;

        if(code){
            // note that it might be the case that the return code signifies something else
            // rather than success/failure
            * processes_failed += 1;
        }

        if(pid == sandboxed_process_pid){
            * return_code = code;
        }

        if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_CONT\n");
            return 1;
        }

        if(* processes_running <= 0){
            * finished = 1;
        }

        return 0;

    }else if(
        status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))
    ){

        // generic syscall that we need to filter

    }else{

        if(!WIFSTOPPED(status)){
            // WIFSTOPPED(status): returns true if the child process was stopped by delivery of a signal; this is only possible if the call was done using WUNTRACED or when the child is being traced
            // so, this was NOT caused by us, and using PTRACE_CONT will do nothing and fail
            return 0;
        }

        // TODO wtf is this
        if(WSTOPSIG(status) == SIGTRAP){
            if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
                fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_CONT\n");
                return 1;
            }
            return 0;
        }

        // forward the signal to the child
        if(ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status))){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_CONT\n");
            return 1;
        }

        return 0;

    }

    // TODO the code for the filtering should go here
    // currently we're allowing everything
    if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not PTRACE_CONT\n");
        return 1;
    }

    return 0;

}