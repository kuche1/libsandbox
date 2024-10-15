
#include "libsandbox.h"

#include <unistd.h> // fork
#include <sys/ptrace.h> // ptrace
#include <stdio.h> // fprintf
#include <signal.h> // raise
#include <sys/wait.h> // waitpid

#define LIBSANDBOX_ERR_PREFIX LIBSANDBOX_PRINT_PREFIX "ERROR: "

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

        // set_static_rules(settings);
        // TODO

        execvp(command, command_args);
        // no need to check return code, if the execution continues the call has failed for sure

        fprintf(stderr, LIBSANDBOX_ERR_PREFIX "call to execvp failed: could not run `%s`\n", command);
        // TODO also include app name (and args?)

        return -1;

    }else{

        // wait for the SIGSTOP
        int status;
        waitpid(child, &status, 0);

        if(!WIFSTOPPED(status)){ // was child stopped by a delivery of a signal
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "child was not stopped by a delivery of a signal\n");
            // TODO kill child
            return -1;
        }

        if(WSTOPSIG(status) != SIGSTOP){ // which was the signal that caused the child to stop
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "child was was stopped, but not due to SIGSTOP\n");
            // TODO kill child
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
            // TODO kill child
            return -1;
        };

        if(ptrace(PTRACE_CONT, child, NULL, NULL)){
            fprintf(stderr, LIBSANDBOX_ERR_PREFIX "could not continue child execution\n");
            // TODO kill child
            return -1;
        }

    }

    * new_process_pid = child;

    return 0;

}
