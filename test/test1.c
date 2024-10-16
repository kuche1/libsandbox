
#include "../src/libsandbox.h"

#include <stdio.h>
#include <unistd.h> // sleep

int main(void){

    char * command_argv [] = {
        "echo",
        "asd 123",
        "4567",
        NULL,
    };

    pid_t pid;
    if(libsandbox_fork(command_argv, & pid)){
        return 1;
    }

    printf("forked successfully\n");

    // TODO this should be returned by libsandbox_fork
    // also it would be best if we made 2 structs, 1 for internal things, and 1 for external
    struct libsandbox_sandbox_data ctx = {
        .sandboxed_process_pid = pid,
        .finished = 0,
        .return_code = 0,
        .processes_running = 1,
        .processes_failed = 0,
    };

    for(;;){
        int fail = libsandbox_next_syscall(& ctx);
        if(fail){
            printf("something went wrong\n");
            return 1;
        }

        if(ctx.finished){
            break;
        }
    }

    // sleep(3);

    // execvp(command_argv[0], command_argv);

    printf("process finished; return code: %d\n", ctx.return_code);

    return 0;
}
