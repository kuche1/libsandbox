
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

    int finished = 0;
    int processes_running = 1;
    int processes_failed = 0;
    int return_code = 0;

    for(;;){
        int fail = libsandbox_next_syscall(pid, & finished, & return_code, & processes_running, & processes_failed);
        if(fail){
            printf("something went wrong\n");
            return 1;
        }

        if(finished){
            break;
        }
    }

    // sleep(3);

    // execvp(command_argv[0], command_argv);

    printf("all done\n");

    return 0;
}
