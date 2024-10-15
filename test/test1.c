
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

    sleep(5);

    // execvp(command_argv[0], command_argv);

    return 0;
}
