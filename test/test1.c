
#include "../src/libsandbox.h"

#include <stdio.h>
#include <unistd.h> // sleep

int main(void){

    // printf("spawning new process...\n");

    char * command = "echo";

    char * command_args [] = {
        "hui 123",
        "4567",
        NULL,
    };

    pid_t pid;
    if(libsandbox_fork(command, command_args, & pid)){
        return 1;
    }

    printf("forked successfully\n");

    sleep(5);

    return 0;
}
