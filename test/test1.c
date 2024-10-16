
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

    // char * command_argv [] = {
    //     "bash",
    //     "-c",
    //     "exit 69",
    //     NULL,
    // };

    void * ctx_private = NULL;
    if(libsandbox_fork(command_argv, & ctx_private)){
        return 1;
    }

    printf("forked successfully\n");

    // TODO this should be returned by libsandbox_fork
    // also it would be best if we made 2 structs, 1 for internal things, and 1 for external
    struct libsandbox_sandbox_data ctx = {
        .finished = 0,
        .return_code = 0,
    };

    for(;;){
        int fail = libsandbox_next_syscall(& ctx, ctx_private);
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

    printf("process finished\n");

    return ctx.return_code;
}
