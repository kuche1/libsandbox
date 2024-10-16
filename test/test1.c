
#include "../src/libsandbox.h"

#include <stdio.h> // printf
#include <unistd.h> // sleep
#include <stdlib.h> // malloc

int main(void){

    // char * command_argv [] = {
    //     "echo",
    //     "asd 123",
    //     "4567",
    //     NULL,
    // };

    // char * command_argv [] = {
    //     "bash",
    //     "-c",
    //     "exit 69",
    //     NULL,
    // };

    // char * command_argv [] = {
    //     "bash",
    //     "-c",
    //     "echo 1 & echo 2 & exit 69",
    //     NULL,
    // };

    char * command_argv [] = {
        "bash",
        "-c",
        "cat test.sh",
        NULL,
    };

    struct libsandbox_rules rules;
    libsandbox_rules_init(& rules, 0); // `1` stands for permissive, `0` for non-permissive
    rules.filesystem_allow_metadata = 1;

    size_t ctx_private_size = libsandbox_get_ctx_private_size();
    char ctx_private[ctx_private_size];

    if(libsandbox_fork(command_argv, & rules, ctx_private)){
        printf("fork failed\n");
        return 1;
    }

    printf("forked successfully\n");

    struct libsandbox_summary summary = {0}; // TODO the user should not be responsible for this

    char path[400];

    for(int running = 1; running;){

        switch(libsandbox_next_syscall(ctx_private, & summary, path, sizeof(path))){

            case LIBSANDBOX_RESULT_FINISHED:{
                running = 0;
            }break;

            case LIBSANDBOX_RESULT_ERROR:{
                printf("something went wrong\n");
                return 1;
            }break;

            case LIBSANDBOX_RESULT_ACCESS_ATTEMPT_PATH:{
                printf("attempt to access path `%s`\n", path);
                libsandbox_syscall_allow(ctx_private);
            }break;

        }

    }

    // sleep(3);

    // execvp(command_argv[0], command_argv);

    printf("process finished\n");

    return summary.return_code;
}
