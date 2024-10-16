
static int extract_pathraw_addr(pid_t pid, char * addr, char * path, size_t path_size){

    for(;;){

        // read chunk of data

        char chunk[sizeof(long)];
        errno = 0;

        *(long*)chunk = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

        if( (*(long*)chunk == -1) && (errno != 0) ){
            // the process has probably exited (or perhaps the address is wrong) (or perhaps there is a bug in the program that makes it try and read an invalid address)
            fprintf(stderr, ERR_PREFIX "could not read from address space of process with pid `%d`\n", pid);
            return 1;
        }

        addr += sizeof(long);

        // process chunk data

        for(size_t idx=0; idx<sizeof(chunk); ++idx){
            char ch = chunk[idx];

            if(path_size <= 0){
                fprintf(stderr, ERR_PREFIX "not enough memory in buffer to extract rawpath of process with pid `%d`\n", pid);
                return 1;
            }

            path[0] = ch;

            if(ch == 0){
                return 0;
            }

            path += 1;
            path_size -= 1;
        }

    }

}

static int extract_arg0pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){

    char * path_cstr = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);

    if(extract_pathraw_addr(pid, path_cstr, path, path_size)){
        return 1;
    }

    // TODO follow the path symlink

    return 0;
}

static int extract_arg0dirfd_arg1pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){

    // int dir_fd = CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    // TODO

    char * path_cstr = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    if(extract_pathraw_addr(pid, path_cstr, path, path_size)){
        return 1;
    }

    // TODO follow the path symlink

    return 0;
}
