
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

static int extract_pathraw_pidmemstr(pid_t pid, char * pidmem_str, char * path, size_t path_size){

    char path_raw[path_size];

    if(extract_pathraw_addr(pid, pidmem_str, path_raw, sizeof(path_raw))){
        return 1;
    }

    if(path_size <= 0){
        fprintf(stderr, ERR_PREFIX "provided buffer size is <= 0\n");
        return 1;
    }

    ssize_t path_dereferenced_len_or_err = readlink(path_raw, path, path_size - 1);

    if(path_dereferenced_len_or_err < 0){
        fprintf(stderr, ERR_PREFIX "could not dereference path `%s`\n", path_raw);
        return 1;
    }

    size_t path_dereferenced_len = path_dereferenced_len_or_err;

    if(path_dereferenced_len == path_size - 1){
        // it might be the case that we have just enough memory, but we can't differentiate
        // wetween having just enough memory and not having enough, so we'll assume the worst
        fprintf(stderr, ERR_PREFIX "not enough memory to dereference path `%s`\n", path_raw);
        return 1;
    }

    path[path_dereferenced_len] = 0;

    return 0;

}

static int extract_arg0pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){
    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    return extract_pathraw_pidmemstr(pid, pidmem_str, path, path_size);
}

static int extract_arg0dirfd_arg1pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){

    // int dir_fd = CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    // TODO

    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    if(extract_pathraw_addr(pid, pidmem_str, path, path_size)){
        return 1;
    }

    // TODO follow the path symlink

    return 0;
}
