
// TODO ideally we would only dereference a symlink if the given syscall does so as well

// `pathraw` means a path as it is (it might be a symlink)
// `pathlink` means a dereferenced path (it's not a symlink (TODO but what about invalid symlinks, we need to test this))

//////////
////////// low level
//////////

// returns how much bytes have been written (excluding the last \0), or negative if error
static ssize_t extract_pathraw_addr(pid_t pid, char * addr, char * path, size_t path_size){

    ssize_t bytes_read = 0;

    for(;;){

        // read chunk of data

        char chunk[sizeof(long)];
        errno = 0;

        *(long*)chunk = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

        if( (*(long*)chunk == -1) && (errno != 0) ){
            // the process has probably exited (or perhaps the address is wrong) (or perhaps there is a bug in the program that makes it try and read an invalid address)
            fprintf(stderr, ERR_PREFIX "could not read from address space of process with pid `%d`\n", pid);
            return -1;
        }

        addr += sizeof(long);

        // process chunk data

        for(size_t idx=0; idx<sizeof(chunk); ++idx){
            char ch = chunk[idx];

            if(path_size <= 0){
                fprintf(stderr, ERR_PREFIX "not enough memory in buffer to extract rawpath of process with pid `%d`\n", pid);
                return -1;
            }

            path[bytes_read] = ch;

            if(ch == 0){
                return bytes_read;
            }

            bytes_read += 1;
            path_size -= 1;
        }

    }

}

// `path_actually_written_bytes` does not include the ending \0
static int extract_pathlink(char * path_raw, char * path, size_t path_size, size_t * path_actually_written_bytes){

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

    * path_actually_written_bytes = path_dereferenced_len;

    return 0;

}

// `path_actually_written_bytes` does not include the ending \0
static int extract_pathlink_pidmemstr(pid_t pid, char * pidmem_str, char * path, size_t path_size, size_t * path_actually_written_bytes){

    char path_raw[path_size];

    if(extract_pathraw_addr(pid, pidmem_str, path_raw, sizeof(path_raw)) < 0){
        return 1;
    }

    return extract_pathlink(path_raw, path, path_size, path_actually_written_bytes);

}

// `path_actually_written_bytes` does not include the ending \0
static ssize_t extract_pathlink_pidmemdirfd(pid_t pid, int pidmem_dirfd, char * path, size_t path_size){

    char file_containing_dirfd[100];

    int written;

    if(pidmem_dirfd == AT_FDCWD){
        written = snprintf(file_containing_dirfd, sizeof(file_containing_dirfd), "/proc/%d/cwd", pid);
    }else{
        written = snprintf(file_containing_dirfd, sizeof(file_containing_dirfd), "/proc/%d/fd/%d", pid, pidmem_dirfd);
    }

    if(written < 0){
        fprintf(stderr, ERR_PREFIX "`snprintf` failure\n");
        return -1;
    }

    if((long unsigned int) written >= sizeof(file_containing_dirfd)){
        fprintf(stderr, ERR_PREFIX "not enough memory in temporary buffer; this is a bug that needs to be reported\n");
        return -1;
    }

    if(pidmem_dirfd == AT_FDCWD){

        size_t path_actually_written_bytes;
        if(extract_pathlink(file_containing_dirfd, path, path_size, & path_actually_written_bytes)){
            return -1;
        }
        return path_actually_written_bytes;

    }else{

        printf("DBG: YEEEEE");
        // TODO this print is here since this branch has been
        // totally untested

        FILE * f = fopen(file_containing_dirfd, "rb");
        if(!f){
            fprintf(stderr, ERR_PREFIX "could not open file containing dirfd `%s`\n", file_containing_dirfd);
            return -1;
        }

        if(fseek(f, 0, SEEK_END)){
            fprintf(stderr, ERR_PREFIX "`fseek` failure\n");
            fclose(f);
            return -1;
        }

        long actual_path_size = ftell(f);

        if(actual_path_size < 0){
            fprintf(stderr, ERR_PREFIX "`ftell` failure\n");
            fclose(f);
            return -1;
        }

        rewind(f);

        if(path_size <= 0){
            fprintf(stderr, ERR_PREFIX "provided buffer size is <= 0\n");
            fclose(f);
            return -1;
        }

        if((size_t) actual_path_size > path_size - 1){
            fprintf(stderr, ERR_PREFIX "not enough memory for the actual path\n");
            fclose(f);
            return -1;
        }

        size_t read = fread(path, 1, path_size - 1, f);

        if(read != (size_t) actual_path_size){
            fprintf(stderr, ERR_PREFIX "`fread` failure\n");
            fclose(f);
            return -1;
        }

        fclose(f);

        path[read] = 0;

        return read;

    }

}

//////////
////////// high level
//////////

static int extract_arg0pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){
    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    size_t tmp;
    return extract_pathlink_pidmemstr(pid, pidmem_str, path, path_size, & tmp);
}

static int extract_arg0dirfd_arg1pathlink(pid_t pid, struct user_regs_struct * cpu_regs, char * path, size_t path_size){

    // extract file

    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    char filename[path_size];

    ssize_t filename_len = extract_pathraw_addr(pid, pidmem_str, filename, sizeof(filename));

    if(filename_len < 0){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return 1;
    }

    if(filename[0] == '/'){
        // it's a full path
        strcpy(path, filename);
        return 0;
    }

    // extract folder

    int pidmem_dirfd = CPU_REG_R_SYSCALL_ARG0(* cpu_regs);

    ssize_t path_len_ssize = extract_pathlink_pidmemdirfd(pid, pidmem_dirfd, path, path_size);

    if(path_len_ssize < 0){
        return 1;
    }

    size_t path_len = path_len_ssize;

    // add separator

    path[path_len] = '/';
    path_len += 1;

    if(path_len >= path_size){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return 1;
    }

    // add file

    if(path_len + filename_len + 1 >= path_size){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return 1;
    }

    strcpy(path + path_len, filename);

    return 0;
}
