
// TOD0 ideally we would only dereference a symlink if the given syscall does so as well
// alternatively, this can probably be fixed by (ab) using the path0 path1 return thingy (althoit would probably have
// to be expanded in the case of a symlink pointing to a symlink pointing to ...) (altho this method could lead to false
// positives (imagine you are working on a symlink that points outside of your allowed directory))

// `pathraw` - treat a path as it is (do not try to dereference)
// `pathlink` - try to dereference, and if it doesn't work (eg you can't dererefence a non-existant symlink) trat as it is

//////////
////////// low level
//////////

static int is_symlink(char * path){

    struct stat sb;

    if(lstat(path, & sb) == -1){
        if(errno == ENOENT){
            // No such file or directory
        }else{
            fprintf(stderr, ERR_PREFIX "`lstat` failure for `%s` (errno=%d `%s`)\n", path, errno, strerror(errno));
        }
        return 0;
    };

    return (sb.st_mode & S_IFMT) == S_IFLNK;
}

// return: (negative on err) or (number of bytes written excluding \0)
static ssize_t extract_cwd(pid_t pid, size_t path_size, char * path){

    char link_to_cwd[100];

    int written;

    written = snprintf(link_to_cwd, sizeof(link_to_cwd), "/proc/%d/cwd", pid);

    if(written < 0){
        fprintf(stderr, ERR_PREFIX "`snprintf` failure\n");
        return -1;
    }

    if((long unsigned int) written >= sizeof(link_to_cwd)){
        fprintf(stderr, ERR_PREFIX "not enough memory in temporary buffer; this is a bug that needs to be reported\n");
        return -1;
    }

    ssize_t len_or_err = readlink(link_to_cwd, path, path_size - 1);

    if(len_or_err < 0){
        fprintf(stderr, ERR_PREFIX "`readlink` failure\n");
        return -1;
    }

    size_t len = len_or_err;

    if(len == path_size - 1){
        fprintf(stderr, ERR_PREFIX "buf too small\n");
        return -1;
    }

    path[len] = 0;

    return len;

}

// returns how much bytes have been written (excluding the last \0), or negative if error
static ssize_t extract_pathraw_addr(pid_t pid, char * addr, char * path, size_t path_size){

    size_t bytes_read = 0;

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

// returns: (negative on error) or (number of bytes written, excluding ending \0)
static ssize_t extract_pathlink(pid_t pid, char * path_raw, char * path, size_t path_size){

    char full_path[path_size];
    size_t full_path_len = 0;

    if(path_raw[0] == '/'){

        // it's a full path, forget about cwd

        if(str_append_str(full_path, sizeof(full_path), & full_path_len, path_raw)){
            fprintf(stderr, ERR_PREFIX "`str_append_str` failure\n");
            return -1;
        }

    }else{

        ssize_t full_path_len_or_err = extract_cwd(pid, sizeof(full_path), full_path);
        if(full_path_len_or_err < 0){
            fprintf(stderr, ERR_PREFIX "could not extract cwd of process with pid `%d`\n", pid);
            return -1;
        }

        full_path_len = full_path_len_or_err;

        if(str_append_char(full_path, sizeof(full_path), & full_path_len, '/')){
            fprintf(stderr, ERR_PREFIX "`str_append_str` failure\n");
            return -1;
        }

        if(str_append_str(full_path, sizeof(full_path), & full_path_len, path_raw)){
            fprintf(stderr, ERR_PREFIX "`str_append_str` failure\n");
            return -1;
        }

    }

    if(!is_symlink(full_path)){

        size_t len = 0;

        if(str_append_str(path, path_size, & len, full_path)){
            fprintf(stderr, ERR_PREFIX "`str_append_str` failure\n");
            return -1;
        }

        return len;

    }

    // must be a symlink

    if(path_size <= 0){
        fprintf(stderr, ERR_PREFIX "provided buffer size is <= 0\n");
        return -1;
    }

    ssize_t path_dereferenced_len_or_err = readlink(full_path, path, path_size - 1);
    int path_dereferenced_len_or_err_errno = errno;

    if(path_dereferenced_len_or_err < 0){
        fprintf(stderr, ERR_PREFIX "could not dereference path `%s` (full=`%s`) (errno=%d `%s`)\n", path_raw, full_path, path_dereferenced_len_or_err_errno, strerror(path_dereferenced_len_or_err_errno));
        return -1;
    }

    size_t path_dereferenced_len = path_dereferenced_len_or_err;

    if(path_dereferenced_len == path_size - 1){
        // it might be the case that we have just enough memory, but we can't differentiate
        // between having just enough memory and not having enough, so we'll assume the worst
        fprintf(stderr, ERR_PREFIX "not enough memory to dereference path `%s`\n", path_raw);
        return -1;
    }

    path[path_dereferenced_len] = 0;

    return path_dereferenced_len;

}

// returns (negative on error) or (number of bytes written, excluding ending \0)
static ssize_t extract_pathlink_pidmemstr(pid_t pid, char * pidmem_str, char * path, size_t path_size){

    char path_raw[path_size];

    if(extract_pathraw_addr(pid, pidmem_str, path_raw, sizeof(path_raw)) < 0){
        fprintf(stderr, ERR_PREFIX "call to `extract_pathraw_addr` failed\n");
        return -1;
    }

    ssize_t ret = extract_pathlink(pid, path_raw, path, path_size);
    if(ret < 0){
        fprintf(stderr, ERR_PREFIX "call to `extract_pathlink` failed\n");
    }

    return ret;
}

// returns (negative on error) or (number of bytes written, excluding ending \0)
static ssize_t extract_pathlink_pidmemdirfd(pid_t pid, int pidmem_dirfd, char * path, size_t path_size){

    if(pidmem_dirfd == AT_FDCWD){
        return extract_cwd(pid, path_size, path);
    }

    printf("DBG: YEEEEE");
    // TODO this print is here since this branch has been
    // totally untested

    char file_containing_dirfd[100];

    int written;

    written = snprintf(file_containing_dirfd, sizeof(file_containing_dirfd), "/proc/%d/fd/%d", pid, pidmem_dirfd);

    if(written < 0){
        fprintf(stderr, ERR_PREFIX "`snprintf` failure\n");
        return -1;
    }

    if((long unsigned int) written >= sizeof(file_containing_dirfd)){
        fprintf(stderr, ERR_PREFIX "not enough memory in temporary buffer; this is a bug that needs to be reported\n");
        return -1;
    }

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

// both `path` and `path_tmp` need to be of size `path_size`
// returns (negative on err) or (length of path, excluding final \0)
static ssize_t extract_pidmemdirfd_pathlink(pid_t pid, int pidmem_dirfd, char * pidmem_str, size_t path_size, char * path, char * path_tmp){

    // extract file

    char * filename = path_tmp;

    ssize_t filename_len = extract_pathraw_addr(pid, pidmem_str, filename, path_size);

    if(filename_len < 0){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return -1;
    }

    if(filename[0] == '/'){ // we CAN check [0] - worst case scenario it's \0
        // it's a full path
        strcpy(path, filename);
        return filename_len;
    }

    // extract folder

    ssize_t path_len_ssize = extract_pathlink_pidmemdirfd(pid, pidmem_dirfd, path, path_size);

    if(path_len_ssize < 0){
        fprintf(stderr, ERR_PREFIX "call to `extract_pathlink_pidmemdirfd` failed\n");
        return -1;
    }

    size_t path_len = path_len_ssize;

    // add separator

    path[path_len] = '/';
    path_len += 1;

    if(path_len >= path_size){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return -1;
    }

    // add file

    if(path_len + filename_len + 1 >= path_size){
        fprintf(stderr, ERR_PREFIX "not enough memory in buffer\n");
        return -1;
    }

    strcpy(path + path_len, filename);

    return path_len + filename_len;
}

//////////
////////// high level
//////////

// all these functions return (negative on error) or (the number of paths extracted)

// TODO untested
static int extract_arg0pathlink(pid_t pid, struct user_regs_struct * cpu_regs, size_t path_size, char * path0, __attribute__((unused)) char * path1){

    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);

    if(extract_pathlink_pidmemstr(pid, pidmem_str, path0, path_size) < 0){
        fprintf(stderr, ERR_PREFIX "call to `extract_pathlink_pidmemstr` failed\n");
        return -1;
    }

    return 1;
}

static int extract_arg0dirfd_arg1pathlink(pid_t pid, struct user_regs_struct * cpu_regs, size_t path_size, char * path0, char * path1){

    int pidmem_dirfd = CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    char * pidmem_str = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    if(extract_pidmemdirfd_pathlink(pid, pidmem_dirfd, pidmem_str, path_size, path0, path1) < 0){
        return -1;
    }

    return 1;
}

// TODO untested
static int extract_arg0pathlink_arg1pathlink(pid_t pid, struct user_regs_struct * cpu_regs, size_t path_size, char * path0, char * path1){

    // extract path0

    char * pidmem_str0 = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);

    if(extract_pathlink_pidmemstr(pid, pidmem_str0, path0, path_size) < 0){
        return -1;
    }

    // extract path1

    char * pidmem_str1 = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    if(extract_pathlink_pidmemstr(pid, pidmem_str1, path1, path_size) < 0){
        return -1;
    }

    return 2;

}


static int extract_arg0pathlinkA_arg1dirfdB_arg2pathlinkB(pid_t pid, struct user_regs_struct * cpu_regs, size_t path_size, char * path0, char * path1){

    // extract path0

    char * pidmem_str0 = (char *) CPU_REG_R_SYSCALL_ARG0(* cpu_regs);

    if(extract_pathlink_pidmemstr(pid, pidmem_str0, path0, path_size) < 0){
        return -1;
    }

    // extract path1

    int pidmem_dirfd1 = CPU_REG_R_SYSCALL_ARG1(* cpu_regs);
    char * pidmem_str2 = (char *) CPU_REG_R_SYSCALL_ARG2(* cpu_regs);

    char tmp[path_size];

    if(extract_pidmemdirfd_pathlink(pid, pidmem_dirfd1, pidmem_str2, path_size, path1, tmp) < 0){
        return -1;
    }

    return 2;

}

// TODO untested
static int extract_arg0dirfdA_arg1pathlinkA_arg2dirfdB_arg3pathlinkB(pid_t pid, struct user_regs_struct * cpu_regs, size_t path_size, char * path0, char * path1){

    char tmp[path_size];

    // extract path0

    int pidmem_dirfd0 = CPU_REG_R_SYSCALL_ARG0(* cpu_regs);
    char * pidmem_str0 = (char *) CPU_REG_R_SYSCALL_ARG1(* cpu_regs);

    if(extract_pidmemdirfd_pathlink(pid, pidmem_dirfd0, pidmem_str0, path_size, path0, tmp) < 0){
        return -1;
    }

    // extract path1

    int pidmem_dirfd1 = CPU_REG_R_SYSCALL_ARG2(* cpu_regs);
    char * pidmem_str1 = (char *) CPU_REG_R_SYSCALL_ARG3(* cpu_regs);

    if(extract_pidmemdirfd_pathlink(pid, pidmem_dirfd1, pidmem_str1, path_size, path1, tmp)){
        return -1;
    }

    return 2;

}
