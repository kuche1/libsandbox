
// `str_len` is excluding the last \0
static int str_append_char(char * str, size_t str_cap, size_t * str_len, char ch){
    if(* str_len + 1 >= str_cap){
        return 1;
    }

    str[*str_len] = ch;
    * str_len += 1;
    str[*str_len] = 0;

    return 0;
}
