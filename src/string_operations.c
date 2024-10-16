
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

static int str_append_str(char * str0, size_t str0_cap, size_t * str0_len, char * str1){

    str0 += * str0_len;

    for(;;){

        if(* str0_len + 1 >= str0_cap){
            return 1;
        }

        char ch = str1[0];

        str0[0] = ch;

        if(ch == 0){
            return 0;
        }

        str0 += 1;
        str1 += 1;

        * str0_len += 1;

    }
}
