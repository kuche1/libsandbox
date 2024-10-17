
// this might actually turn out to be a bad idea since if someone
// if to CTRL+F for return, they might miss this macro

// // `...` is the error message
// #define ASSERT_0_OR_MORE(value, return_code_if_failure, ...){ \
//     if((value) < 0){ \
//         fprintf(stderr, ERR_PREFIX __VA_ARGS__); \
//         return return_code_if_failure; \
//     }\
// }
