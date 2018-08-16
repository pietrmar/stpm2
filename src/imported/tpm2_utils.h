#ifndef __TPM2_UTILS__H__
#define __TPM2_UTILS__H__

#include <tpm2_error.h>

/*
 * This macros and helper functions here are imported from the tpm2-tools
 * project and are intended for internal use of the library only.
 */

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }

#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))

#define UNUSED(x) (void)x

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    __extension__ ({                                       \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (tpm2_error_get(__result) == TPM2_RC_RETRY); \
        __result;                                          \
    })

#endif /* __TPM2_UTILS_H__ */

