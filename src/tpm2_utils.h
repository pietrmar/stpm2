#ifndef __TPM2_UTILS__H__
#define __TPM2_UTILS__H__

/*
 * This macros and helper functions here are imported from the tpm2-tools
 * project and are intended for internal use of the library only.
 */

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }


/**
 * Mask for the error bits of tpm2 compliant return code.
 */
#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

/**
 * Retrieves the error bits from a TSS2_RC. The error bits are
 * contained in the first 2 octets.
 * @param rc
 *  The rc to query for the error bits.
 * @return
 *  The error bits.
 */
static inline UINT16 tpm2_error_get(TSS2_RC rc) {
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (tpm2_error_get(__result) == TPM2_RC_RETRY); \
        __result;                                          \
    })

#endif /* __TPM2_UTILS_H__ */
