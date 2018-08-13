#ifndef __STPM2_H__
#define __STPM2_H__

#include <stdint.h>

#include <tss2/tss2_sys.h>

typedef struct {
	TSS2_SYS_CONTEXT	*sys_ctx;
	TSS2_TCTI_CONTEXT	*tcti_ctx;

	void 	*tcti_so_handle;

	TPM2_HANDLE		primary_handle;
} stpm2_context;

typedef enum {
	STPM2_HASH_ALG_SHA1,
	STPM2_HASH_ALG_SHA256,
	STPM2_HASH_ALG_SHA384,
	STPM2_HASH_ALG_SHA512,
} stpm2_hash_alg;

int stpm2_init(stpm2_context *ctx);
int stpm2_free(stpm2_context *ctx);

int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size);
int stpm2_hash(stpm2_context *ctx, stpm2_hash_alg alg, const uint8_t *buf, size_t size, uint8_t *outbuf, size_t outsize);

#endif /* __STPM2_H__ */
