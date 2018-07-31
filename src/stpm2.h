#ifndef __STPM2_H__
#define __STPM2_H__

#include <stdint.h>

#include <tss2/tss2_sys.h>

typedef struct {
	TSS2_SYS_CONTEXT	*sys_ctx;
	TSS2_TCTI_CONTEXT	*tcti_ctx;

	void 	*tcti_so_handle;
} stpm2_context;

int stpm2_init(stpm2_context *ctx);
int stpm2_free(stpm2_context *ctx);
int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size);

#endif /* __STPM2_H__ */
