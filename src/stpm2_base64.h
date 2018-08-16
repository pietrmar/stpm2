#ifndef __STPM2_BASE64_H__
#define __STPM2_BASE64_H__

#include <sys/types.h>
#include <stdint.h>

size_t base64_get_encsize(size_t insize);
ssize_t base64_enc(uint8_t *in, size_t insize, char *out, size_t outsize);

#endif /* __STPM2_BASE64_H__ */

