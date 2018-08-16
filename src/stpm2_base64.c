#include <sys/types.h>
#include <stdint.h>

#include "stpm2_base64.h"
#include "stpm2_log.h"

static const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_mod_table[] = {0, 2, 1};

size_t base64_get_encsize(size_t insize)
{
	return 4 * ((insize + 2) / 3);
}

/* Based on: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
ssize_t base64_enc(uint8_t *in, size_t insize, char *out, size_t outsize)
{
	TRACE_ENTER();

	size_t real_outsize = base64_get_encsize(insize);

	if (outsize < real_outsize) {
		LOG_ERROR("output buffer size is too small");
		return -1;
	}

	for (size_t i = 0, j = 0; i < insize; ) {
		uint32_t octet_a = i < insize ? in[i++] : 0;
		uint32_t octet_b = i < insize ? in[i++] : 0;
		uint32_t octet_c = i < insize ? in[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		out[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
		out[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
		out[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
		out[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < base64_mod_table[insize % 3]; i++) {
		out[real_outsize - 1 - i] = '=';
	}

	TRACE_LEAVE();
	return real_outsize;
}

