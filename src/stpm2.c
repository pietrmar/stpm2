#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tpm2_utils.h>
#include <tpm2_error.h>

#include "stpm2.h"
#include "stpm2_log.h"

static int init_tcit(stpm2_context *ctx)
{
	TRACE_ENTER();

	/*
	 * Tested with:
	 *  * libtss2-tcti-tabrmd.so (access broker, which uses the simulator at the backend)
	 *  * libtss2-tcti-mssim.so  (simulator)
	 *
	 *  TODO:
	 *   * test with libtss2-tcti-device.so on the RPi
	 */
	const char *tcti_so = "libtss2-tcti-mssim.so";

	ctx->tcti_so_handle = dlopen(tcti_so, RTLD_LAZY);
	if (!ctx->tcti_so_handle) {
		LOG_ERROR("Failed to load %s", tcti_so);
		return -1;
	}

	/*
	 * We need to use this trick to get around the "ISO C forbids conversion of object pointer to function pointer type"
	 * warning which comes with -Wpedantic.
	 *
	 * Based on: https://stackoverflow.com/questions/14134245/iso-c-void-and-function-pointers
	 */
	TSS2_TCTI_INFO_FUNC infofn;
	*((void **)(&infofn)) = dlsym(ctx->tcti_so_handle, TSS2_TCTI_INFO_SYMBOL);

	if (!infofn) {
		LOG_ERROR("Could not find synbol %s in %s\n", TSS2_TCTI_INFO_SYMBOL, tcti_so);
		return -1;
	}

	const TSS2_TCTI_INFO *info = infofn();
	TSS2_TCTI_INIT_FUNC init = info->init;

	size_t size;
	TSS2_RC ret = init(NULL, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init failed with %s", tpm2_error_str(ret));
		return -1;
	}

	ctx->tcti_ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
	if (ctx->tcti_ctx == NULL) {
		LOG_ERROR("Failed to allocate tcti_ctx");
		return -1;
	}

	ret = init(ctx->tcti_ctx, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init call failed %s", tpm2_error_str(ret));
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

#define TSS2_CHECKED_CALL(__fn__, ...) do { \
		TSS2_RC ret = __fn__(__VA_ARGS__); \
		if (ret != TSS2_RC_SUCCESS) { \
			LOG_ERROR(#__fn__"() failed with %s", tpm2_error_str(ret)); \
			return -1; \
		} \
	} while(0)

#define TSS2_CHECKED_CALL_RETRY(__fn__, ...) do { \
		TSS2_RC ret = 0; \
		do { \
			TSS2_RC ret = __fn__(__VA_ARGS__); \
			if (ret != TSS2_RC_SUCCESS && tpm2_error_get(ret) != TPM2_RC_RETRY) { \
				LOG_ERROR(#__fn__"() failed with %s", tpm2_error_str(ret)); \
				return -1; \
			} \
		} while(tpm2_error_get(ret) == TPM2_RC_RETRY); \
	} while(0)

/* Based on access_broker_flush_all_unlocked() from https://github.com/tpm2-software/tpm2-abrmd.git */
static int stpm2_flush_context_range(stpm2_context *ctx, TPM2_RH first, TPM2_RH last)
{
	TRACE_ENTER();

	TPMS_CAPABILITY_DATA capability_data = { 0 };
	TPM2_HANDLE handle;
	size_t i;

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_GetCapability,
				ctx->sys_ctx,
				NULL,
				TPM2_CAP_HANDLES,
				first,
				last - first,
				NULL,
				&capability_data,
				NULL);

	for (i = 0; i < capability_data.data.handles.count; i++) {
		handle = capability_data.data.handles.handle[i];
		TSS2_CHECKED_CALL_RETRY(Tss2_Sys_FlushContext, ctx->sys_ctx, handle);
	}

	TRACE_LEAVE();
	return 0;
}

static int stpm2_flush_all(stpm2_context *ctx)
{
	TRACE_ENTER();

	if (stpm2_flush_context_range(ctx, TPM2_ACTIVE_SESSION_FIRST, TPM2_ACTIVE_SESSION_LAST) < 0) {
		LOG_ERROR("Failed to flush active sessions");
		return -1;
	}

	if (stpm2_flush_context_range(ctx, TPM2_LOADED_SESSION_FIRST, TPM2_LOADED_SESSION_LAST) < 0) {
		LOG_ERROR("Failed to flush loaded sessions");
		return -1;
	}

	if (stpm2_flush_context_range(ctx, TPM2_TRANSIENT_FIRST, TPM2_TRANSIENT_LAST) < 0) {
		LOG_ERROR("Failed to flush transient objects");
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

/*
 * This creates a primary key with the default settings that match tpm2_createprimary,
 * they key is stored inside the stpm2_context struct
 */
static int stpm2_create_primary(stpm2_context *ctx)
{
	TRACE_ENTER();

	TSS2L_SYS_AUTH_COMMAND sessions_cmd = {
		.count = 1,
		.auths = {{ .sessionHandle = TPM2_RS_PW }},
	};

	TSS2L_SYS_AUTH_RESPONSE sessions_rsp;

	TPM2B_SENSITIVE_CREATE	in_sensitive	= { 0 };
	TPM2B_DATA		outside_info	= { 0 };
	TPM2B_CREATION_DATA	creation_data	= { 0 };
	TPM2B_DIGEST		creation_hash	= TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPM2B_PUBLIC		in_public	= { 0 };
	TPMT_TK_CREATION	creation_ticket	= { 0 };
	TPM2B_NAME		name		= TPM2B_TYPE_INIT(TPM2B_NAME, name);
	TPML_PCR_SELECTION	creation_pcr	= { 0 };
	TPM2B_PUBLIC		out_public	= { 0 };

	in_public.publicArea.type = TPM2_ALG_RSA;
	in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
	in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 256;
	in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.keyBits = 2048;

	ctx->primary_handle = 0;
	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_CreatePrimary,
				ctx->sys_ctx,
				TPM2_RH_OWNER,
				&sessions_cmd,
				&in_sensitive,
				&in_public,
				&outside_info,
				&creation_pcr,
				&ctx->primary_handle,
				&out_public,
				&creation_data,
				&creation_hash,
				&creation_ticket,
				&name,
				&sessions_rsp);

	LOG_INFO("Created primary key with handle 0x%X", ctx->primary_handle);

	LOG_HEXDUMP(STPM2_LOG_LEVEL_DEBUG,
			"Public RSA modulus",
			out_public.publicArea.unique.rsa.buffer,
			out_public.publicArea.unique.rsa.size);

	TRACE_LEAVE();
	return 0;
}

int stpm2_init(stpm2_context *ctx)
{
	TRACE_ENTER();

	TSS2_RC ret;
	/* Use current ABI version of tss2 headers we are compiling against */
	TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

	memset(ctx, 0, sizeof(*ctx));

	/* Allocate system ctx */
	size_t ctx_size = Tss2_Sys_GetContextSize(0);

	ctx->sys_ctx = (TSS2_SYS_CONTEXT *)calloc(1, ctx_size);
	if (ctx->sys_ctx == NULL) {
		LOG_ERROR("Failed to allocate sys_ctx");
		return -1;
	}

	if (init_tcit(ctx) < 0) {
		LOG_ERROR("init_tcit() failed");
		return -1;
	}

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Initialize, ctx->sys_ctx, ctx_size, ctx->tcti_ctx, &abi_version);

	/* we cannot use the TSS2_CHECKED_CALL_RETRY() macro here because Tss2_Sys_Startup() can return TPM2_RC_INITIALIZE */
	ret = TSS2_RETRY_EXP(Tss2_Sys_Startup(ctx->sys_ctx, TPM2_SU_CLEAR));
	if (ret != TPM2_RC_SUCCESS && ret != TPM2_RC_INITIALIZE) {
		LOG_ERROR("Tss2_Sys_Startup() failed with %s", tpm2_error_str(ret));
		return -1;
	}

	/* Flush all objects to have a clean state */
	if (stpm2_flush_all(ctx) < 0) {
		LOG_ERROR("stpm2_flush_all() failed");
		return -1;
	}

	/* Always create a primary key */
	if (stpm2_create_primary(ctx) < 0) {
		LOG_ERROR("Failed to create primary key");
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

int stpm2_free(stpm2_context *ctx)
{
	TRACE_ENTER();

	int ret = 0;

	/* Since we are freeing memory we do not want to exit on failure in any of the following functions */
	if (stpm2_flush_all(ctx) < 0) {
		LOG_ERROR("stpm2_flush_all() failed");
		ret = -1;
	}

	TSS2_RC tss2_ret = Tss2_Sys_Shutdown(ctx->sys_ctx, NULL, TPM2_SU_CLEAR, NULL);
	if (tss2_ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("Tss2_Sys_Shutdown() failed with %s", tpm2_error_str(tss2_ret));
		ret = -1;
	}

	Tss2_Sys_Finalize(ctx->sys_ctx);
	free(ctx->sys_ctx);
	ctx->sys_ctx = NULL;

	Tss2_Tcti_Finalize(ctx->tcti_ctx);
	free(ctx->tcti_ctx);
	ctx->tcti_ctx = NULL;

	if (dlclose(ctx->tcti_so_handle) != 0) {
		LOG_ERROR("dlclose() failed");
		ret = -1;
	}
	ctx->tcti_so_handle = NULL;

	memset(ctx, 0, sizeof(*ctx));

	TRACE_LEAVE();
	return ret;
}

int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size)
{
	TRACE_ENTER();

	/*TODO: check size of output buffer, the TPM2 can only deliver a limited number of random bytes on one call. */
	TPM2B_DIGEST random_bytes = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_GetRandom, ctx->sys_ctx, NULL, size, &random_bytes, NULL);

	size_t i;
	for(i = 0; i < size; i++) {
		buf[i] = random_bytes.buffer[i];
	}

	TRACE_LEAVE();
	return 0;
}

static TPMI_ALG_HASH stpm2_to_tpmi_alg(stpm2_hash_alg alg)
{
	switch(alg) {
	case STPM2_HASH_ALG_SHA1:
		return TPM2_ALG_SHA1;
	case STPM2_HASH_ALG_SHA256:
		return TPM2_ALG_SHA256;
	case STPM2_HASH_ALG_SHA384:
		return TPM2_ALG_SHA384;
	case STPM2_HASH_ALG_SHA512:
		return TPM2_ALG_SHA512;
	default:
		LOG_ERROR("Unknown hash algorithm specified");
		return TPM2_ALG_NULL;
	}
}

int stpm2_hash(stpm2_context *ctx, stpm2_hash_alg alg, const uint8_t *buf, size_t size, uint8_t *outbuf, size_t outsize)
{
	TRACE_ENTER();

	/* TODO: handle input which is larger than TPM2_MAX_DIGEST_BUFFER */
	if (size > TPM2_MAX_DIGEST_BUFFER) {
		LOG_ERROR("stpm2_hash() only supports buffers of up to %zu bytes", TPM2_MAX_DIGEST_BUFFER);
		return -1;
	}

        TPM2B_MAX_BUFFER buffer = { .size = size };
	TPM2B_DIGEST result = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPMT_TK_HASHCHECK validation;

	memcpy(buffer.buffer, buf, size);

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Hash, ctx->sys_ctx, NULL, &buffer, stpm2_to_tpmi_alg(alg), TPM2_RH_OWNER, &result, &validation, NULL);

	int i;
	for (i = 0; i < outsize && i < result.size; i++) {
		outbuf[i] = result.buffer[i];
	}

	TRACE_LEAVE();
	return i;
}

int stpm2_unload_key(stpm2_context *ctx)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() od stpm2_load_key()");
		return -1;
	}

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_FlushContext, ctx->sys_ctx, ctx->current_rsa_key.handle);
	memset(&ctx->current_rsa_key, 0, sizeof(ctx->current_rsa_key));

	TRACE_LEAVE();
	return 0;
}


/* TODO: Those base64 stuff should go into seperate files */
static uint8_t openssl_pem_header[] = {
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
};

static uint8_t openssl_pem_trail[] = {
	0x02, 0x03,		/* integer exponent (0x02) and 3-byte long (0x03) */
	0x01, 0x00, 0x01,	/* the exponent 65537 (2^16 + 1) */
};

static const char *openssl_begin_pubkey = "-----BEGIN PUBLIC KEY-----\n";
static const char *openssl_end_pubkey = "\n-----END PUBLIC KEY-----\n";

static const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_mod_table[] = {0, 2, 1};

static size_t base64_get_encsize(size_t insize)
{
	return 4 * ((insize + 2) / 3);
}

/* Based on: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
static ssize_t base64_enc(uint8_t *in, size_t insize, char *out, size_t outsize)
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

int stpm2_export_pubkey_pem(stpm2_context *ctx, const char *path)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() od stpm2_load_key()");
		return -1;
	}

	size_t pubsize_bin = ctx->current_rsa_key.pub.publicArea.unique.rsa.size;
	size_t pemsize_bin = sizeof(openssl_pem_header) + pubsize_bin + sizeof(openssl_pem_trail);
	uint8_t *pemkey_bin = malloc(pemsize_bin);
	if (pemkey_bin == NULL) {
		LOG_ERROR("malloc() failed");
		return -1;
	}

	size_t pemsize_b64 = base64_get_encsize(pemsize_bin);
	char *pemkey_b64 = malloc(pemsize_b64);
	if (pemkey_b64 == NULL) {
		free(pemkey_bin);
		LOG_ERROR("malloc() failed");
		return -1;
	}

	size_t off = 0;
	memcpy(pemkey_bin + off, openssl_pem_header, sizeof(openssl_pem_header));
	off += sizeof(openssl_pem_header);

	memcpy(pemkey_bin + off, ctx->current_rsa_key.pub.publicArea.unique.rsa.buffer, pubsize_bin);
	off += pubsize_bin;

	memcpy(pemkey_bin + off, openssl_pem_trail, sizeof(openssl_pem_trail));
	off += sizeof(openssl_pem_trail);

	ssize_t ret = base64_enc(pemkey_bin, pemsize_bin, pemkey_b64, pemsize_b64);
	if (ret < 0) {
		LOG_ERROR("base64_enc() failed\n");
		free(pemkey_bin);
		free(pemkey_b64);
		return -1;
	}
	free(pemkey_bin);

	FILE *f = fopen(path, "w");
	if (f == NULL) {
		LOG_ERROR("Could not open file %s for writing: %s", path, strerror(errno));
		free(pemkey_b64);
		return -1;
	}

	fwrite(openssl_begin_pubkey, 1, strlen(openssl_begin_pubkey), f);
	fwrite(pemkey_b64, 1, pemsize_b64, f);
	fwrite(openssl_end_pubkey, 1, strlen(openssl_end_pubkey), f);
	fclose(f);

	TRACE_LEAVE();
	return 0;
}

int stpm2_create_rsa_2048(stpm2_context *ctx)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle != 0) {
		LOG_ERROR("a key is already loaded, please call stpm2_unload_key() first");
		return -1;
	}

	TSS2L_SYS_AUTH_COMMAND sessions_cmd = {
		.count = 1,
		.auths = {{ .sessionHandle = TPM2_RS_PW }},
	};

	TSS2L_SYS_AUTH_RESPONSE sessions_rsp;

	TPM2B_SENSITIVE_CREATE	in_sensitive	= { 0 };
	TPM2B_DATA		outside_info	= { 0 };
	TPM2B_CREATION_DATA	creation_data	= { 0 };
	TPM2B_DIGEST		creation_hash	= TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPMT_TK_CREATION	creation_ticket	= { 0 };
	TPML_PCR_SELECTION	creation_pcr	= { 0 };

	/* For a detailed description see TPM-Rev-2.0-Part-1-Architecture-01.38.pdf section 27.2 */
	TPM2B_PUBLIC in_public = { 0 };
	in_public.publicArea.type = TPM2_ALG_RSA;
	in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
	in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.keyBits = 2048;


	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Create,
				ctx->sys_ctx,
				ctx->primary_handle,
				&sessions_cmd,
				&in_sensitive,
				&in_public,
				&outside_info,
				&creation_pcr,
				&ctx->current_rsa_key.priv,
				&ctx->current_rsa_key.pub,
				&creation_data,
				&creation_hash,
				&creation_ticket,
				&sessions_rsp);

	LOG_INFO("Created RSA key");
	LOG_HEXDUMP(STPM2_LOG_LEVEL_DEBUG,
			"Public RSA modulus",
			ctx->current_rsa_key.pub.publicArea.unique.rsa.buffer,
			ctx->current_rsa_key.pub.publicArea.unique.rsa.size);

	LOG_HEXDUMP(STPM2_LOG_LEVEL_DEBUG,
			"Private RSA part",
			ctx->current_rsa_key.priv.buffer,
			ctx->current_rsa_key.priv.size);

	LOG_DEBUG("Loading new key");
	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Load,
				ctx->sys_ctx,
				ctx->primary_handle,
				&sessions_cmd,
				&ctx->current_rsa_key.priv,
				&ctx->current_rsa_key.pub,
				&ctx->current_rsa_key.handle,
				NULL,
				&sessions_rsp);
	LOG_INFO("New key handle is 0x%X", ctx->current_rsa_key.handle);

	TRACE_LEAVE();
	return 0;
}


#undef TSS2_CHECKED_CALL
#undef TSS2_CHECKED_CALL_RETRY

