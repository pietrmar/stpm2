#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include <tpm2_utils.h>
#include <tpm2_error.h>

#include "stpm2.h"
#include "stpm2_log.h"
#include "stpm2_base64.h"

static int init_tcti(stpm2_context *ctx)
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
		goto err_clean_dlopen;
	}

	const TSS2_TCTI_INFO *info = infofn();
	TSS2_TCTI_INIT_FUNC init = info->init;

	size_t size;
	TSS2_RC ret = init(NULL, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init failed with %s", tpm2_error_str(ret));
		goto err_clean_dlopen;
	}

	ctx->tcti_ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
	if (ctx->tcti_ctx == NULL) {
		LOG_ERROR("Failed to allocate tcti_ctx");
		goto err_clean_dlopen;
	}

	ret = init(ctx->tcti_ctx, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init call failed %s", tpm2_error_str(ret));
		goto err_clean_tcti;
	}

	TRACE_LEAVE();
	return 0;

err_clean_tcti:
	free(ctx->tcti_ctx);
	ctx->tcti_ctx = NULL;
err_clean_dlopen:
	dlclose(ctx->tcti_so_handle);
	ctx->tcti_so_handle = NULL;
	return -1;
}

static int free_tcti(stpm2_context *ctx)
{
	TRACE_ENTER();

	int ret = 0;

	Tss2_Tcti_Finalize(ctx->tcti_ctx);
	free(ctx->tcti_ctx);
	ctx->tcti_ctx = NULL;

	if (dlclose(ctx->tcti_so_handle) != 0) {
		LOG_ERROR("dlclose() failed");
		ret = -1;
	}
	ctx->tcti_so_handle = NULL;

	TRACE_LEAVE();
	return ret;
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
			ret = __fn__(__VA_ARGS__); \
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

	if (init_tcti(ctx) < 0) {
		LOG_ERROR("init_tcit() failed");
		free(ctx->sys_ctx);
		return -1;
	}

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Initialize, ctx->sys_ctx, ctx_size, ctx->tcti_ctx, &abi_version);

	/* we cannot use the TSS2_CHECKED_CALL_RETRY() macro here because Tss2_Sys_Startup() can return TPM2_RC_INITIALIZE */
	ret = TSS2_RETRY_EXP(Tss2_Sys_Startup(ctx->sys_ctx, TPM2_SU_CLEAR));
	if (ret != TPM2_RC_SUCCESS && ret != TPM2_RC_INITIALIZE) {
		LOG_ERROR("Tss2_Sys_Startup() failed with %s", tpm2_error_str(ret));
		goto err_free;
	}

	/* Flush all objects to have a clean state */
	if (stpm2_flush_all(ctx) < 0) {
		LOG_ERROR("stpm2_flush_all() failed");
		goto err_free;
	}

	/* Always create a primary key */
	if (stpm2_create_primary(ctx) < 0) {
		LOG_ERROR("Failed to create primary key");
		goto err_free;
	}

	TRACE_LEAVE();
	return 0;

err_free:
	stpm2_free(ctx);
	return -1;
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

	ret = free_tcti(ctx);
	if (ret < 0) {
		LOG_ERROR("free_tcti() failed");
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

/* TODO: only return 0 or -1 here and use a size_t output parameter */
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

int stpm2_export_pubkey_pem(stpm2_context *ctx, const char *path)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() or stpm2_load_key()");
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

	size_t fret;
	fret = fwrite(openssl_begin_pubkey, 1, strlen(openssl_begin_pubkey), f);
	if (fret != strlen(openssl_begin_pubkey)) {
		LOG_ERROR("failed writing to file %s", path);
		free(pemkey_b64);
		return -1;
	}

	fret = fwrite(pemkey_b64, 1, pemsize_b64, f);
	if (fret != pemsize_b64) {
		LOG_ERROR("failed writing to file %s", path);
		free(pemkey_b64);
		return -1;
	}
	free(pemkey_b64);

	fret = fwrite(openssl_end_pubkey, 1, strlen(openssl_end_pubkey), f);
	if (fret != strlen(openssl_end_pubkey)) {
		LOG_ERROR("failed writing to file %s", path);
		return -1;
	}
	fclose(f);

	TRACE_LEAVE();
	return 0;
}


/*
 * TODO: in case some of the marshalling functions fail we will have a partly written file, we should fix this.
 * TODO: there is too much boilerplate code, maybe write some nice macros
 */
int stpm2_export_key(stpm2_context *ctx, const char *path)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() or stpm2_load_key()");
		return -1;
	}

	/* Write the header */
	FILE *f = fopen(path, "w");
	if (f == NULL) {
		LOG_ERROR("Could not open file %s for writing: %s", path, strerror(errno));
		return -1;
	}

	size_t fret = 0;
	fret = fwrite("STPM2", 1, 5, f);
	if (fret != 5) {
		LOG_ERROR("failed writing to file %s", path);
		fclose(f);
		return -1;
	}
	size_t offset = 0;

	/* Write the public part */
	uint8_t pub_buffer[sizeof(ctx->current_rsa_key.pub)] = { 0 };
	TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(&ctx->current_rsa_key.pub, pub_buffer, sizeof(pub_buffer), &offset);
	if (rc != TSS2_RC_SUCCESS) {
		LOG_ERROR("Tss2_MU_TPM2B_PUBLIC_Marshal() failed with %s", tpm2_error_str(rc));
		fclose(f);
		return -1;
	}
	fret = fwrite(pub_buffer, 1, offset, f);
	if (fret != offset) {
		LOG_ERROR("failed writing to file %s", path);
		fclose(f);
		return -1;
	}

	/* Write the private part */
	uint8_t priv_buffer[sizeof(ctx->current_rsa_key.priv)] = { 0 };
	rc = Tss2_MU_TPM2B_PRIVATE_Marshal(&ctx->current_rsa_key.priv, priv_buffer, sizeof(priv_buffer), &offset);
	if (rc != TSS2_RC_SUCCESS) {
		LOG_ERROR("Tss2_MU_TPM2B_PRIVATE_Marshal() failed with %s", tpm2_error_str(rc));
		fclose(f);
		return -1;
	}
	fret = fwrite(priv_buffer, 1, offset, f);
	if (fret != offset) {
		LOG_ERROR("failed writing to file %s", path);
		fclose(f);
		return -1;
	}

	fclose(f);

	TRACE_LEAVE();
	return 0;
}

int stpm2_load_key(stpm2_context *ctx, const char *path)
{
	TRACE_ENTER();

	if (ctx->current_rsa_key.handle != 0) {
		LOG_ERROR("a key is already loaded, please call stpm2_unload_key() first");
		return -1;
	}

	FILE *f = fopen(path, "r");
	if (f == NULL) {
		LOG_ERROR("Could not open file %s for reading: %s", path, strerror(errno));
		return -1;
	}

	size_t fret = 0;
	char magic_buffer[5] = { 0 };
	size_t offset = 0;

	fret = fread(magic_buffer, 1, 5, f);
	if (fret != 5 || (strncmp(magic_buffer, "STPM2", 5) != 0)) {
		LOG_ERROR("Could not read magic header from file %s", path);
		fclose(f);
		return -1;
	}

	/* Read public part */
	uint8_t pub_buffer[sizeof(ctx->current_rsa_key.pub)] = { 0 };
	fret = fread(pub_buffer, 1, sizeof(pub_buffer), f);
	if (fret != sizeof(pub_buffer)) {
		/* TODO: check ferror() and feof() */
		LOG_WARN("Short or failed read from file %s, tried to read %zu, got %zu", path, sizeof(pub_buffer), fret);
	}

	TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_buffer, sizeof(pub_buffer), &offset, &ctx->current_rsa_key.pub);
	if (rc != TSS2_RC_SUCCESS) {
		LOG_ERROR("Tss2_MU_TPM2B_PUBLIC_Unmarshal() failed with %s", tpm2_error_str(rc));
		fclose(f);
		return -1;
	}

	/* Read private part */
	/* Reposition file pointer at start of new section */
	fseek(f, offset + 5, SEEK_SET);
	uint8_t priv_buffer[sizeof(ctx->current_rsa_key.priv)] = { 0 };
	fret = fread(priv_buffer, 1, sizeof(priv_buffer), f);
	if (fret != sizeof(priv_buffer)) {
		/* TODO: check ferror() and feof() */
		LOG_WARN("Short or failed read from file %s, tried to read %zu, got %zu", path, sizeof(pub_buffer), fret);
	}
	rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_buffer, sizeof(priv_buffer), &offset, &ctx->current_rsa_key.priv);
	if (rc != TSS2_RC_SUCCESS) {
		LOG_ERROR("Tss2_MU_TPM2B_PRIVATE_Unmarshal() failed with %s", tpm2_error_str(rc));
		fclose(f);
		return -1;
	}
	fclose(f);

	TSS2L_SYS_AUTH_COMMAND sessions_cmd = {
		.count = 1,
		.auths = {{ .sessionHandle = TPM2_RS_PW }},
	};

	TSS2L_SYS_AUTH_RESPONSE sessions_rsp;

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

int stpm2_rsa_encrypt(stpm2_context *ctx, uint8_t *in, size_t insize, uint8_t *out, size_t outsize)
{
	TRACE_ENTER();
	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() or stpm2_load_key()");
		return -1;
	}

	if (insize > (STPM2_RSA_ENC_MESSAGE_SIZE - 11)) {
		LOG_ERROR("message size is too long, got: %zu max: %d\n", insize, (STPM2_RSA_ENC_MESSAGE_SIZE - 11));
		return -1;
	}

	if (outsize < STPM2_RSA_ENC_MESSAGE_SIZE) {
		LOG_ERROR("output buffer is too small, got: %zu required: %d\n", outsize, STPM2_RSA_ENC_MESSAGE_SIZE);
		return -1;
	}

	TPM2B_PUBLIC_KEY_RSA input_message;
	input_message.size = insize;
	memcpy(input_message.buffer, in, insize);

	TPMT_RSA_DECRYPT in_scheme;
	in_scheme.scheme = TPM2_ALG_RSAES;

	TPM2B_PUBLIC_KEY_RSA output_data;
	TPM2B_DATA label = { .size = 0, };

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_RSA_Encrypt,
				ctx->sys_ctx,
				ctx->current_rsa_key.handle,
				NULL,
				&input_message,
				&in_scheme,
				&label,
				&output_data,
				NULL);

	LOG_DEBUG("encrypted %zu bytes, got %u bytes back", insize, output_data.size);
	if (output_data.size > outsize) {
		LOG_ERROR("encrypted data size is larger than the output buffer");
		return -1;
	}

	memcpy(out, output_data.buffer, output_data.size);

	TRACE_LEAVE();
	return 0;
}

int stpm2_rsa_decrypt(stpm2_context *ctx, uint8_t *in, size_t insize, uint8_t *out, size_t outsize, size_t *actual_size)
{
	TRACE_ENTER();
	if (ctx->current_rsa_key.handle == 0) {
		LOG_ERROR("no key is present in context, use stpm2_create_rsa_2048() or stpm2_load_key()");
		return -1;
	}

	TSS2L_SYS_AUTH_COMMAND sessions_cmd = {
		.count = 1,
		.auths = {{ .sessionHandle = TPM2_RS_PW }},
	};

	TPM2B_PUBLIC_KEY_RSA input_data;
	input_data.size = insize;
	memcpy(input_data.buffer, in, insize);

	TPMT_RSA_DECRYPT in_scheme;
	in_scheme.scheme = TPM2_ALG_RSAES;

	TPM2B_PUBLIC_KEY_RSA output_message;
	TPM2B_DATA label = { .size = 0, };

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_RSA_Decrypt,
				ctx->sys_ctx,
				ctx->current_rsa_key.handle,
				&sessions_cmd,
				&input_data,
				&in_scheme,
				&label,
				&output_message,
				NULL);

	LOG_DEBUG("decrypted %zu bytes, got %u bytes back", insize, output_message.size);
	if (output_message.size > outsize) {
		LOG_ERROR("decrypted data size is larger than the output buffer");
		return -1;
	}
	memcpy(out, output_message.buffer, output_message.size);

	if (actual_size != NULL) {
		*actual_size = output_message.size;
	}

	TRACE_LEAVE();
	return 0;
}

#undef TSS2_CHECKED_CALL
#undef TSS2_CHECKED_CALL_RETRY

