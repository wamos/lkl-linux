#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/internal/skcipher.h>
#include <crypto/aes.h>
#include <asm/fpu/api.h>

struct xtsproxy_ctx {
	struct crypto_skcipher *xts_aesni;
	struct crypto_skcipher *xts_generic;
};

static int xtsproxy_skcipher_init(struct crypto_skcipher *tfm)
{
	struct xtsproxy_ctx *ctx = crypto_skcipher_ctx(tfm);

	/* AESNI based XTS implementation, requires FPU to be available */
	ctx->xts_aesni = crypto_alloc_skcipher("__xts-aes-aesni", CRYPTO_ALG_INTERNAL, 0);
	if (IS_ERR(ctx->xts_aesni))
		return PTR_ERR(ctx->xts_aesni);

	/* generic XTS implementation based on generic FPU-less AES */
	/* there is also aes-aesni implementation, which falls back to aes-generic */
	/* but we're doing FPU checks in our code, so no need to repeat those */
	/* as we will always fallback to aes-generic in this case */
	ctx->xts_generic = crypto_alloc_skcipher("xts(ecb(aes-generic))", 0, 0);
	if (IS_ERR(ctx->xts_generic))
		return PTR_ERR(ctx->xts_generic);

	/* make sure we allocate enough request memory for both implementations */
	crypto_skcipher_set_reqsize(tfm, max(crypto_skcipher_reqsize(ctx->xts_aesni), crypto_skcipher_reqsize(ctx->xts_generic)));

	return 0;
}

static void xtsproxy_skcipher_exit(struct crypto_skcipher *tfm)
{
	struct xtsproxy_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (!IS_ERR_OR_NULL(ctx->xts_generic)) {
		crypto_free_skcipher(ctx->xts_generic);
		ctx->xts_generic = NULL;
	}

	if (!IS_ERR_OR_NULL(ctx->xts_aesni)) {
		crypto_free_skcipher(ctx->xts_aesni);
		ctx->xts_aesni = NULL;
	}
}

static int xtsproxy_setkey(struct crypto_skcipher *tfm, const u8 *key,
			    unsigned int keylen)
{
	struct xtsproxy_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = crypto_skcipher_setkey(ctx->xts_aesni, key, keylen);
	if (err)
		return err;

	return crypto_skcipher_setkey(ctx->xts_generic, key, keylen);
}

static int xtsproxy_encrypt(struct skcipher_request *req)
{
	struct xtsproxy_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));

	if (irq_fpu_usable())
		skcipher_request_set_tfm(req, ctx->xts_aesni);
	else
		skcipher_request_set_tfm(req, ctx->xts_generic);

	/* underlying implementations should not try to sleep */
	req->base.flags &= ~(CRYPTO_TFM_REQ_MAY_SLEEP | CRYPTO_TFM_REQ_MAY_BACKLOG);

	return crypto_skcipher_encrypt(req);
}

static int xtsproxy_decrypt(struct skcipher_request *req)
{
	struct xtsproxy_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));

	if (irq_fpu_usable())
		skcipher_request_set_tfm(req, ctx->xts_aesni);
	else
		skcipher_request_set_tfm(req, ctx->xts_generic);

	/* underlying implementations should not try to sleep */
	req->base.flags &= ~(CRYPTO_TFM_REQ_MAY_SLEEP | CRYPTO_TFM_REQ_MAY_BACKLOG);

	return crypto_skcipher_decrypt(req);
}

static struct skcipher_alg xtsproxy_skcipher = {
	.base = {
		.cra_name			= "xts(aes)",
		.cra_driver_name	= "xts-aes-xtsproxy",
		/* make sure we don't use it unless requested explicitly */
		.cra_priority		= 402,
		/* .cra_flags			= CRYPTO_ALG_INTERNAL, */
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct xtsproxy_ctx),
		.cra_module			= THIS_MODULE,
	},
	.min_keysize	= 2 * AES_MIN_KEY_SIZE,
	.max_keysize	= 2 * AES_MAX_KEY_SIZE,
	.ivsize			= AES_BLOCK_SIZE,
	.init 			= xtsproxy_skcipher_init,
	.exit 			= xtsproxy_skcipher_exit,
	.setkey			= xtsproxy_setkey,
	.encrypt		= xtsproxy_encrypt,
	.decrypt		= xtsproxy_decrypt,
};

static int __init xtsproxy_init(void)
{
	return crypto_register_skcipher(&xtsproxy_skcipher);
}

static void __exit xtsproxy_fini(void)
{
	crypto_unregister_skcipher(&xtsproxy_skcipher);
}

module_init(xtsproxy_init);
module_exit(xtsproxy_fini);

MODULE_DESCRIPTION("XTS-AES using AESNI implementation with generic AES fallback");
MODULE_AUTHOR("Ignat Korchagin <ignat@cloudflare.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("xts(aes)");
