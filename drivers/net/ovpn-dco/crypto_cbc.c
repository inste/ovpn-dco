// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel accelerator
 *
 *  Copyright (C) 2020 Ilya Ponetaev.
 *
 *  Author:	Ilya Ponetaev
 */

#include "crypto_cbc.h"
#include "crypto.h"
#include "pktid.h"
#include "proto.h"
#include "skb.h"
#include "ovpn.h"

#include <crypto/authenc.h>
#include <crypto/aead.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <linux/skbuff.h>
#include <linux/printk.h>

static inline void crypto_inc_byte_(u8 *a, unsigned int size)
{
	u8 *b = (a + size);
	u8 c;

	for (; size; size--) {
		c = *--b + 1;
		*b = c;
		if (c)
			break;
	}
}

static inline void crypto_inc_(u8 *a, unsigned int size)
{
	__be32 *b = (__be32 *)(a + size);
	u32 c;

	if (IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) ||
	    IS_ALIGNED((unsigned long)b, __alignof__(*b)))
		for (; size >= 4; size -= 4) {
			c = be32_to_cpu(*--b) + 1;
			*b = cpu_to_be32(c);
			if (likely(c))
				return;
		}

	crypto_inc_byte_(a, size);
}

const struct ovpn_crypto_ops ovpn_cbc_ops;

static int ovpn_cbc_encap_overhead(const struct ovpn_crypto_key_slot *ks, enum ovpn_data_format data_format)
{
	return  (data_format == OVPN_P_DATA_V2 ? OVPN_OP_SIZE_V2 : OVPN_OP_SIZE_V1) +			/* OP header size */
		crypto_aead_authsize(ks->encrypt) +	/* hmac len */
		crypto_aead_ivsize(ks->encrypt) + /* IV size */
		sizeof(uint32_t); /* Packet ID */
}

static inline unsigned int ovpn_cbc_min(const unsigned int a,
					const unsigned int b)
{
	return a > b ? b : a;
}

static inline int ovpn_cbc_min_s(const int a, const int b)
{
	return a > b ? b : a;
}

static void ovpn_cbc_encrypt_done(struct crypto_async_request *req, int error)
{
	struct sk_buff *skb = req->data;

	if (likely(error >= 0))
		ovpn_send_out(skb);

	ovpn_crypto_key_slot_put(OVPN_SKB_CB(skb)->ks);
	kfree(OVPN_SKB_CB(skb)->sg);
	kfree(req);
}

static int ovpn_cbc_encrypt(struct ovpn_crypto_key_slot *ks,
			     struct sk_buff *skb, enum ovpn_data_format data_format)
{
	const unsigned int block_size = crypto_aead_blocksize(ks->encrypt);
	const unsigned int iv_size = crypto_aead_ivsize(ks->encrypt);
	const unsigned int tag_size = crypto_aead_authsize(ks->encrypt);
	unsigned int crypt_size = skb->len + sizeof(uint32_t);
	struct scatterlist *sg;
	//u8 iv[MAX_AUTHENC_IV_SIZE];
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	struct sk_buff *trailer;
	int nfrags, ret;
	u32 pktid, op;
	u8 op8;
	u8 *tail;
	u8 *iv;
	unsigned int i;
	const u8 opcode_size =
		(data_format == OVPN_P_DATA_V1 ? OVPN_OP_SIZE_V1 : OVPN_OP_SIZE_V2);
	unsigned int tailroom = ALIGN(skb->len + sizeof(uint32_t), block_size) -
		(skb->len + sizeof(uint32_t));

	if (tailroom == 0)
		tailroom += block_size;

	crypt_size += tailroom;

	/* Sample CBC header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275ab abcdef10 aabb...
	 * [ OP32 ] [ HMAC          ] [ - IV -                          ] [ *ID* ] [ * packet payload * ]
	 */

	sg = kmalloc((MAX_SKB_FRAGS + 1) * sizeof(struct scatterlist) + iv_size, GFP_KERNEL);

	if (unlikely(sg == NULL))
		return -ENOMEM;

	iv = (u8 *)sg + (MAX_SKB_FRAGS + 1) * sizeof(struct scatterlist);

	/* check that there's enough headroom in the skb for packet
	 * encapsulation, after adding network header and encryption overhead
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM +
			ovpn_cbc_encap_overhead(ks, data_format))))
		return -ENOBUFS;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, tailroom, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags > MAX_SKB_FRAGS))
		return -ENOSPC;

	req = aead_request_alloc(ks->encrypt, GFP_KERNEL);
	if (unlikely(!req))
		return -ENOMEM;

	/* sg table:
	 * 0, 1, 2, 3, ..., n: iv + ID + payload,
	 * n + 1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 1);

	/* obtain packet ID */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0)) {
		if (ret != -1)
			return ret;
	}

	/* append ID onto data buffer */
	__skb_push(skb, sizeof(uint32_t));
	ovpn_pktid_chm_write(pktid, skb->data);

	/* do pad for CBC */
	tail = skb_tail_pointer(trailer);
	memset(tail, tailroom, tailroom);
	pskb_put(skb, trailer, tailroom);

	/* echainiv */
	i = iv_size;

	do {
		u64 a;

		memcpy(&a, ks->xmit_iv_salt + i - 8, 8);

		a |= 1;
		a *= pktid;

		memcpy(iv + i - 8, &a, 8);
	} while ((i -= 8));

	/* prepend IV onto scatterlist */
	/* as AEAD Additional data */

	__skb_push(skb, iv_size);
	memcpy(skb->data, iv, iv_size);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(nfrags != ret)) {
		ret = -EINVAL;
		goto free_req;
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, tag_size);
	sg_set_buf(sg + nfrags, skb->data, tag_size);

	/* add packet op as head of additional data */
	if (data_format == OVPN_P_DATA_V2) {
		op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, ks->remote_peer_id);
		__skb_push(skb, opcode_size);
		BUILD_BUG_ON(sizeof(op) != OVPN_OP_SIZE_V2);
		*((__force __be32 *)skb->data) = htonl(op);
	} else {
		op8 = ovpn_opcode_compose_v1(OVPN_DATA_V1, ks->key_id);
		__skb_push(skb, opcode_size);
		BUILD_BUG_ON(sizeof(op8) != OVPN_OP_SIZE_V1);
		*((u8 *)skb->data) = op8;
	}

	OVPN_SKB_CB(skb)->sg = sg;

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  ovpn_cbc_encrypt_done, skb);
	aead_request_set_crypt(req, sg, sg, crypt_size, iv);
	aead_request_set_ad(req, iv_size);

	ret = crypto_aead_encrypt(req);

	pr_info_ratelimited("enq ret %d\n", ret);

	switch (ret) {
	case -EINPROGRESS:
		pr_info_ratelimited("scheduled\n");
		return ret;

	case 0:
		ovpn_crypto_key_slot_put(OVPN_SKB_CB(skb)->ks);
		ovpn_send_out(skb);
		break;

	case -EBUSY:
	default:
		ovpn_crypto_key_slot_put(OVPN_SKB_CB(skb)->ks);
		ovpn_peer_put(OVPN_SKB_CB(skb)->peer);
		consume_skb(skb);

		break;
	}

free_req:
	kfree(sg);
	aead_request_free(req);
	return ret;
}

static void hexdump(const char* pfx, const unsigned char *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, pfx, DUMP_PREFIX_OFFSET,
			16, 1,
			buf, len, false);
}

static int ovpn_cbc_decrypt(struct ovpn_crypto_key_slot *ks, struct sk_buff *skb)
{
	const unsigned int iv_size = crypto_aead_ivsize(ks->decrypt);
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	const unsigned int block_size = crypto_aead_blocksize(ks->decrypt);
	struct scatterlist sg[MAX_SKB_FRAGS + 1];
	int ret, payload_len, nfrags;
	unsigned int payload_offset;
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	struct sk_buff *trailer;
	__be32 *pid;
	const u8 opcode = ovpn_opcode_from_skb(skb, 0);
	const u8 opcode_size = (opcode == OVPN_DATA_V2 ? OVPN_OP_SIZE_V2 : OVPN_OP_SIZE_V1);

	payload_offset = opcode_size + tag_size + iv_size;
	payload_len = skb->len - payload_offset;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < sizeof(uint32_t)))
		return -EINVAL;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg list.
	 */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags + 1 > ARRAY_SIZE(sg)))
		return -ENOSPC;

	req = aead_request_alloc(ks->decrypt, GFP_KERNEL);
	if (unlikely(!req))
		return -ENOMEM;

	/* sg table:
	 * 0, 1, 2, 3, ..., n: IV (AD, len=iv_size) + ID + payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 1);

	/* packet IV is head of additional data */
	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg, payload_offset - iv_size,
				  payload_len + iv_size);
	if (unlikely(nfrags != ret)) {
		ret = -EINVAL;
		goto free_req;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + nfrags, skb->data + opcode_size, tag_size);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size,
			       skb->data + opcode_size + tag_size);

	aead_request_set_ad(req, iv_size);

	/* decrypt it */
	ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (ret < 0) {
		pr_err_ratelimited("%s: decrypt failed: %d\n", __func__, ret);
		goto free_req;
	}

	if (skb->len < block_size) {
		pr_err_ratelimited("%s: invalid packet size\n", __func__);
		goto free_req;
	}

	ret = skb_linearize(skb);
	if (ret < 0) {
		pr_err_ratelimited("%s: unable to linearize padded skb\n", __func__);

		goto free_req;
	}

	do {
		u8 _block[MAX_AUTHENC_IV_SIZE];
		u8 pv, *p = skb_header_pointer(skb,
					       skb->len - block_size,
					       block_size, &_block);
		int i = 0;

		if (p == NULL) {
			pr_err_ratelimited("%s: pad handling failed\n", __func__);
			goto free_req;
		}

		pv = p[block_size - 1];

		if (pv == 0 || pv > block_size) {
			pr_err_ratelimited("%s: invalid padding\n", __func__);
			goto free_req;
		}

		for (i = block_size - 1; i > block_size - 1 - pv; --i) {
			if (p[i] != pv) {
				pr_err_ratelimited("%s: invalid padding value\n", __func__);
				goto free_req;
			}
		}

		skb_trim(skb, skb->len - pv);

	} while(0);

	__skb_pull(skb, payload_offset);

	/* PID sits right at payload offset */
	pid = (__force __be32 *)(skb->data);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0))
		goto free_req;

	/* point to encapsulated IP packet */
	__skb_pull(skb, sizeof(uint32_t));

free_req:
	aead_request_free(req);
	return ret;
}

/* Initialize a struct crypto_cbc object */
static struct crypto_aead *ovpn_cbc_init(const char *title,
					  const char *alg_name,
					  const unsigned char *enc_key,
					  unsigned int enc_keylen,
					  const char *hmac_name,
					  const unsigned char *hmac_key,
					  unsigned int hmac_len,
					  unsigned int auth_size)
{
	struct crypto_aead *aead;
	int ret;
	struct rtattr *rta;
	char *key;
	char *p;
	unsigned int keylen;
	struct crypto_authenc_key_param *param;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	keylen = (hmac_name ? hmac_len : 0) +
		 enc_keylen + RTA_SPACE(sizeof(*param));
	ret = -ENOMEM;
	key = kmalloc(keylen, GFP_KERNEL);
	if (!key) {
		pr_err("%s kmalloc failed\n", title);
		goto error;
	}

	p = key;
	rta = (void *)p;
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	rta->rta_len = RTA_LENGTH(sizeof(*param));
	param = RTA_DATA(rta);
	p += RTA_SPACE(sizeof(*param));

	if (hmac_name) {
		memcpy(p, hmac_key, hmac_len);
		p += hmac_len;

		ret = crypto_aead_setauthsize(aead, auth_size);
		if (ret) {
			pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
			       ret);
			goto free_key;
		}
	}

	param->enckeylen = cpu_to_be32(enc_keylen);
	memcpy(p, enc_key, enc_keylen);

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title,
		       keylen, ret);
		goto free_key;
	}

	kfree(key);

	pr_info("********* Cipher %s%s%s (%s)\n", alg_name, hmac_name == NULL ? "" : " / ", hmac_name, title);
	pr_info("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_info("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_info("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_info("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_info("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

free_key:
	kfree(key);
error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

static void ovpn_cbc_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return;

	crypto_free_aead(ks->encrypt);
	crypto_free_aead(ks->decrypt);
	kfree(ks);
}

static struct ovpn_crypto_key_slot *
ovpn_cbc_crypto_key_slot_init(enum ovpn_cipher_alg alg,
			       enum ovpn_hmac_alg hmac_alg,
			       const unsigned char *encrypt_key,
			       unsigned int encrypt_keylen,
			       const unsigned char *decrypt_key,
			       unsigned int decrypt_keylen,
			       const unsigned char *encrypt_hmac_key,
			       unsigned int encrypt_hmac_key_len,
			       const unsigned char *decrypt_hmac_key,
			       unsigned int decrypt_hmac_key_len,
			       u16 key_id)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *calg_name = NULL;
	const char *halg_name = NULL;
	unsigned int auth_size = 0;
	char authenc_name[CRYPTO_MAX_ALG_NAME];
	int ret;

	/* validate crypto alg */
	switch (alg) {
	case OVPN_CIPHER_ALG_AES_CBC:
		calg_name = "cbc(aes)";
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	switch (hmac_alg) {
	case OVPN_HMAC_ALG_MD5:
		halg_name = "hmac(md5)";
		auth_size = MD5_DIGEST_SIZE;
		break;
	case OVPN_HMAC_ALG_SHA1:
		halg_name = "hmac(sha1)";
		auth_size = SHA1_DIGEST_SIZE;
		break;
	case OVPN_HMAC_ALG_SHA256:
		halg_name = "hmac(sha256)";
		auth_size = SHA256_DIGEST_SIZE;
		break;
	case OVPN_HMAC_ALG_SHA512:
		halg_name = "hmac(sha512)";
		auth_size = SHA512_DIGEST_SIZE;
		break;
	case OVPN_HMAC_ALG_NONE:
		halg_name = NULL;
		auth_size = 0;
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
		     "authenc(%s,%s)",
		     halg_name ? halg_name : "digest_null",
		     calg_name) >= CRYPTO_MAX_ALG_NAME)
		return ERR_PTR(-ENOMEM);

	/* build the key slot */
	ks = kmalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->alg = alg;
	ks->hmac_alg = hmac_alg;
	ks->ops = &ovpn_cbc_ops;
	ks->encrypt = NULL;
	ks->decrypt = NULL;
	kref_init(&ks->refcount);
	ks->key_id = key_id;

	ks->encrypt = ovpn_cbc_init("encrypt", authenc_name, encrypt_key,
				    encrypt_keylen, halg_name,
				    encrypt_hmac_key, encrypt_hmac_key_len,
				    auth_size);
	if (IS_ERR(ks->encrypt)) {
		ret = PTR_ERR(ks->encrypt);
		ks->encrypt = NULL;
		goto destroy_ks;
	}

	ks->decrypt = ovpn_cbc_init("decrypt", authenc_name, decrypt_key,
				    decrypt_keylen, halg_name,
				    decrypt_hmac_key, decrypt_hmac_key_len,
				    auth_size);
	if (IS_ERR(ks->decrypt)) {
		ret = PTR_ERR(ks->decrypt);
		ks->decrypt = NULL;
		goto destroy_ks;
	}

	get_random_bytes(&ks->xmit_iv_salt, MAX_AUTHENC_IV_SIZE);

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_cbc_crypto_key_slot_destroy(ks);
	return ERR_PTR(ret);
}

static struct ovpn_crypto_key_slot *
ovpn_cbc_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	return ovpn_cbc_crypto_key_slot_init(kc->cipher_alg,
					     kc->hmac_alg,
					     kc->encrypt.cipher_key,
					     kc->encrypt.cipher_key_size,
					     kc->decrypt.cipher_key,
					     kc->decrypt.cipher_key_size,
					     kc->encrypt.hmac_key,
					     kc->encrypt.hmac_key_size,
					     kc->decrypt.hmac_key,
					     kc->decrypt.hmac_key_size,
					     kc->key_id);
}

const struct ovpn_crypto_ops ovpn_cbc_ops = {
	.encrypt     = ovpn_cbc_encrypt,
	.decrypt     = ovpn_cbc_decrypt,
	.new         = ovpn_cbc_crypto_key_slot_new,
	.destroy     = ovpn_cbc_crypto_key_slot_destroy,
	.encap_overhead = ovpn_cbc_encap_overhead,
};
