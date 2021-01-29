#include "main.h"
#include "netlink.h"
#include "sock.h"
#include "proto.h"
#include "peer.h"
#include "skb.h"

#define N_SEQ_ID            256

#define FRAG_TYPE_MASK        0x00000003
/**< Bit mask for %fragment type info. */
#define FRAG_TYPE_SHIFT       0 /**< Bit shift for %fragment type info. */

#define FRAG_WHOLE            0 /**< Fragment type indicating packet is
                                 *   whole. */
#define FRAG_YES_NOTLAST      1 /**< Fragment type indicating packet is
                                 *   part of a fragmented packet, but not
                                 *   the last part in the sequence. */
#define FRAG_YES_LAST         2 /**< Fragment type indicating packet is
                                 *   the last part in the sequence of
                                 *   parts. */
#define FRAG_TEST             3 /**< Fragment type not implemented yet.
                                 *   In the future might be used as a
                                 *   control packet for establishing MTU
                                 *   size. */

#define FRAG_SEQ_ID_MASK      0x000000ff
/**< Bit mask for %fragment sequence ID. */
#define FRAG_SEQ_ID_SHIFT     2 /**< Bit shift for %fragment sequence ID. */

#define FRAG_ID_MASK          0x0000001f
/**< Bit mask for %fragment ID. */
#define FRAG_ID_SHIFT         10
/**< Bit shift for %fragment ID. */

/*
 * FRAG_SIZE  14 bits
 *
 * IF FRAG_YES_LAST (FRAG_SIZE):
 *   The max size of a %fragment.  If a %fragment is not the last %fragment in the packet,
 *   then the %fragment size is guaranteed to be equal to the max %fragment size.  Therefore,
 *   max_frag_size is only sent over the wire if FRAG_LAST is set.  Otherwise it is assumed
 *   to be the actual %fragment size received.
 */
#define FRAG_SIZE_MASK        0x00003fff
/**< Bit mask for %fragment size. */
#define FRAG_SIZE_SHIFT       15
/**< Bit shift for %fragment size. */
#define FRAG_SIZE_ROUND_SHIFT 2 /**< Bit shift for %fragment size rounding. */
#define FRAG_SIZE_ROUND_MASK ((1 << FRAG_SIZE_ROUND_SHIFT) - 1)
/**< Bit mask for %fragment size rounding. */

/*
 * FRAG_EXTRA 16 bits
 *
 * IF FRAG_WHOLE or FRAG_YES_NOTLAST, these 16 bits are available (not currently used)
 */
#define FRAG_EXTRA_MASK         0x0000ffff
/**< Bit mask for extra bits. */
#define FRAG_EXTRA_SHIFT        15
/**< Bit shift for extra bits. */

static inline int
ovpn_fragment_min_int(const int x, const int y)
{
	if (x < y)
		return x;

	return y;
}

static inline int
ovpn_fragment_modulo_add(const int x, const int y, const int mod)
{
	int sum = x + y;

	if (sum >= mod)
		sum -= mod;

	if (sum < 0)
		sum += mod;

	return sum;
}

static inline int
ovpn_fragment_optimal_fragment_size(const int len, const int max_frag_size)
{
	const int mfs_aligned = (max_frag_size & ~FRAG_SIZE_ROUND_MASK);
	const int div = len / mfs_aligned;
	const int mod = len % mfs_aligned;

	if (div > 0 && mod > 0 && mod < mfs_aligned * 3 / 4)
		return ovpn_fragment_min_int(mfs_aligned, (max_frag_size - ((max_frag_size - mod) / (div + 1))
				+ FRAG_SIZE_ROUND_MASK) & ~FRAG_SIZE_ROUND_MASK);

	return mfs_aligned;
}

static inline void
ovpn_fragment_prepend_flags(__be32 *out, const int type, const int seq_id,
			    const int frag_id, const int frag_size)
{
	uint32_t flags = ((type & FRAG_TYPE_MASK) << FRAG_TYPE_SHIFT)
			| ((seq_id & FRAG_SEQ_ID_MASK) << FRAG_SEQ_ID_SHIFT)
			| ((frag_id & FRAG_ID_MASK) << FRAG_ID_SHIFT);

	if (type == FRAG_YES_LAST)
		flags |= (((frag_size >> FRAG_SIZE_ROUND_SHIFT) & FRAG_SIZE_MASK)
			<< FRAG_SIZE_SHIFT);

	*out = cpu_to_be32(flags);
}

int ovpn_fragment_one(struct ovpn_peer *peer, struct sk_buff_head *head,
		      struct sk_buff *skb, size_t max_len)
{
	int ret = -1;
	struct sk_buff *trailer, *skb2;
	int frag_id = 0;
	int seq_id = 0;
	off_t skip = 0;
	int done = 0;
	struct scatterlist sg[MAX_SKB_FRAGS];
	int nfrags;
	const int frag_size = ovpn_fragment_optimal_fragment_size(
		skb->len, max_len);

	if (unlikely(skb_cow_head(skb, sizeof(uint32_t))))
		return -ENOBUFS;

	if (skb->len < max_len) {
		__skb_push(skb, sizeof(uint32_t));
		ovpn_fragment_prepend_flags(
			(__be32 *)skb->data, FRAG_WHOLE, 0, 0, 0);

		return 1;
	}

	if (unlikely(skb->len > frag_size * MAX_FRAGS)) {
		pr_err_ratelimited("%s: too many frags requested\n", __func__);

		return -E2BIG;
	}

	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0)) {
		pr_err_ratelimited("%s: cow error\n", __func__);

		return nfrags;
	}

	sg_init_table(sg, nfrags);
	ret = skb_to_sgvec_nomark(skb, sg, 0, skb->len);
	if (unlikely(nfrags != ret)) {
		pr_err_ratelimited("%s: sgvec error\n", __func__);

		return -EINVAL;
	}

	spin_lock(&peer->frag_tx);
	seq_id = peer->frag_tx_seq_id =
		ovpn_fragment_modulo_add(peer->frag_tx_seq_id, 1, N_SEQ_ID);
	spin_unlock(&peer->frag_tx);

	skip += frag_size;
	frag_id = 1;
	skb2 = skb;

	while (skb->len > skip) {
		struct sg_mapping_iter miter;
		const int to_copy = ovpn_fragment_min_int(skb->len - skip, frag_size);
		const bool last = (skb->len - skip <= frag_size);
		struct sk_buff *new = alloc_skb(OVPN_NEW_SIZE + to_copy, GFP_KERNEL);
		size_t offset = 0;

		if (unlikely(!new)) {
			pr_err_ratelimited(
				"%s: unable to alloc new fragment\n", __func__);

			return -ENOMEM;
		}

		skb_reserve(new, OVPN_NEW_HEADROOM);
		__skb_put(new, to_copy);

		ret = skb_linearize(new);
		if (ret < 0) {
			pr_err_ratelimited(
				"%s: unable to linearize new fragment\n", __func__);

			return ret;
		}

		sg_miter_start(&miter, sg, nfrags, SG_MITER_FROM_SG);

		if (!sg_miter_skip(&miter, skip)) {
			pr_err_ratelimited("%s: unable to skip data\n", __func__);

			return -1;
		}

		while (sg_miter_next(&miter) && offset < to_copy) {
			unsigned int len;

			len = min(miter.length, to_copy - offset);
			memcpy(new->data + offset, miter.addr, len);
			offset += len;
		}

		sg_miter_stop(&miter);

		skip += offset;
		done += to_copy;

		__skb_push(new, sizeof(uint32_t));

		ovpn_fragment_prepend_flags((__be32 *)new->data,
					    last ? FRAG_YES_LAST : FRAG_YES_NOTLAST,
					    seq_id,
					    frag_id++,
					    last ? frag_size : 0);

		__skb_queue_after(head, skb2, new);
		skb2 = new;
	}

	skb_trim(skb, skb->len - done);
	__skb_push(skb, sizeof(uint32_t));

	ovpn_fragment_prepend_flags((__be32 *)skb->data,
				     FRAG_YES_NOTLAST,
				     seq_id,
				     0,
				     0);

	return 1;
}

static inline
struct ovpn_fragment *ovpn_get_fragment(struct ovpn_peer *peer,
					size_t seq_id, size_t frag_id)
{
	return peer->frag_queue + seq_id * MAX_FRAGS + frag_id;
}

void ovpn_defrag_queue_cleanup(struct ovpn_peer *peer)
{
	size_t i, j;

	spin_lock(&peer->frag_rx);

	for (i = 0; i < MAX_SEQ; ++i) {
		for (j = 0; j < MAX_FRAGS; ++j) {
			struct ovpn_fragment *f = ovpn_get_fragment(peer, i, j);

			if (f->skb == NULL)
				continue;

			consume_skb(f->skb);
		}
	}

	spin_unlock(&peer->frag_rx);
}

int ovpn_defragment_one(struct ovpn_peer *peer, struct sk_buff *skb,
			struct sk_buff **out)
{
	struct sk_buff *curr, *next, *new;
	int ret;
	uint32_t _flags, flags;
	const __be32 *fp = skb_header_pointer(skb, 0, sizeof(flags), &_flags);
	int frag_type = 0;
	int seq_id = 0;
	int n = 0;
	int frag_len;
	bool completed = false;
	size_t newsize = 0;
	struct sk_buff_head skb_list;
	struct sk_buff_head skb_list_free;
	size_t i, j;
	struct ovpn_fragment *f;
	size_t offset = 0;

	flags = be32_to_cpup(fp);
	__skb_pull(skb, sizeof(uint32_t));
	frag_type = ((flags >> FRAG_TYPE_SHIFT) & FRAG_TYPE_MASK);

	if (frag_type == FRAG_WHOLE) {
		if (unlikely(flags & (FRAG_SEQ_ID_MASK | FRAG_ID_MASK))) {
			pr_err_ratelimited(
				"%s: spurrious FRAG_WHOLE flags\n", __func__);

			return -1;
		}

		*out = skb;

		return 0;
	}

	if (unlikely(frag_type == FRAG_TEST)) {
		pr_err_ratelimited("%s: FRAG_TEST not implemented\n", __func__);
		consume_skb(skb);

		return -1;
	}

	if (unlikely(
		!(frag_type == FRAG_YES_NOTLAST || frag_type == FRAG_YES_LAST))) {
		pr_err_ratelimited("%s: unknown fragment type\n", __func__);
		consume_skb(skb);

		return -1;
	}

	seq_id = ((flags >> FRAG_SEQ_ID_SHIFT) & FRAG_SEQ_ID_MASK);
	n = ((flags >> FRAG_ID_SHIFT) & FRAG_ID_MASK);
	frag_len = (int)(((flags >> FRAG_SIZE_SHIFT) & FRAG_SIZE_MASK) << FRAG_SIZE_ROUND_SHIFT);

//	pr_info_ratelimited("FRAG_IN buf->len=%d type=%s seq_id=%d frag_idx=%d\n", skb->len, frag_type == FRAG_YES_NOTLAST ? "FRAG_YES_NOTLAST" : "FRAG_YES_LAST", seq_id, n);

	if (unlikely(frag_type == FRAG_YES_LAST &&
		     skb->len + sizeof(uint32_t) != frag_len)) {
		pr_err_ratelimited("%s: unexpected len: %d (expected %d)\n",
			__func__, frag_len, skb->len + sizeof(uint32_t));
		consume_skb(skb);

		return -1;
	}

	spin_lock(&peer->frag_rx);

	f = ovpn_get_fragment(peer, seq_id, n);

	if (f->skb != NULL) {
		pr_warn_ratelimited("%s: fragment seq_id %d frag %d already exists, replace\n",
			__func__, seq_id, n);
		consume_skb(f->skb);
		memset(f, 0, sizeof(*f));
	} else {
//		pr_info_ratelimited("save fragment seq_id %d frag %d\n", seq_id, n);
	}

	f->skb = skb;
	f->recv_time = jiffies;

	if (frag_type == FRAG_YES_LAST)
		f->last_idx = n;

	__skb_queue_head_init(&skb_list);
	__skb_queue_head_init(&skb_list_free);

	for (i = 0; i < MAX_FRAGS; ++i) {
		struct ovpn_fragment *f = ovpn_get_fragment(peer, seq_id, i);

		if (f->skb == NULL)
			break;

		newsize += f->skb->len;

		__skb_queue_tail(&skb_list, f->skb);

		if (f->last_idx == i) {
			//pr_info_ratelimited("completed chain for seq_idx=%d, newsize=%u, idx=%u\n", seq_id, newsize, i);
			completed = true;
			break;
		}
	}

	if (completed) {
		unsigned long timeo = jiffies - msecs_to_jiffies(10000);
		memset(peer->frag_queue + seq_id * MAX_FRAGS, 0, sizeof(struct ovpn_fragment) * MAX_FRAGS);
		skb_list.prev->next = NULL;

		for (i = 0; i < MAX_SEQ; ++i) {
			bool timeouted = false;
			for (j = 0; j < MAX_FRAGS; ++j) {
				struct ovpn_fragment *f = ovpn_get_fragment(peer, i, j);

				if (f->skb == NULL)
					continue;

				if (time_after(timeo, f->recv_time)) {
					timeouted = true;
					pr_warn_ratelimited("%s: seq_id=%u frag=%u is timeouted, cleanup\n", __func__, i, j);

					break;
				}
			}

			if (!timeouted)
				continue;

			for (j = 0; j < MAX_FRAGS; ++j) {
				struct ovpn_fragment *f = ovpn_get_fragment(peer, i, j);

				if (f->skb == NULL)
					continue;

				__skb_queue_tail(&skb_list_free, f->skb);
			}

			memset(peer->frag_queue + i * MAX_FRAGS, 0, sizeof(struct ovpn_fragment) * MAX_FRAGS);
		}
	}

	spin_unlock(&peer->frag_rx);

	if (!completed) {
		*out = NULL;
		return 0;
	}

	skb_list_free.prev->next = NULL;

	skb_list_walk_safe(skb_list_free.next, curr, next) {
		skb_mark_not_on_list(curr);
		consume_skb(curr);
	}

	new = alloc_skb(OVPN_NEW_SIZE + newsize, GFP_KERNEL);

	if (unlikely(!new)) {
		pr_err_ratelimited("%s: unable to alloc defragmented packet\n", __func__);
		*out = NULL;

		return -ENOMEM;
	}

	skb_reserve(new, OVPN_NEW_HEADROOM);
	__skb_put(new, newsize);

	ret = skb_linearize(new);
	if (ret < 0) {
		pr_err_ratelimited("%s: unable to linearize defragmented packet\n", __func__);

		return ret;
	}

	skb_list_walk_safe(skb_list.next, curr, next) {
		struct scatterlist sg[MAX_SKB_FRAGS];
		struct sg_mapping_iter miter;
		struct sk_buff *trailer;
		int nfrags = 0;

		skb_mark_not_on_list(curr);

		nfrags = skb_cow_data(curr, 0, &trailer);
		if (unlikely(nfrags < 0)) {
			pr_err_ratelimited("%s: cow error\n", __func__);
			*out = NULL;
			return nfrags;
		}

		sg_init_table(sg, nfrags);
		ret = skb_to_sgvec_nomark(curr, sg, 0, curr->len);
		if (unlikely(nfrags != ret)) {
			pr_err_ratelimited("%s: sgvec error\n", __func__);
			*out = NULL;
			return -EINVAL;
		}

		sg_miter_start(&miter, sg, nfrags, SG_MITER_FROM_SG);

		while (sg_miter_next(&miter) && offset < newsize) {
			unsigned int len;

			len = min(miter.length, newsize - offset);
			memcpy(new->data + offset, miter.addr, len);
			offset += len;
		}

		sg_miter_stop(&miter);

		consume_skb(curr);
	}

	*out = new;

	return 0;
}
