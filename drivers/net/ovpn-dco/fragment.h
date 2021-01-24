#ifndef _NET_OVPN_DCO_FRAGMENT_H_
#define _NET_OVPN_DCO_FRAGMENT_H_

#define MAX_FRAGS		32
#define MAX_SEQ			256

struct sk_buff;
struct sk_buff_head;
struct ovpn_peer;

struct ovpn_fragment {
	struct sk_buff *skb;
	unsigned long recv_time;
	int last_idx;
};

int ovpn_fragment_one(struct ovpn_peer *peer, struct sk_buff_head *head,
		      struct sk_buff *skb, size_t max_len);
int ovpn_defragment_one(struct ovpn_peer *peer, struct sk_buff *skb,
			struct sk_buff **out); 

void ovpn_defrag_queue_cleanup(struct ovpn_peer *peer);

#endif /* _NET_OVPN_DCO_FRAGMENT_H_ */
