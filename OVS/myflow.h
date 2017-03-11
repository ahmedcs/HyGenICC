/*
 * HyGenICC - End-host Hypervisor (OpenvSwitch) based generic congestion control.
 *
 *  Author: Ahmed Mohamed Abdelmoniem Sayed, <ahmedcs982@gmail.com, github:ahmedcs>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of CRAPL LICENCE avaliable at
 *    http://matt.might.net/articles/crapl/.
 *    http://matt.might.net/articles/crapl/CRAPL-LICENSE.txt
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the CRAPL LICENSE for more details.
 *
 * Please READ carefully the attached README and LICENCE file with this software
 */

#ifndef MYFLOW_H
#define MYFLOW_H 1

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <net/pkt_sched.h>
#include <linux/openvswitch.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"


/******************************************ecn********************************************/
#define  FLOW_CLEAR_INTERVAL_MS 300
#define  ECN_FEEDBACK_INTERVAL_MS 1
//#define  EVIL_FEEDBACK_INTERVAL_US 200


struct track_table {
    /* xxx Need all these? */
    struct flex_array *buckets;
    unsigned int count, n_buckets;
    struct rcu_head rcu;
    int node_ver;
    u32 hash_seed;
    struct delayed_work work;
};

struct track_flow_key {
    __be32 src;	/* IP source address. */
    __be32 dst;	/* IP destination address. */
//    struct {
//		u32	priority;	/* Packet QoS priority. */
//		u32	skb_mark;	/* SKB mark. */
//		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
//	} __packed phy; /* Safe when right after 'tun_key'. */
//	//u32 ovs_flow_hash;		/* Datapath computed hash value.  */
//	struct {
//			u8     proto;	/* IP protocol or lower 8 bits of ARP opcode. */
//			//u8     tos;	    /* IP ToS. */
//			//u8     ttl;	    /* IP TTL/hop limit. */
//			//u8     frag;	/* One of OVS_FRAG_TYPE_*. */
//		} ip;
//    struct {
//        __be32 src;	/* IP source address. */
//        __be32 dst;	/* IP destination address. */
//        } addr;
//	 struct {
//		__be16 src;		/* TCP/UDP/SCTP source port. */
//		__be16 dst;		/* TCP/UDP/SCTP destination port. */
//		__be16 flags;		/* TCP flags. */
//	  } tp;
} __aligned(BITS_PER_LONG/8); /* Ensure that we can do comparisons as longs. */

struct track_flow {
	struct rcu_head rcu;
	struct hlist_node hash_node[2];
	u32 hash;

	struct track_flow_key key;

	//struct PacketQueue q; 	/* packet queue for traffic shaping*/

	spinlock_t lock;       /* Lock for values below. */
	unsigned long created; /* Time created (in jiffies). */
	unsigned long used;    /* Last used time (in jiffies). */
	unsigned long ecn_lastfeedback;    /* Last used time (in jiffies). */
	unsigned long evil_lastfeedback;    /* Last used time (in jiffies). */
    //t_ktime feedbacksent;    /* Last time feedback was sent (in nanosecond). */
	u64 in_packet_count;      /* Number of packets recieved. */
	u64 in_byte_count;        /* Number of bytes recieved. */	
	u64 ecn_packet_count;      /* Number of packets matched. */
	u64 ecn_byte_count;        /* Number of bytes matched. */

	u64 old_out_packet_count;      /* Number of packets sent. */
	u64 old_out_byte_count;        /* Number of bytes sent. */
        u64 out_packet_count;      /* Number of packets sent. */
	u64 out_byte_count;        /* Number of bytes sent. */
	u64 evil_packet_count;      /* Number of packets matched. */
	u64 evil_byte_count;        /* Number of bytes matched. */
	u16 evil_alpha;
    	u16 ecn_alpha;
	bool evil_cleared;
 	//u64 tokens;	/* Tokens in nanoseconds */
  	  //u32 capacity; 	/* Maximum value of bucket*/
   	 //u64	time_ns;	/* Time check-point */
    	// u64 fill_rate;	/* bytes per interval */
};



int ovs_track_tbl_need_to_expand(struct track_table *table);
/*struct hlist_head *find_bucket(struct track_table *table, u32 hash);
struct flex_array *alloc_buckets(unsigned int n_buckets);
void free_buckets(struct flex_array *buckets);*/
struct track_table *ovs_track_tbl_alloc(int new_size);
void ovs_track_tbl_destroy(struct track_table *table);
void track_tbl_destroy_rcu_cb(struct rcu_head *rcu);
void ovs_track_tbl_deferred_destroy(struct track_table *table);
struct track_flow *ovs_track_tbl_next(struct track_table *table, u32 *bucket, u32 *last);
void __track_tbl_insert(struct track_table *table, struct track_flow *flow);
void track_table_copy_flows(struct track_table *old, struct track_table *new);
struct track_table *__track_tbl_rehash(struct track_table *table, int n_buckets);
struct track_table *ovs_track_tbl_expand(struct track_table *table);
void ovs_track_free(struct track_flow *flow);
void rcu_free_track_flow_callback(struct rcu_head *rcu);
void ovs_track_flow_deferred_free(struct track_flow *flow);
u32 ovs_track_flow_hash(const struct track_flow_key *key, int key_start, int key_len);
/*int flow_key_start(struct sw_flow_key *key);*/

void track_check_table(struct work_struct *work);
void ovs_track_tbl_insert(struct track_table *table,struct track_flow *flow, struct track_flow_key *key, int key_len);
void ovs_track_tbl_remove(struct track_table *table,struct track_flow *flow);


struct track_flow *ovs_track_flow_alloc(void);
void clear_stats(struct track_flow *flow);
void init_flow(struct track_flow *flow);
void clear_queue(struct track_flow * flow);
void print_flow(struct track_flow *flow);
void ovs_track_print_flows(struct track_table *track_table);


bool byte_check(const struct track_flow *flow,uint32_t byte_count, uint32_t num_secs);
bool tso_check(const struct track_flow *flow,	uint32_t tso_size, uint32_t tso_count);


int ovs_track_dp_init(struct track_table *);
void ovs_track_dp_exit(struct track_table *);

struct track_table *ovs_track_tbl_alloc(int new_size);
void ovs_track_tbl_destroy(struct track_table *);

//Ahmed
u16 ovs_track_get_avg_alpha(__be32 src);
void init_tracking(void);
void stop_tracking(void);
void track_key_extract(struct sk_buff *skb, struct track_flow_key *key);
void track_reverse_key_extract(struct sk_buff *skb, struct track_flow_key *key);
struct track_flow *ovs_track_tbl_lookup(struct track_flow_key *key, int key_len);
void ovs_track_tbl_clear_and_queue(int virtdevcount);
void ovs_track_used(struct track_flow *flow, const struct sk_buff *skb,bool is_ecn, bool is_evil);
bool is_ecn(const struct sk_buff *skb, u8 tos);
bool is_evil(const struct sk_buff *, u16 fragoff);
struct track_flow * insert_flow( struct track_flow_key key);
void clear_table(void);
/******************************************ecn********************************************/

/*************************************Feedback***********************************/
/* This is what "br_dev_queue_push_xmit" would do */
static inline void skb_xmit(struct sk_buff *skb)
{
    skb_push(skb, ETH_HLEN);
    dev_queue_xmit(skb);
}

/* Create a feebdack packet and prepare for transmission.  Returns 1 if successful. */
static inline int generate_feedback(int ecnmarks, struct sk_buff *pkt)
{
    struct sk_buff *skb;
    struct ethhdr *eth_to, *eth_from;
    struct iphdr *iph_to, *iph_from;

    eth_from = eth_hdr(pkt);
    if(unlikely(eth_from->h_proto != __constant_htons(ETH_P_IP)))
        return 0;

    /* XXX: netdev_alloc_skb's meant to allocate packets for receiving.
     * Is it okay to use for transmitting?
     */
    skb = netdev_alloc_skb(pkt->dev, FEEDBACK_PACKET_SIZE);
    if(likely(skb))
    {
        skb_set_queue_mapping(skb, 0);
        skb->len = FEEDBACK_PACKET_SIZE;
        skb->protocol = __constant_htons(ETH_P_IP);
        skb->pkt_type = PACKET_OUTGOING;

        skb_reset_mac_header(skb);
        skb_set_tail_pointer(skb, FEEDBACK_PACKET_SIZE);
        eth_to = eth_hdr(skb);

        memcpy(eth_to->h_source, eth_from->h_dest, ETH_ALEN);
        memcpy(eth_to->h_dest, eth_from->h_source, ETH_ALEN);
        eth_to->h_proto =  __constant_htons(ETH_P_IP);//eth_from->h_proto;

        skb_pull(skb, ETH_HLEN);
        skb_reset_network_header(skb);
        iph_to = ip_hdr(skb);
        iph_from = ip_hdr(pkt);

        iph_to->ihl = 5;
        iph_to->version = 4;
        //iph_to->tos = 0x2 | (bit ? ECN_REFLECT_MASK : 0);
        iph_to->tot_len = __constant_htons(FEEDBACK_HEADER_SIZE);
        //Ahmed - set id and set TOS for ECN marking
        iph_to->tos = 0x2;
        iph_to->id = htons((u16)ecnmarks); // we will set the remaining marks in the IP ID feild
        iph_to->frag_off = 0;
        iph_to->ttl = FEEDBACK_PACKET_TTL;
        iph_to->protocol = (u8)FEEDBACK_PACKET_IPPROTO;
        iph_to->saddr = iph_from->daddr;
        iph_to->daddr = iph_from->saddr;

        /* NB: this function doesn't "send" the packet */
        ip_send_check(iph_to);

        /* Driver owns the buffer now; we don't need to free it */
        skb_xmit(skb);
        return 1;
    }

    return 0;
}
/*************************************Feedback***********************************/


#endif /* myflow.h */
