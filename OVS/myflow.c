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

#include "datapath.h"

static struct track_table *mytrack_table;
static struct kmem_cache *track_table;

void init_tracking(void)
{
    track_table = kmem_cache_create("track_flow", sizeof(struct track_flow), 0, 0, NULL);
    if (track_table == NULL)
    {
        printk(KERN_INFO "OpenVswitch Init ecn cache Error");
        return -ENOMEM;
    }
    rcu_assign_pointer(mytrack_table,ovs_track_tbl_alloc(track_TBL_MIN_BUCKETS));
    if (mytrack_table == NULL)
    {
        ovs_track_dp_exit(mytrack_table);
        printk(KERN_INFO "OpenVswitch Init ecn Table allocation Error");
        return;

    }
    if(ovs_track_dp_init(mytrack_table))
    {
        ovs_track_tbl_destroy(mytrack_table);
        printk(KERN_INFO "OpenVswitch Init ecn Table db init Error");
        return;
    }
}

void stop_tracking(void)
{
    ovs_track_dp_exit(mytrack_table);
    ovs_track_tbl_destroy(mytrack_table);
    kmem_cache_destroy(track_table);
}

void clear_table(void)
{
    struct track_table *table;
    int i;

    table = mytrack_table;

    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        struct hlist_node *n;
        int ver = table->node_ver;

        hlist_for_each_entry_safe(flow, n, head, hash_node[ver])
        {           
                ovs_track_tbl_remove(table, flow);
                ovs_track_flow_deferred_free(flow);
        }
    }
}

void track_key_extract(struct sk_buff *skb, struct track_flow_key *key)
{
    int error;
    struct iphdr *nh;

    nh = (struct iphdr *)skb_network_header(skb);
    //key->ip.proto = nh->protocol;
    key->src = nh->saddr;
    key->dst = nh->daddr;
    //key->addr.dst = nh->daddr;

    /* Transport layer. */
    /*if (key->ip.proto == IPPROTO_TCP) {
    		struct tcphdr *tcp = tcp_hdr(skb);
    		key->tp.src = tcp->source;
    		key->tp.dst = tcp->dest;
    		key->tp.flags = TCP_FLAGS_BE16(tcp);
    	}*/

}

void track_reverse_key_extract(struct sk_buff *skb, struct track_flow_key *key)
{
    int error;
    struct iphdr *nh;

    nh = (struct iphdr *)skb_network_header(skb);
    //key->ip.proto = nh->protocol;
    key->src = nh->daddr;
    key->dst = nh->saddr;
    //key->addr.dst = nh->daddr;

    /* Transport layer. */
    /*if (key->ip.proto == IPPROTO_TCP) {
    		struct tcphdr *tcp = tcp_hdr(skb);
    		key->tp.src = tcp->source;
    		key->tp.dst = tcp->dest;
    		key->tp.flags = TCP_FLAGS_BE16(tcp);
    	}*/

}

struct track_flow * insert_flow(struct track_flow_key key)
{
    struct track_table *table;
    table = mytrack_table;
    struct track_flow *flow;
    /* Expand table, if necessary, to make room. */
    if (ovs_track_tbl_need_to_expand(table))
    {
        struct track_table *new_table;
        //printk("OpenVswitch: Expanding Table ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
        new_table = ovs_track_tbl_expand(table);
        if (!IS_ERR(new_table))
        {
            rcu_assign_pointer(track_table, new_table);
            ovs_track_tbl_deferred_destroy(table);
            table = track_table;
            //printk("OpenVswitch: Expansion Successful ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
        }
    }

    /* Allocate flow. */
    flow = ovs_track_flow_alloc();
    if (IS_ERR(flow))
    {
        printk("OpenVswitch: Flow was not cleated created ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
        return false;
    }
    init_flow(flow);

    /* Put flow in bucket. */
    ovs_track_tbl_insert(table, flow, &key, sizeof(key));

    return flow;
}


bool is_ecn(const struct sk_buff *skb, u8 tos)
{
    struct track_table *table;
    struct track_flow_key key; //=OVS_CB(skb)->pkt_key;
    const struct vport *p = OVS_CB(skb)->input_vport;
    struct track_flow_key track_key;
    struct track_flow *flow;

    track_reverse_key_extract(skb, &key);

    track_key = key;

    table = mytrack_table;
    flow = ovs_track_tbl_lookup(&track_key, sizeof(track_key));
    if (!flow)
    {
        /* Expand table, if necessary, to make room. */
        if (ovs_track_tbl_need_to_expand(table))
        {
            struct track_table *new_table;
            //printk("OpenVswitch: Expanding Table ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            new_table = ovs_track_tbl_expand(table);
            if (!IS_ERR(new_table))
            {
                rcu_assign_pointer(track_table, new_table);
                ovs_track_tbl_deferred_destroy(table);
                table = track_table;
                //printk("OpenVswitch: Expansion Successful ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            }
        }

        /* Allocate flow. */
        flow = ovs_track_flow_alloc();
        if (IS_ERR(flow))
	        {
            printk("OpenVswitch: Flow was not cleated created ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            return false;
        }
        init_flow(flow);

        /* Put flow in bucket. */
        ovs_track_tbl_insert(table, flow, &track_key, sizeof(track_key));
        //printk("OpenVswitch: Flow created ipv4(src=%#x,dst=%#x) packets:%lld, bytes:%lld, tso:%lld, created:%d, used:%d\n",ntohl(flow->key.src),		ntohl(flow->key.dst),		flow->packet_count, flow->byte_count, flow->tso_count, 		jiffies_to_msecs(jiffies -flow->created),		jiffies_to_msecs(jiffies - flow->used));
    }

    bool is_ecn_pkt = INET_ECN_is_ce(tos);
    if(flow)
    {
        flow->used = jiffies;
        flow->in_packet_count++;
        flow->in_byte_count += skb->len;
        if(is_ecn_pkt)
        {
            flow->ecn_packet_count++;
            flow->ecn_byte_count += skb->len;
            //printk(KERN_INFO "OpenVswitch [%pI4->%pI4]: ecn count %d, in count: %d and alpha : %d \n", &flow->key.src, &flow->key.dst, flow->ecn_packet_count, flow->in_packet_count, flow->ecn_alpha);
        }
        if((jiffies_to_msecs(jiffies - flow->ecn_lastfeedback) >= ECN_FEEDBACK_INTERVAL_MS && flow->ecn_packet_count > 1) || flow->ecn_packet_count > 10) // || (flow->ecn_alpha >= 256 && flow->ecn_packet_count >= 20))
        {
            int ret=generate_feedback(flow->ecn_packet_count,skb);
            if(!ret)
                printk(KERN_INFO "OpenVswitch [%pI4->%pI4]: failed to generate the feedback to the source\n", &flow->key.src, &flow->key.dst);
            else
            {
                //printk(KERN_INFO "OpenVswitch [%pI4->%pI4]: Sent the feedback to the source, ECN count %d, Total In: %d \n", &flow->key.src, &flow->key.dst, flow->ecn_packet_count, flow->in_packet_count);
				flow->ecn_lastfeedback=jiffies;
                flow->in_packet_count=MAX(0, flow->in_packet_count - flow->ecn_packet_count);
				flow->in_byte_count=MAX(0, flow->in_byte_count - flow->ecn_byte_count);
                flow->ecn_packet_count=0;
                flow->ecn_byte_count=0;
            }
        }

    }
    //printk("OpenVswitch: Returning from is_ecn: %d \n", is_track_pkt);
    return is_ecn_pkt;
}

bool is_evil(const struct sk_buff *skb, u16 fragoff)
{
    struct track_table *table;
    struct track_flow_key key; //=OVS_CB(skb)->pkt_key;
    const struct vport *p = OVS_CB(skb)->input_vport;
    struct track_flow_key track_key;
    struct track_flow *flow;

    track_reverse_key_extract(skb, &key);

    track_key = key;

    table = mytrack_table;
    flow = ovs_track_tbl_lookup(&track_key, sizeof(track_key));
    if (!flow)
    {
        /* Expand table, if necessary, to make room. */
        if (ovs_track_tbl_need_to_expand(table))
        {
            struct track_table *new_table;
            //printk("OpenVswitch: Expanding Table ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            new_table = ovs_track_tbl_expand(table);
            if (!IS_ERR(new_table))
            {
                rcu_assign_pointer(track_table, new_table);
                ovs_track_tbl_deferred_destroy(table);
                table = track_table;
                //printk("OpenVswitch: Expansion Successful ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            }
        }

        /* Allocate flow. */
        flow = ovs_track_flow_alloc();
        if (IS_ERR(flow))
        {
            printk("OpenVswitch: Flow was not cleated created ipv4(src=%#x,dst=%#x)\n",ntohl(key.src),ntohl(key.dst));
            return false;
        }
        init_flow(flow);

        /* Put flow in bucket. */
        ovs_track_tbl_insert(table, flow, &track_key, sizeof(track_key));
        //printk("OpenVswitch: Flow created ipv4(src=%#x,dst=%#x) packets:%lld, bytes:%lld, tso:%lld, created:%d, used:%d\n",ntohl(flow->key.src),		ntohl(flow->key.dst),		flow->packet_count, flow->byte_count, flow->tso_count, 		jiffies_to_msecs(jiffies -flow->created),		jiffies_to_msecs(jiffies - flow->used));
    }

    bool is_evil_pkt = ((fragoff & IP_CE) == IP_CE);

    if(flow)
    {
        if(is_evil_pkt)
        {
            flow->evil_packet_count++;
            flow->evil_byte_count += skb->len;
	        flow->evil_lastfeedback = jiffies;
            //printk(KERN_INFO "OpenVswitch [%pI4->%pI4]: evil count %d, out count: %d and alpha : %d \n", &flow->key.src, &flow->key.dst, flow->evil_packet_count, flow->out_packet_count, flow->evil_alpha);

        }
    }
    //printk("OpenVswitch: Returning from is_ecn: %d \n", is_track_pkt);
    return is_evil_pkt;
}

void ovs_track_used(struct track_flow *flow, const struct sk_buff *skb, bool is_ecn, bool is_evil)
{
    /* xxx Is the spin lock safe? */
    
    if(is_ecn)
    {
        flow->ecn_packet_count++;
        if(flow->in_packet_count <  flow->ecn_packet_count)
            flow->ecn_packet_count=0;
        flow->ecn_byte_count += skb->len;
        //printk("OpenVswitch: ECN flow updated old aplha: %d, ECN count: %d , in packet count: %d \n", flow->ecn_alpha, flow->ecn_packet_count, flow->in_packet_count);
    }
    if(is_evil)
    {
        //flow->used = jiffies;
        flow->evil_packet_count++;
        if(flow->out_packet_count <  flow->evil_packet_count)
            flow->evil_packet_count=0;
        flow->evil_byte_count += skb->len;
        // printk("OpenVswitch: EVIL flow updated old aplha: %d, evil count: %d , out packet count: %d \n", flow->evil_alpha, flow->evil_packet_count, flow->out_packet_count);
    }

}

u16 ovs_track_get_avg_alpha(__be32 src)
{
    struct track_table *table = mytrack_table;
    int i;
    u16 avg=0;
    int count=0;

    if(!table || table->count==0)
        return avg;

    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        int ver = table->node_ver;

        hlist_for_each_entry(flow, head, hash_node[ver])
        {
	    if(flow)
	    {
		if(flow->out_packet_count==0)
               		flow->out_packet_count=1;
		if(flow->out_packet_count >= flow->evil_packet_count && jiffies_to_msecs(jiffies - flow->evil_lastfeedback) <= (ECN_FEEDBACK_INTERVAL_MS<<2))
		{         	
            		flow->evil_alpha = MAX(0, flow->evil_alpha - (flow->evil_alpha >> g) + ((flow->evil_packet_count << (10-g)) / flow->out_packet_count));
			if(flow->evil_alpha > 1024)
                	flow->evil_alpha=1024;
			//flow->out_packet_count-=flow->evil_packet_count;
			//flow->evil_packet_count=0;
            		
		}
		else
		    flow->evil_alpha = MAX(0, flow->evil_alpha - (flow->evil_alpha >> g));
		 if(flow->evil_alpha>0 && flow->key.src == src )
		 {
		
		        avg+=flow->evil_alpha;
		        //flow->evil_alpha = MAX(0, flow->evil_alpha - (flow->evil_alpha>>5));
		        count++;
		        //printk("OpenVswitch: source src=%#x alpha: %d, avg: %d and count: %d \n",src , flow->alpha, avg, count);
		  }
	      }
        }
    }
    if(count>0 && avg>0)
    {
        avg=avg/count;
        //printk("OpenVswitch: source src=%#x  avg alpha: %d and count: %d \n",src, avg, count);
    }
    return avg;
}

/*u16 ovs_track_get_evil_count(__be32 src, __be32 dst)
{
    struct track_table *table = mytrack_table;
    int i;
    u16 avg=0;
    int count=0;

    if(!table || table->count==0)
        return avg;

    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        int ver = table->node_ver;

        hlist_for_each_entry(flow, head, hash_node[ver])
        {
	    if(flow && flow->key.src == src && flow->key.dst == dst)
		return flow->evil_packet_count;
        }
    }
    
}*/

void track_check_table(struct work_struct *ws)
{
    struct track_table *table;
    int i;

    table = container_of(ws, struct track_table, work.work);

    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        struct hlist_node *n;
        int ver = table->node_ver;

        hlist_for_each_entry_safe(flow, n, head, hash_node[ver])
        {
            if (time_after(jiffies, flow->used + track_FLOW_LIFE))
            {
                ovs_track_tbl_remove(table, flow);
                ovs_track_flow_deferred_free(flow);
            }
        }
    }

    schedule_delayed_work(&table->work, track_CHECK_INTERVAL);
}

void ovs_track_tbl_clear_and_queue(int virtdevcount)
{
    struct track_table *table = mytrack_table;
    int i;

    if(!table || table->count==0)
        return;
    ktime_t now_ktime=ktime_get();
    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        int ver = table->node_ver;

        hlist_for_each_entry(flow, head, hash_node[ver])
        {
            if(flow)
            {          

                    if(!flow->evil_cleared)
                    {
                        //spin_lock(&flow->lock);
                        flow->evil_packet_count = 0;
                        flow->evil_byte_count = 0;
                        flow->evil_cleared = true;
                        //spin_unlock(&flow->lock);
                    }
                    if(jiffies_to_msecs(jiffies - flow->used) >= FLOW_CLEAR_INTERVAL_MS) //(virtdevcount * FLOW_CLEAR_INTERVAL_MS))//interval/1000)
                    {

                        if(flow->evil_cleared)
                        {
                            //spin_lock(&flow->lock);
                            flow->old_out_packet_count = flow->out_packet_count;
                            flow->old_out_byte_count = flow->out_byte_count;
                            flow->out_byte_count = 0;
                            flow->out_packet_count = 0;
                            flow->evil_cleared = false;
                            //spin_unlock(&flow->lock);
                        }

                        clear_stats(flow);
                        /*if(jiffies_to_msecs(jiffies - flow->used) >= 2)
                        	flow->alpha = 0;*/
                    }
            }
        }
    }
}

void clear_queue(struct track_flow * flow)
{
    //u64 now= ktime_to_ns(ktime_get());
    //flow->tokens = MIN(flow->capacity, flow->tokens + flow->fill_rate);
    //printk(KERN_INFO "OpenvSwitch: filling the token %d and max capacity is %d \n",flow->tokens, flow->capacity);
    //flow->time_ns = now;
    /* struct sk_buff *skb;
    int num=0;
    if(!(&flow->q) || (&flow->q)->size==0)
    {
        printk(KERN_INFO "OpenvSwitch: Can not clear Queue is not properly set or is empty \n");
        return;
    }
    while(1)
    {
        skb = Peek_PacketQueue(&flow->q);
        if(skb && flow->tokens >= skb->len && num < 8 )
        {
            //There are still some packets in queue
            //Dequeue packets
            flow->tokens = MAX(0, flow->tokens - skb->len);
            num++;
            int res=Dequeue_PacketQueue(&flow->q);
            if (res==0)
            {
                printk(KERN_INFO "OpenvSwitch: Something went wrong in dequeue \n");
                return;
            }

        }
        else
        {
            //There is no packet in queue
            break;
        }
    }*/
}

void clear_stats(struct track_flow *flow)
{
    flow->created = jiffies;
    flow->used = 0;
    flow->in_packet_count = 0;
    flow->in_byte_count = 0;
    flow->ecn_packet_count = 0;
    flow->ecn_byte_count = 0;
}

void init_flow(struct track_flow *flow)
{
    flow->ecn_alpha = 0;
    flow->evil_alpha = 0;
    flow->evil_cleared = true;
    flow->out_packet_count = 0;
    flow->out_byte_count = 0;
    flow->old_out_packet_count = 0;
    flow->old_out_byte_count = 0;
    flow->evil_packet_count = 0;
    flow->evil_byte_count = 0;
    clear_stats(flow);


}

/**************Ahmed**********************/


int ovs_track_tbl_need_to_expand(struct track_table *table)
{
    return (table->count > table->n_buckets);
}

static struct hlist_head *find_bucket(struct track_table *table, u32 hash)
{
    hash = jhash_1word(hash, table->hash_seed);
    return flex_array_get(table->buckets, (hash & (table->n_buckets - 1)));
}

static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
    struct flex_array *buckets;
    int i, err;

    buckets = flex_array_alloc(sizeof(struct hlist_head *),n_buckets, GFP_ATOMIC);
    if (!buckets)
        return NULL;

    err = flex_array_prealloc(buckets, 0, n_buckets, GFP_ATOMIC);
    if (err)
    {
        flex_array_free(buckets);
        return NULL;
    }

    for (i = 0; i < n_buckets; i++)
        INIT_HLIST_HEAD((struct hlist_head *)flex_array_get(buckets, i));

    return buckets;
}

static void free_buckets(struct flex_array *buckets)
{
    flex_array_free(buckets);
}

struct track_table *ovs_track_tbl_alloc(int new_size)
{
    struct track_table *table = kmalloc(sizeof(*table), GFP_ATOMIC);

    if (!table)
        return NULL;

    table->buckets = alloc_buckets(new_size);

    if (!table->buckets)
    {
        kfree(table);
        return NULL;
    }
    table->n_buckets = new_size;
    table->count = 0;
    table->node_ver = 0;
    get_random_bytes(&table->hash_seed, sizeof(u32));

    return table;
}

void ovs_track_tbl_destroy(struct track_table *table)
{
    int i;

    if (!table)
        return;

    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        struct hlist_node *n;
        int ver = table->node_ver;

        hlist_for_each_entry_safe(flow, n, head, hash_node[ver])
        {
            hlist_del_rcu(&flow->hash_node[ver]);
            ovs_track_free(flow);
        }
    }

    free_buckets(table->buckets);
    kfree(table);
}

void track_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
    struct track_table *table = container_of(rcu, struct track_table, rcu);

    ovs_track_tbl_destroy(table);
}

void ovs_track_tbl_deferred_destroy(struct track_table *table)
{
    if (!table)
        return;

    call_rcu(&table->rcu, track_tbl_destroy_rcu_cb);
}

struct track_flow *ovs_track_tbl_next(struct track_table *table, u32 *bucket, u32 *last)
{
    struct track_flow *flow;
    struct hlist_head *head;
    int ver;
    int i;

    ver = table->node_ver;
    while (*bucket < table->n_buckets)
    {
        i = 0;
        head = flex_array_get(table->buckets, *bucket);
        hlist_for_each_entry_rcu(flow, head, hash_node[ver])
        {
            if (i < *last)
            {
                i++;
                continue;
            }
            *last = i + 1;
            return flow;
        }
        (*bucket)++;
        *last = 0;
    }

    return NULL;
}

void __track_tbl_insert(struct track_table *table, struct track_flow *flow)
{
    struct hlist_head *head;
    head = find_bucket(table, flow->hash);
    hlist_add_head_rcu(&flow->hash_node[table->node_ver], head);
    table->count++;
}

void track_table_copy_flows(struct track_table *old, struct track_table *new)
{
    int old_ver;
    int i;

    old_ver = old->node_ver;
    new->node_ver = !old_ver;

    /* Insert in new table. */
    for (i = 0; i < old->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head;

        head = flex_array_get(old->buckets, i);

        hlist_for_each_entry(flow, head, hash_node[old_ver])
        __track_tbl_insert(new, flow);
    }
}

struct track_table *__track_tbl_rehash(struct track_table *table, int n_buckets)
{
    struct track_table *new_table;

    new_table = ovs_track_tbl_alloc(n_buckets);
    if (!new_table)
        return ERR_PTR(-ENOMEM);

    track_table_copy_flows(table, new_table);

    return new_table;
}

struct track_table *ovs_track_tbl_rehash(struct track_table *table)
{
    return __track_tbl_rehash(table, table->n_buckets);
}

struct track_table *ovs_track_tbl_expand(struct track_table *table)
{
    return __track_tbl_rehash(table, table->n_buckets * 2);
}

void ovs_track_free(struct track_flow *flow)
{
    if (unlikely(!flow))
        return;

    kmem_cache_free(track_table, flow);
}

/* RCU callback used by ovs_track_flow_deferred_free. */
void rcu_free_track_flow_callback(struct rcu_head *rcu)
{
    struct track_flow *flow = container_of(rcu, struct track_flow, rcu);

    ovs_track_free(flow);
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void ovs_track_flow_deferred_free(struct track_flow *flow)
{
    /* xxx Still need this? */
    call_rcu(&flow->rcu, rcu_free_track_flow_callback);
}

u32 ovs_track_flow_hash(const struct track_flow_key *key, int key_start, int key_len)
{
    return jhash2((u32 *)((u8 *)key + key_start),
                  DIV_ROUND_UP(key_len - key_start, sizeof(u32)), 0);
}

static int flow_key_start(struct track_flow_key *key)
{
    //return offsetof(struct track_flow_key, phy);
    return offsetof(struct track_flow_key, src);
}

struct track_flow *ovs_track_tbl_lookup(struct track_flow_key *key, int key_len)
{
    struct track_table *table;
    struct track_flow *flow;
    struct hlist_head *head;
    u8 *_key;
    int key_start;
    u32 hash;
    table = mytrack_table;
    key_start = flow_key_start(key);
    hash = ovs_track_flow_hash(key, key_start, key_len);

    _key = (u8 *) key + key_start;
    head = find_bucket(table, hash);
    hlist_for_each_entry_rcu(flow, head, hash_node[table->node_ver])
    {
        if (flow->hash == hash &&
                !memcmp((u8 *)&flow->key + key_start, _key, key_len - key_start))
        {
            return flow;
        }
    }
    return NULL;
}

void ovs_track_tbl_insert(struct track_table *table,struct track_flow *flow, struct track_flow_key *key, int key_len)
{
    flow->hash = ovs_track_flow_hash(key, flow_key_start(key), key_len);
    memcpy(&flow->key, key, sizeof(flow->key));
    __track_tbl_insert(table, flow);
}

void ovs_track_tbl_remove(struct track_table *table,struct track_flow *flow)
{
    hlist_del_rcu(&flow->hash_node[table->node_ver]);
    table->count--;
    BUG_ON(table->count < 0);
}



int ovs_track_dp_init(struct track_table *track_table)
{
    INIT_DELAYED_WORK(&track_table->work, track_check_table);
    schedule_delayed_work(&track_table->work, track_CHECK_INTERVAL);

    return 0;
}

void ovs_track_dp_exit(struct track_table *track_table)
{
    cancel_delayed_work_sync(&track_table->work);
}

struct track_flow *ovs_track_flow_alloc(void)
{
    struct track_flow *flow;

    flow = kmem_cache_alloc(track_table, GFP_ATOMIC);
    if (!flow)
        return ERR_PTR(-ENOMEM);

    spin_lock_init(&flow->lock);

    return flow;
}

void print_flow(struct track_flow *flow)
{
    /* xxx Only supports non-tunneled IPv4! */
    /*printk("in_port(%d),ipv4(src=%#x,dst=%#x,proto=%d),tp(src=%d,dst=%d),"
    	" packets:%lld, bytes:%lld, tso:%lld, created:%d, used:%d\n",
    	flow->key.phy.in_port, ntohl(flow->key.addr.src),
    	ntohl(flow->key.addr.dst),
    	flow->key.ip.proto, ntohs(flow->key.tp.src),
    	ntohs(flow->key.tp.dst),
    	flow->packet_count, flow->byte_count, flow->tso_count,
    	jiffies_to_msecs(jiffies - flow->created),
    	jiffies_to_msecs(jiffies - flow->used));*/
}

void ovs_track_print_flows(struct track_table *track_table)
{
    struct track_table *table = track_table;
    int i;

    printk("--- ecn Flows ---\n");
    for (i = 0; i < table->n_buckets; i++)
    {
        struct track_flow *flow;
        struct hlist_head *head = flex_array_get(table->buckets, i);
        int ver = table->node_ver;

        hlist_for_each_entry(flow, head, hash_node[ver])
        {
            print_flow(flow);
        }
    }
}


bool byte_check(const struct track_flow *flow,uint32_t byte_count, uint32_t num_secs)

{
    if ((flow->in_byte_count >= byte_count) &&
            time_after(jiffies, flow->created + HZ * num_secs))
    {
        return true;
    }
    else
        return false;
}

/*bool tso_check(const struct track_flow *flow,	uint32_t tso_size, uint32_t tso_count)

{
    if (flow->tso_count >= tso_count)
    {
        return true;
    }
    else
        return false;
}*/


