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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "datapath.h"

#define DEPTH 100 //Bucket depth worth of 25 * 20 1514-bytes segments
//#define FILL_INTERVAL_US 244 //Time to transmit 20 1514-bytes segments
#define FILL_INTERVAL_US 250 
#define TCPBURST 2 // By how much to increase tokens allocation for TCP traffic (right shift)

//#define bucketmbytes (X * FILL_INTERVAL_US)

#define EVIL_DEV_MAX 50
#define SECTOUS 1E6L
#define SECTONS 1E9L

#define MIN_RATE 10
#define MIN_BUCKET 1514

/**********************feedback variables************************/
// We are assuming that we don't need to do any VLAN tag
const int FEEDBACK_INTERVAL_US= 1000;
const int FEEDBACK_INTERVAL_MARKS = 10;

// TODO: We are assuming that we don't need to do any VLAN tag
// ourselves
const int FEEDBACK_PACKET_SIZE = 64;
const u16 FEEDBACK_HEADER_SIZE = 20;
const u8 FEEDBACK_PACKET_TTL = 64;
const int FEEDBACK_PACKET_IPPROTO = 143; // should be some unused protocol
/**********************feedback variables************************/

//static spinlock_t globalLock;
static struct hrtimer evil_hrtimer;
static ktime_t evil_ktime;
static ktime_t lastupdate_ktime;
static bool evil_timerrun=false;
static bool evil_fail=false;

static unsigned short depth=DEPTH;
static unsigned short fill_us=FILL_INTERVAL_US;
static unsigned short tcpburst=TCPBURST;

static unsigned short devcount=0;
static unsigned short virtdevcount=0;
static unsigned short ethdevcount=0;

static unsigned int virtdevindex[EVIL_DEV_MAX];
static __be32 virtipaddress[EVIL_DEV_MAX];
static u16 virtavgalpha[EVIL_DEV_MAX];

static unsigned int ethdevindex[EVIL_DEV_MAX];
static unsigned int ethdevconn[EVIL_DEV_MAX];

static unsigned int virt_tokens[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_tcptokens[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_unused_tokens[EVIL_DEV_MAX * EVIL_DEV_MAX] ;
static unsigned int virt_bucket[EVIL_DEV_MAX * EVIL_DEV_MAX];
static int virt_rate[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_initrate[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_sent[EVIL_DEV_MAX * EVIL_DEV_MAX];
static bool virt_isactive[EVIL_DEV_MAX * EVIL_DEV_MAX];
static ktime_t virt_lastupdate[EVIL_DEV_MAX * EVIL_DEV_MAX];
static int virt_lastrate[EVIL_DEV_MAX * EVIL_DEV_MAX];
static ktime_t virt_lastevil[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_lastdeltaus[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned int virt_lastcount[EVIL_DEV_MAX * EVIL_DEV_MAX];
static bool virt_lastincr[EVIL_DEV_MAX * EVIL_DEV_MAX];
static bool virt_evildetected[EVIL_DEV_MAX * EVIL_DEV_MAX];
static unsigned long virt_lastsent[EVIL_DEV_MAX * EVIL_DEV_MAX];

static unsigned int eth_bucket[EVIL_DEV_MAX];
static unsigned int eth_rate[EVIL_DEV_MAX];
static unsigned int eth_fair_rate[EVIL_DEV_MAX];
static unsigned int eth_sent[EVIL_DEV_MAX];
static unsigned int eth_maxvirt_sent[EVIL_DEV_MAX];
static unsigned int eth_minvirt_sent[EVIL_DEV_MAX];
static bool eth_isactive[EVIL_DEV_MAX];


static int prevgsosize[EVIL_DEV_MAX];

static bool hygenicc_enable = false;
module_param(hygenicc_enable, bool, 0644);
MODULE_PARM_DESC(hygenicc_enable, " hygenicc_enable enables HyGenICC congestion control mechanism");

static int rate = 1000;
module_param(rate, int, 0644);
MODULE_PARM_DESC(rate, " rate determines the speed of the physical out link in Mbits/s");

static int gsosize = 0;
module_param(gsosize, int, 0644);
MODULE_PARM_DESC(gsosize, " gsosize determines the size of GSO segment, if zero default is used");


static unsigned int initialgsosize=0;
static unsigned int initialrate=1000;

static unsigned int tcpdropcount=0;
static unsigned int udpdropcount=0;


inline bool hygenicc_enabled(void)
{
    return hygenicc_enable;
}

void init_variables(void)
{
    int i,j,k;

    fill_us = FILL_INTERVAL_US;
    devcount=0;
    ethdevcount=0;
    virtdevcount=0;
    for(i=0; i<EVIL_DEV_MAX; i++)
    {
        virtdevindex[i]=-1;
        virtavgalpha[i]=0;
        virtipaddress[i]=0;
        for(j=0; j<EVIL_DEV_MAX; j++)
        {
            virt_bucket[i * EVIL_DEV_MAX + j] = 0;
            virt_rate[i * EVIL_DEV_MAX + j] = 0;
            virt_initrate[i * EVIL_DEV_MAX + j] = 0;
            virt_tokens[i * EVIL_DEV_MAX + j] = 0;
            virt_tcptokens[i * EVIL_DEV_MAX + j] = 0;
            virt_isactive[i * EVIL_DEV_MAX + j] = false;
            virt_sent[i * EVIL_DEV_MAX + j] =  0;
            virt_lastsent[i * EVIL_DEV_MAX + j] = 0;
            virt_lastevil[i * EVIL_DEV_MAX + j] = ktime_get();
	    virt_lastincr[i * EVIL_DEV_MAX + j] =  0;
	    virt_lastdeltaus[i * EVIL_DEV_MAX + j] =  0;
            virt_evildetected[i * EVIL_DEV_MAX + j] = false;
            //virt_lastupdate[i * EVIL_DEV_MAX + j] = NULL;

        }
    	eth_fair_rate[i]=0;
        ethdevindex[i]=-1;
        eth_bucket[i] = 0;
        eth_rate[i] = 0;
        eth_sent[i] = 0;
	    eth_maxvirt_sent[i] = 0;
	    eth_minvirt_sent[i] = 0;
        eth_isactive[i] = false;

    }
}

void add_evil_connection(const struct net_device * dev, __be32 addr)
{
    int i=0;
    while(i < virtdevcount)
    {
        if(virtdevindex[i] == dev->ifindex)
            break;
        i++;
    }
    if(i==virtdevcount && strstr((const char*)dev->name, "eth") == NULL)
    {
        fill_us = FILL_INTERVAL_US ;
        add_evil_dev(dev, true, addr);

    }
    if(!evil_timerrun)
    {
        if (hrtimer_active(&evil_hrtimer) != 0)
            hrtimer_cancel(&evil_hrtimer);
        evil_ktime = ktime_set(0 , fill_us * ( (unsigned long) 1E3L) );
        hrtimer_start(&evil_hrtimer, evil_ktime, HRTIMER_MODE_REL);
        evil_timerrun=true;
    }

}

void del_evil_connection(const struct net_device * dev)
{
    /*if(strcmp(strstr((const char*)dev->name, "eth"),"eth") != 0)
        del_evil_dev(dev, true);
    else
        del_evil_dev(dev, false);*/
}

void reset_evil_dev(int j)
{
     if(!virtdevcount)
	return;
     int i;
     for(i=0; i<ethdevcount; i++)
      {
           
                virt_rate[i * EVIL_DEV_MAX + j] = MAX(MIN_RATE, eth_rate[i]  / virtdevcount);
                virt_initrate[i * EVIL_DEV_MAX + j] = virt_rate[i * EVIL_DEV_MAX + j];
                virt_bucket[i * EVIL_DEV_MAX + j] =  MAX(MIN_BUCKET, depth * (virt_rate[i * EVIL_DEV_MAX + j]  >> 3) * fill_us);
                virt_tokens[i * EVIL_DEV_MAX + j] =  virt_bucket[i * EVIL_DEV_MAX + j];
                virt_tcptokens[i * EVIL_DEV_MAX + j] =  virt_bucket[i * EVIL_DEV_MAX + j]>>tcpburst;
                //virt_sent[i * EVIL_DEV_MAX + j] = 0;
                virt_isactive[i * EVIL_DEV_MAX + j] = false;
                virt_lastsent[i * EVIL_DEV_MAX + j]= 0;
		virt_lastevil[i * EVIL_DEV_MAX + j]= ktime_get();
		virt_lastcount[i * EVIL_DEV_MAX + j] =  0;
		virt_lastincr[i * EVIL_DEV_MAX + j] =  0;
		virt_evildetected[i * EVIL_DEV_MAX + j]= false;
                virt_lastupdate[i * EVIL_DEV_MAX + j]= ktime_get();
    }
     printk(KERN_INFO "OpenVswitch RESET virtual device : %i \n", j);
}

enum hrtimer_restart evil_timer_callback(struct hrtimer *timer)
{
    int i,j;
    if(hygenicc_enabled() && !evil_fail)
    {
        if(evil_timerrun)
        {
            if(initialgsosize!=gsosize || initialrate!=rate)
                init_ethdevices();
   	     for(i=0; i<ethdevcount; i++)
   	     {
		unsigned int avg_sent=0,active_count=0;
		eth_fair_rate[i]=eth_rate[i];
		    for(j=0; j<virtdevcount; j++)
		    {
				if(virt_lastsent[i * EVIL_DEV_MAX + j]>0 && jiffies_to_msecs(jiffies - virt_lastsent[i * EVIL_DEV_MAX + j]) >= 1000)
				{
					virt_isactive[i * EVIL_DEV_MAX + j] = false;
					reset_evil_dev(j);
				}
				else
				{
					virt_isactive[i * EVIL_DEV_MAX + j] = true;
					avg_sent += virt_sent[i * EVIL_DEV_MAX + j];
					active_count++;
				}
		    }
		
		if(active_count>1)
			eth_fair_rate[i] = eth_rate[i] / active_count;
	     }
	     for(i=0; i<ethdevcount; i++)
   	     {
		    for(j=0; j<virtdevcount; j++)
		    {
			if(virt_rate[i * EVIL_DEV_MAX + j] < eth_fair_rate[i] && virt_isactive[i * EVIL_DEV_MAX + j] && ktime_us_delta(ktime_get(), virt_lastevil[i * EVIL_DEV_MAX + j]) >= 2000)
			{
				
		        if(virt_evildetected[i * EVIL_DEV_MAX + j]) //&& virt_lastevil[i * EVIL_DEV_MAX + j]>0 && jiffies_to_msecs(jiffies -virt_lastevil[i * EVIL_DEV_MAX + j]) >= 1)
				{
				virt_evildetected[i * EVIL_DEV_MAX + j] = false;
				virt_lastincr[i * EVIL_DEV_MAX +j] = true;
				virt_rate[i * EVIL_DEV_MAX + j] = (virt_rate[i * EVIL_DEV_MAX + j] + virt_lastrate[i * EVIL_DEV_MAX + j])>>1;
				virt_rate[i * EVIL_DEV_MAX + j] = MIN(eth_fair_rate[i], virt_rate[i * EVIL_DEV_MAX + j] + (eth_fair_rate[i]/10));
				printk(KERN_INFO "OpenVswitch [Rateincrease:%pI4]: fair rate is %d, old rate is %d, new rate is %d\n", &virtipaddress[j], eth_fair_rate[i], virt_lastrate[i * EVIL_DEV_MAX + j],  virt_rate[i * EVIL_DEV_MAX + j]);
					
				}	
			
			}
			
		    }
	     }
		
		
        }

        ktime_t ktnow = hrtimer_cb_get_time(&evil_hrtimer);
        evil_ktime = ktime_set(0 , fill_us * ((unsigned long) 1E3L) );
        int overrun = hrtimer_forward(&evil_hrtimer, ktnow, evil_ktime);

        return HRTIMER_RESTART;
    }
    else
    {
        evil_timerrun=false;
        clear_table();
        init_variables();
    }
    return HRTIMER_NORESTART;
}


void process_packet(struct sk_buff *skb,  struct vport *inp , struct vport *outp, struct sw_flow_key *key)
{
    const struct net_device *in=netdev_vport_priv(inp)->dev;
    const struct net_device *out=netdev_vport_priv(outp)->dev;
    bool evil_pkt,ecn_pkt;
    u8 tos;
    u16 frag_off;
    int i=-1,j=-1, m=-1, n=-1 ,k=0, s=0,t=0, evil_count=0;
    struct track_flow_key track_key;
    struct track_flow * flow;
    struct udphdr * udp_header;
    struct tcphdr * tcp_header;
    struct iphdr * ip_header;
    int sourcep,destp;
    bool drop=false;
    ktime_t now_ktime=ktime_get();
    if (skb && in && out && !evil_fail)
    {
        ip_header = (struct iphdr *)skb_network_header(skb);
        if(ip_header->protocol == FEEDBACK_PACKET_IPPROTO)
        {
            evil_count = ntohs(ip_header->id);
            track_reverse_key_extract(skb, &track_key);
            flow = ovs_track_tbl_lookup(&track_key, sizeof(track_key));
            if(flow)
	    {
                 flow->evil_packet_count += evil_count;	
		 for(s=0;s<ethdevcount;s++)
			if(ethdevindex[s] == in->ifindex)
				break;
		for(t=0;t<virtdevcount;t++)
			if(virtdevindex[t] == out->ifindex)
				break;
  		if(virt_rate[s * EVIL_DEV_MAX + t] > evil_count + MIN_RATE)
		 {
			int delta_us = ktime_us_delta(now_ktime, virt_lastevil[s * EVIL_DEV_MAX + t]);
			bool larger = (evil_count * virt_lastdeltaus[s * EVIL_DEV_MAX + t]) >= (virt_lastcount[s * EVIL_DEV_MAX + t] * delta_us);
			if(larger || delta_us >= 3000)
			{
				 virt_lastrate[s * EVIL_DEV_MAX + t] = virt_rate[s * EVIL_DEV_MAX + t];
				 virt_rate[s * EVIL_DEV_MAX + t] =  MAX(MIN_RATE, virt_rate[s * EVIL_DEV_MAX + t] - evil_count * 5 );		
				 virt_lastevil[s * EVIL_DEV_MAX + t] = now_ktime;
				virt_lastdeltaus[s * EVIL_DEV_MAX + t] = delta_us;
				virt_lastcount[s * EVIL_DEV_MAX + t] = evil_count;
				 virt_evildetected[s * EVIL_DEV_MAX + t]=true;
				virt_lastincr[s * EVIL_DEV_MAX +t] = false;
				 //printk(KERN_INFO "OpenVswitch [%s:%pI4->%s:%pI4(%pI4)]: recieved evil message %d and new rate is %d and new bucket %d\n", (const char*)in, &ip_header->saddr,(const char*)out, &ip_header->daddr, &virtipaddress[t], evil_count, virt_rate[s * EVIL_DEV_MAX + t], virt_bucket[s * EVIL_DEV_MAX + t]);
			}
		}		 			
		 
	   	 flow->evil_lastfeedback = jiffies;
	     }
            kfree_skb(skb);
            return;
        }

        else if (ip_header && (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP) )
        {

            frag_off=ip_header->frag_off;
            tos=ip_header->tos;
            if(ip_header->protocol == IPPROTO_TCP)
            {
                tcp_header = (struct tcphdr *)skb_transport_header(skb);  //grab transport header
                sourcep=htons((unsigned short int) tcp_header->source);
                destp=htons((unsigned short int) tcp_header->dest);
            }
            else if(ip_header->protocol == IPPROTO_UDP)
            {

                udp_header = (struct udphdr *)skb_transport_header(skb);  //grab transport header
                sourcep=htons((unsigned short int) udp_header->source);
                destp=htons((unsigned short int) udp_header->dest);
            }

            /*************************bypass any other type of traffic*********************/
            if(!(sourcep==5001 || destp==5001 || sourcep==80 || destp==80))
                goto send;
            /*************************bypass any other type of traffic*********************/
            //find the out and in device index values
            k=0;
            while(k < ethdevcount)
            {
                if(ethdevindex[k] == out->ifindex)
                    i=k;
                else if(ethdevindex[k] == in->ifindex)
                    m=k;
                k++;
            }
            k=0;
            while(k< virtdevcount)
            {
                if(virtdevindex[k] == in->ifindex)
                    j=k;
                else if(virtdevindex[k] == out->ifindex)
                    n=k;
                k++;
            }


            track_key_extract(skb, &track_key);
            flow = ovs_track_tbl_lookup(&track_key, sizeof(track_key));


            if(i>=0 && j>=0) 
            {
					virt_isactive[i * EVIL_DEV_MAX + j]=true;
					virt_lastsent[i * EVIL_DEV_MAX + j]=jiffies;
					virt_sent[i * EVIL_DEV_MAX + j]++;
					eth_sent[i]++;		

		
                int delta_us = ktime_us_delta(now_ktime, virt_lastupdate[i * EVIL_DEV_MAX + j]);
				virt_tokens[i * EVIL_DEV_MAX + j] = MIN(virt_bucket[i * EVIL_DEV_MAX + j],  virt_tokens[i * EVIL_DEV_MAX + j] + (virt_rate[i * EVIL_DEV_MAX + j] >> 3) * delta_us);
	           virt_lastupdate[i * EVIL_DEV_MAX + j] = now_ktime;

                if(skb->len <= virt_tokens[i * EVIL_DEV_MAX + j])
                {
                    virt_tokens[i * EVIL_DEV_MAX + j]= MAX(0, virt_tokens[i * EVIL_DEV_MAX + j] - skb->len);
                }
				else
				{
			
					kfree_skb(skb);
					return;
				}
                

                //enable ECN on all outgoing packets
                enable_ecn(ip_header);

                if(flow)
                {
                    if(flow->ecn_packet_count >0)
                    {
                        enable_evil(ip_header);
                        flow->ecn_packet_count = MAX(0, flow->ecn_packet_count-1);
                        flow->in_packet_count = MAX(0, flow->in_packet_count-1);
						flow->ecn_lastfeedback = jiffies;

                    }


                }
                else
                    flow=insert_flow(track_key);

                flow->used=jiffies;
                flow->out_byte_count+=skb->len;
                flow->out_packet_count++;
            }
            else if (m>=0 && n>=0)
            {

                ecn_pkt =is_ecn(skb, ip_header->tos);
                if(ecn_pkt)
                {
                    //printk(KERN_INFO "OpenVswitch [%s:%pI4->%s:%pI4]: recieved the ecn bit %x\n", (const char*)in, &ip_header->saddr,(const char*)out, &ip_header->daddr, ip_header->tos);
                    clear_ecn(ip_header);
                }

                //check and clear evil bit
                evil_pkt=is_evil(skb, ntohs(ip_header->frag_off));
                if(evil_pkt)
                {
		    
                    clear_evil(ip_header);
					if(virt_rate[m * EVIL_DEV_MAX + n] > 1 + MIN_RATE)
					{
					   int delta_us = ktime_us_delta(now_ktime, virt_lastevil[m * EVIL_DEV_MAX + n]);
					   bool larger = (1 * virt_lastdeltaus[m * EVIL_DEV_MAX + n]) >= (virt_lastcount[m * EVIL_DEV_MAX + n] * delta_us);
						if(larger || delta_us >= 3000)
						{
							virt_lastrate[m * EVIL_DEV_MAX + n] = virt_rate[m * EVIL_DEV_MAX + n];
							 virt_rate[m * EVIL_DEV_MAX + n] =  MAX(MIN_RATE, virt_rate[m * EVIL_DEV_MAX + n] - 1);
							 virt_lastevil[m * EVIL_DEV_MAX + n] = now_ktime;
							virt_lastdeltaus[m * EVIL_DEV_MAX + n] = delta_us;
							virt_lastcount[m * EVIL_DEV_MAX + n] = 1;
							virt_evildetected[m * EVIL_DEV_MAX + n]=true;
							virt_lastincr[m * EVIL_DEV_MAX +n] = false;
							 //printk(KERN_INFO "OpenVswitch [%s:%pI4->%s:%pI4(%pI4)]: recieved the evil bit %x and new rate is %d and new bucket %d\n", (const char*)in, &ip_header->saddr,(const char*)out, &ip_header->daddr, &virtipaddress[n], frag_off, virt_rate[m * EVIL_DEV_MAX + n],  virt_bucket[m * EVIL_DEV_MAX + n]);
						 }
					 }
                   
                }

            }
            if(i==-1 && m==-1)
            {

                if(m==-1 && strstr((const char*)in->name, "eth") != NULL)
                {
                    m=ethdevcount;
                    add_evil_dev(in, false, 0);
                }
                else if (i==-1 && strstr((const char*)out->name, "eth") != NULL)
                {
                    i=ethdevcount;
                    add_evil_dev(out, false, 0);
                }
            }
            if(j==-1 && n==-1)
            {

                if(strstr((const char*)in->name, "eth") == NULL)
                {
                    j=virtdevcount;
                    add_evil_connection(in, ip_header->saddr);
                }
                else if (strstr((const char*)out->name, "eth") == NULL)
                {
                    n=virtdevcount;
                    add_evil_connection(out, ip_header->daddr);
                }
            }
        }

send:
        if(skb && outp)
            ovs_vport_send(outp, skb);
    }

}

void add_evil_dev(const struct net_device * dev, bool isvirt,__be32 addr)
{
    int i=0,j=0,k=0;
    if(dev==NULL || (isvirt && virtdevcount+1>(EVIL_DEV_MAX)) )
    {
        evil_fail=true;
        evil_timerrun=false;
        //printk(KERN_INFO "OpenVswitch : Fatal Error Exceed Allowed number of virtual Devices : %d \n", virtdevcount);
        return;
    }
    if(dev==NULL || (!isvirt && ethdevcount+1>(EVIL_DEV_MAX)) )
    {
        evil_fail=true;
        evil_timerrun=false;
        //printk(KERN_INFO "OpenVswitch : Fatal Error Exceed Allowed number of ethernet Devices : %d \n", ethdevcount);
        return;
    }
    if(isvirt)
    {
        k=virtdevcount;
        virtdevcount++;
        virtdevindex[k]=dev->ifindex;
        virtavgalpha[k]=0;
        virtipaddress[k]=addr;

        for(i=0; i<ethdevcount; i++)
        {
	    	eth_fair_rate[i]= MAX(MIN_RATE, eth_rate[i]  / virtdevcount);
            for(j=0; j<virtdevcount; j++)
            {
                virt_rate[i * EVIL_DEV_MAX + j] = MAX(MIN_RATE, eth_rate[i]  / virtdevcount);
                virt_initrate[i * EVIL_DEV_MAX + j] = virt_rate[i * EVIL_DEV_MAX + j];
                virt_bucket[i * EVIL_DEV_MAX + j] =  MAX(MIN_BUCKET, depth * (virt_rate[i * EVIL_DEV_MAX + j]  >> 3) * fill_us);
                virt_tokens[i * EVIL_DEV_MAX + j] =  virt_bucket[i * EVIL_DEV_MAX + j];
                virt_tcptokens[i * EVIL_DEV_MAX + j] =  virt_bucket[i * EVIL_DEV_MAX + j]>>tcpburst;
                virt_sent[i * EVIL_DEV_MAX + j] = 0;
                virt_isactive[i * EVIL_DEV_MAX + j] = true;
                virt_lastsent[i * EVIL_DEV_MAX + j]= jiffies;
				virt_lastevil[i * EVIL_DEV_MAX + j] =  ktime_get();
				virt_lastdeltaus[i * EVIL_DEV_MAX + j] =  0;
				virt_lastcount[i * EVIL_DEV_MAX + j] =  0;
				virt_lastincr[i * EVIL_DEV_MAX + j] =  0;
				virt_evildetected[i * EVIL_DEV_MAX + j] =  false;
                virt_lastupdate[i * EVIL_DEV_MAX + j]= ktime_get();
            }
        }
       // printk(KERN_INFO "OpenVswitch ADD %i Virtual Port: [%i:%s] addr:%pI4 initials : %d %d %d %d, Virtual devices : %d\n", k, virtdevindex[k], (const char*)dev->name, &virtipaddress[k] , virt_rate[k], virt_bucket[k], virt_tokens[k], virt_isactive[k], virtdevcount);
    }
    else
    {
        k=ethdevcount;
        ethdevcount++;
        ethdevindex[k]=dev->ifindex;

        eth_rate[k] = rate;
        eth_bucket[k] = MAX(MIN_BUCKET, depth * (eth_rate[k] >> 3) * FILL_INTERVAL_US );
        eth_sent[k] = 0;
		eth_maxvirt_sent[k] =0;
		eth_minvirt_sent[k] =0;
        eth_isactive[k] = true;
        for(j=0; j<virtdevcount; j++)
        {
            virt_rate[k * EVIL_DEV_MAX + j] = MAX(MIN_RATE, eth_rate[k] / virtdevcount);
            virt_initrate[k * EVIL_DEV_MAX + j] = virt_rate[k * EVIL_DEV_MAX + j];
            virt_bucket[k * EVIL_DEV_MAX + j] =  MAX(MIN_BUCKET, depth * (virt_rate[k * EVIL_DEV_MAX + j]  >> 3) * fill_us);
            virt_tokens[k* EVIL_DEV_MAX + j] =  virt_bucket[k * EVIL_DEV_MAX + j] ;
            virt_tcptokens[k* EVIL_DEV_MAX + j] = virt_bucket[k * EVIL_DEV_MAX + j]>>tcpburst;
            virt_sent[k * EVIL_DEV_MAX + j] = 0;
            virt_lastupdate[k * EVIL_DEV_MAX + j] = ktime_get();
            virt_lastsent[k * EVIL_DEV_MAX + j] = 0;
    		 virt_lastevil[i * EVIL_DEV_MAX + j] = ktime_get();
	        virt_lastdeltaus[i * EVIL_DEV_MAX + j] =  0;
	        virt_lastcount[i * EVIL_DEV_MAX + j] =  0;
	        virt_lastincr[i * EVIL_DEV_MAX + j] =  0;
	        virt_evildetected[i * EVIL_DEV_MAX + j] =  false;
        }
		//printk(KERN_INFO "OpenVswitch ADD %i ethernet: [%i:%s] initials : %d %d %d\n", k , ethdevindex[k], (const char*)dev->name, eth_rate[k], eth_bucket[k], eth_isactive[k]);
    }

    devcount++;
    printk(KERN_INFO "OpenVswitch ADD: total number of detected devices : %d \n", devcount);

}


void del_evil_dev(const struct net_device * dev, bool isvirt)
{
    int i=-1,j=-1,k=0;
    if(dev==NULL || devcount<=0)
        return;

    //printk(KERN_INFO "OpenVswitch DEL: [%s] \n", (const char*)dev->name);

    if(isvirt)
    {
        while(k< virtdevcount)
        {
            if(virtdevindex[k] == dev->ifindex)
                break;
            k++;
        }
        if (k==virtdevcount)
            return;
        j=k;
        while(j<virtdevcount) //&& virtdevindex[j+1]!=-1)
        {
            for(i=0; i<ethdevcount; i++)
            {
                virt_bucket[i * EVIL_DEV_MAX + j  ] = virt_bucket[i * EVIL_DEV_MAX + j + 1] ;
                virt_tokens[i * EVIL_DEV_MAX + j  ] = virt_tokens[i * EVIL_DEV_MAX + j + 1] ;
                virt_tcptokens[i * EVIL_DEV_MAX + j  ] = virt_tcptokens[i * EVIL_DEV_MAX + j + 1] ;
                virt_rate[i * EVIL_DEV_MAX + j ] = virt_rate[i * EVIL_DEV_MAX + j + 1];
                virt_initrate[i * EVIL_DEV_MAX + j ] = virt_initrate[i * EVIL_DEV_MAX + j + 1];
                virt_isactive[i * EVIL_DEV_MAX + j] =  virt_isactive[i * EVIL_DEV_MAX + j + 1];
                virt_lastupdate[i * EVIL_DEV_MAX + j+1] =  virt_lastupdate[i * EVIL_DEV_MAX + j];
                virt_sent[i * EVIL_DEV_MAX + j] =  virt_sent[i * EVIL_DEV_MAX + j + 1];
                virt_lastsent[i * EVIL_DEV_MAX + j] =  virt_lastsent[i * EVIL_DEV_MAX + j + 1];
                virt_lastevil[i * EVIL_DEV_MAX + j] =  virt_lastevil[i * EVIL_DEV_MAX + j + 1];
                virt_evildetected[i * EVIL_DEV_MAX + j] =  virt_evildetected[i * EVIL_DEV_MAX + j + 1];

            }
            virtdevindex[j] = virtdevindex[j+1];
            virtavgalpha[j]=virtavgalpha[j+1];
            virtipaddress[j]=virtipaddress[j+1];
	    

            j++;
        }
        virtdevcount--;
    }
    else
    {
        while(k< virtdevcount)
        {
            if(ethdevindex[k] == dev->ifindex)
                break;
            k++;
        }
        if (k==ethdevcount)
            return;
        j=k;
        while(j<ethdevcount )//&& ethdevindex[j+1]!=-1)
        {
            eth_bucket[j] = eth_bucket[j+1];
            eth_rate[j] = eth_rate[j+1];
            eth_sent[j] = eth_sent[j+1];
	    eth_maxvirt_sent[j] = eth_maxvirt_sent[j+1];
	    eth_minvirt_sent[j] = eth_minvirt_sent[j+1];
            eth_isactive[j] =  eth_isactive[j+1];
            // eth_lastupdate[j+1] = eth_lastupdate[j];
            ethdevindex[j] = ethdevindex[j+1];
            j++;
        }
        ethdevcount--;
    }

    devcount--;
    printk(KERN_INFO "OpenVswitch DEL: total number of detected devices : %d \n", devcount);
}


/**************************************************virtual device******************************************/


void init_ethdevices(void)
{
    struct net_device * dev;
    dev = first_net_device(&init_net);
    initialgsosize=gsosize;
    initialrate=rate;
    devcount-=ethdevcount;
    ethdevcount=0;

    int i=0;
    while(dev)
    {

        if(strcmp((const char*)dev->name, "lo") == 0 || strstr((const char*)dev->name, "eth") == NULL)
        {
            dev = next_net_device(dev);
            continue;
        }
        add_evil_dev(dev, false, 0);
        if(gsosize!=0)
        {
            prevgsosize[i] = dev->gso_max_size;
            netif_set_gso_max_size(dev, gsosize);
        }
        dev = next_net_device(dev);
        i++;

    }
}

void reset_ethdevices(void)
{
    struct net_device * dev;
    dev = first_net_device(&init_net);
    int i=0;
    while(dev)
    {
        if(strcmp((const char*)dev->name, "lo") == 0 || strstr((const char*)dev->name, "eth") == NULL)
        {
            dev = next_net_device(dev);
            continue;
        }
        if(gsosize!=0)
            netif_set_gso_max_size(dev,  prevgsosize[i]);

        dev = next_net_device(dev);
        i++;
    }
}

void init_hygenicc(void)
{
    evil_timerrun=false;

    if(rate<10)
        rate = 10;
    if(gsosize<0)
        gsosize=0;

    init_tracking();
    init_variables();

    hrtimer_init(&evil_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    evil_hrtimer.function = &evil_timer_callback;

    printk(KERN_INFO "OpenVswitch Init HyGenICC: hygenicc_enable: %d, rate: %d, gsosize %d\n", hygenicc_enabled(), rate, gsosize);
    return;
}

void cleanup_hygenicc(void)
{
    int ret_cancel = 0;
    reset_ethdevices();
    while( hrtimer_callback_running(&evil_hrtimer) )
    {
        ret_cancel++;
    }
    if (ret_cancel != 0)
    {
        printk(KERN_INFO " OpenVswitch: testjiffy Waited for hrtimer callback to finish (%d)\n", ret_cancel);
    }
    if (hrtimer_active(&evil_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&evil_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy active hrtimer cancelled: %d \n", ret_cancel);
    }
    if (hrtimer_is_queued(&evil_hrtimer) != 0)
    {
        ret_cancel = hrtimer_cancel(&evil_hrtimer);
        printk(KERN_INFO " OpenVswitch: testjiffy queued hrtimer cancelled: %d \n", ret_cancel);
    }
    printk(KERN_INFO "OpenVswitch: Stop HyGenICC \n");


}


