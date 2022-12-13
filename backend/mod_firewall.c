
#define __KERNEL__
#define MODULE

#define MATCH	1
#define NMATCH	0

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/rtc.h>

typedef struct rule
{
	short id;
	short onoff;
	short action;
    unsigned int saddr1;
    unsigned int saddr2;
	unsigned int daddr1;
    unsigned int daddr2;
    unsigned short sport1;
    unsigned short sport2;
	unsigned short dport1;
    unsigned short dport2;
	int time1;
	int time2;
	struct list_head rule_list;
}rule;

struct list_head icmp_rules_head;
struct list_head tcp_rules_head;
struct list_head udp_rules_head;

struct timespec64 cur_time;
struct rtc_time fmt_time;

int enable_flag = 0;

struct nf_hook_ops myhook;

unsigned int c_saddr1;
unsigned int c_saddr2;
unsigned int c_daddr1;
unsigned int c_daddr2;
unsigned short c_sport1;
unsigned short c_sport2;
unsigned short c_dport1;
unsigned short c_dport2;
int c_time1;
int c_time2;
short c_onoff; // on 1 off 0
short c_id;
short c_action;
int c_order_type;// add 1 delete 2 modify 3

struct sk_buff *tmpskb;
struct iphdr *piphdr;

static int rules_init(void){
	INIT_LIST_HEAD(&tcp_rules_head);
	INIT_LIST_HEAD(&udp_rules_head);
	INIT_LIST_HEAD(&icmp_rules_head);
	return 0;
}

static int rules_add(struct list_head* rules,short id,unsigned int saddr1,unsigned int saddr2,unsigned int daddr1,unsigned int daddr2,unsigned short sport1,unsigned short sport2,unsigned short dport1,unsigned short dport2, int time1, int time2,short onoff,short action){
	struct rule *new_rule;
	new_rule = kmalloc(sizeof(struct rule), GFP_KERNEL);
	if(!new_rule) printk("Malloc failed\n");

	new_rule->id = id;
	new_rule->onoff = onoff;
	new_rule->action = action;
	new_rule->saddr1 = ntohl(saddr1);
	new_rule->saddr2 = ntohl(saddr2);
	new_rule->daddr1 = ntohl(daddr1);
	new_rule->daddr2 = ntohl(daddr2);
	new_rule->sport1 = sport1;
	new_rule->sport2 = sport2;
	new_rule->dport1 = dport1;
	new_rule->dport2 = dport2;
	new_rule->time1 = time1;
	new_rule->time2 = time2;
	INIT_LIST_HEAD(&new_rule->rule_list);

	list_add_tail(&new_rule->rule_list, rules);
	printk("new rule:%d added\n", id);
	return 0;
}

static int rule_delete(struct list_head* rules, short id){
	struct rule *del;
	struct rule *r;
	list_for_each_entry(r, rules, rule_list){
		if(r->id == id){
			del = r;
			break;
		}
	}
	list_del(&del->rule_list);
	kfree(del);
	return 0;
}

static int rule_modify(struct list_head* rules,short id,unsigned int saddr1,unsigned int saddr2,unsigned int daddr1,unsigned int daddr2,unsigned short sport1,unsigned short sport2,unsigned short dport1,unsigned short dport2,int time1,int time2,short onoff,short action){
	struct rule *r;
	list_for_each_entry(r, rules, rule_list){
		if(r->id == id){
			r->onoff = onoff;
			r->action = action;
			r->saddr1 = ntohl(saddr1);
			r->saddr2 = ntohl(saddr2);
			r->daddr1 = ntohl(daddr1);
			r->daddr2 = ntohl(daddr2);
			r->sport1 = sport1;
			r->sport2 = sport2;
			r->dport1 = dport1;
			r->dport2 = dport2;
			r->time1 = time1;
			r->time2 = time2;
			break;
		}
	}
	return 0;
}

static int rules_traverse(struct list_head* rules){
	struct rule *r;
	list_for_each_entry(r, rules, rule_list){
		printk("rule:%u sip:%u-%u dip:%u-%u sport:%u-%u dport:%u-%u\n", r->id, r->saddr1, r->saddr2, r->daddr1, r->daddr2,r->sport1, r->sport2,r->dport1, r->dport2);
	}
	return 0;
}

/* TODO */
static int rule_check(struct rule *r, unsigned int saddr, unsigned int daddr, unsigned short srcport, unsigned short dstport){
	int ip_match = MATCH;
	int port_match = MATCH;
	int time_match = MATCH;
	int cur;
	// if the rule is off
	if(r->onoff == 0) return NMATCH;

	ktime_get_real_ts64(&cur_time);
	cur = cur_time.tv_sec;
	printk("time:%u\n", cur);

	saddr = ntohl(saddr);
	daddr = ntohl(daddr);

	if(r->daddr1 != 0){
		if(r->daddr1 > daddr || daddr > r->daddr2) ip_match = NMATCH;
	}
	if(r->saddr1 != 0){
		if(r->saddr1 > saddr || saddr > r->saddr2) ip_match = NMATCH;
	}
	if(r->dport1 != 0){
		if(r->dport1 > dstport || dstport > r->dport2) port_match = NMATCH;
	}
	if(r->sport1 != 0){
		if(r->sport1 > srcport || srcport > r->sport2) port_match = NMATCH;
	}
	if(r->time1 != -1){
		if(r->time1 > cur || cur > r->time2) time_match = NMATCH;
	}
	// icmp
	if(srcport == 0 && dstport == 0) port_match = MATCH;

	if(ip_match == MATCH && port_match == MATCH && time_match == MATCH) 
		return MATCH;
	else return NMATCH;
}

int tcp_chain_check(void){
	struct tcphdr *ptcphdr;
	struct rule *r;
	int ret = NF_ACCEPT;
	ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));

	list_for_each_entry(r, &tcp_rules_head, rule_list){
		printk("tcp rule id : %d\n", r->id);
		if(rule_check(r,piphdr->saddr,piphdr->daddr,ptcphdr->source,ptcphdr->dest) == MATCH){
			printk("dump\n");
			ret = NF_DROP;
			break;
		}
	}
	return ret;
}

int udp_chain_check(void){
	struct udphdr *pudphdr;
	struct rule *r;
	int ret = NF_ACCEPT;
    pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));

	list_for_each_entry(r, &udp_rules_head, rule_list){
		if(rule_check(r,piphdr->saddr,piphdr->daddr,pudphdr->source,pudphdr->dest) == MATCH){
			printk("udp rule %u:dump\n", r->id);
			ret = NF_DROP;
			break;
		}
	}
	return ret;
}

int icmp_chain_check(void){
	struct icmphdr *picmphdr;
	struct rule *r;
	int ret = NF_ACCEPT;
   	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

	if (picmphdr->type == 0){ // ping reply
		list_for_each_entry(r, &icmp_rules_head, rule_list){
			printk("rule id : %d\n", r->id);
			if(rule_check(r,piphdr->daddr,piphdr->saddr,0,0) == MATCH){
				printk("icmp rule %u:dump\n", r->id);
				ret = NF_DROP;
				break;
			}
		}
	} else if (picmphdr->type == 8) // ping request
	{
		list_for_each_entry(r, &icmp_rules_head, rule_list){
			if(rule_check(r,piphdr->saddr,piphdr->daddr,0,0) == MATCH){
				printk("icmp rule %u:dump\n", r->id);
				ret = NF_DROP;
				break;
			}
		}
	}
	
	return ret;
}

/*
unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	if (enable_flag == 0)
		return NF_ACCEPT;
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

	/* icmp */
	if (piphdr->protocol  == 1)  
		return icmp_chain_check();
	/* tcp */
	else if (piphdr->protocol  == 6) 
		return tcp_chain_check();
	/* udp */
	else if (piphdr->protocol  == 17) 
		return udp_chain_check();
	else
	{
		printk("Unkonwn type's packet! \n");
		return NF_ACCEPT;
	}
}

static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;
	int controlled_type;
	unsigned int c_protocol;
	pchar = controlinfo;
	printk("--------operation---------\n");
	if (len == 0){
		enable_flag = 0;
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	c_order_type = *((int*) pchar);
	c_id = *((int*) (pchar + 4));
	c_protocol = *((int*) (pchar + 8));
	printk("Order type:%u\n", c_order_type);
	if(c_order_type == 1){ // add
		c_saddr1 = *((int*) (pchar + 12));
		c_saddr2 = *((int*) (pchar + 16));
		c_daddr1 = *((int*) (pchar + 20));
		c_daddr2 = *((int*) (pchar + 24));
		c_sport1 = *((int*) (pchar + 28));
		c_sport2 = *((int*) (pchar + 32));
		c_dport1 = *((int*) (pchar + 36));
		c_dport2 = *((int*) (pchar + 40));
		c_time1 = *((int*) (pchar + 44));
		c_time2 = *((int*) (pchar + 48));
		c_onoff = *((int*) (pchar + 52));
		c_action = *((int*) (pchar + 56));
		switch (c_protocol)
		{
		case 1: // tcp
			printk("new tcp rule\n");
			rules_add(&tcp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 2: // udp
			printk("new udp rule\n");
			rules_add(&udp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 3: // icmp
			printk("new icmp rule\n");
			rules_add(&icmp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 4: // all
			printk("new all rule\n");
			rules_add(&tcp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			rules_add(&udp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			rules_add(&icmp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		}
	}else if(c_order_type == 2){ // delete
		switch (c_protocol)
		{
		case 1: // tcp
			printk("delete tcp rule:%d\n",c_id);
			rule_delete(&tcp_rules_head, c_id);
			break;
		case 2: // udp
			printk("delete udp rule:%d\n",c_id);
			rule_delete(&udp_rules_head, c_id);
			break;
		case 3: // icmp
			printk("delete icmp rule:%d\n",c_id);
			rule_delete(&icmp_rules_head, c_id);
			break;
		case 4: // all
			printk("new all rule\n");
			rule_delete(&tcp_rules_head, c_id);
			rule_delete(&udp_rules_head, c_id);
			rule_delete(&icmp_rules_head, c_id);
			break;
		}
	}else if(c_order_type == 3){ // modify
		c_saddr1 = *((int*) (pchar + 12));
		c_saddr2 = *((int*) (pchar + 16));
		c_daddr1 = *((int*) (pchar + 20));
		c_daddr2 = *((int*) (pchar + 24));
		c_sport1 = *((int*) (pchar + 28));
		c_sport2 = *((int*) (pchar + 32));
		c_dport1 = *((int*) (pchar + 36));
		c_dport2 = *((int*) (pchar + 40));
		c_time1 = *((int*) (pchar + 44));
		c_time2 = *((int*) (pchar + 48));
		c_onoff = *((int*) (pchar + 52));
		c_action = *((int*) (pchar + 56));
		switch (c_protocol)
		{
		case 1: // tcp
			printk("change tcp rule\n");
			rule_modify(&tcp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 2: // udp
			printk("change udp rule\n");
			rule_modify(&udp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 3: // icmp
			printk("change icmp rule\n");
			rule_modify(&icmp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		case 4: // all
			printk("change all rule\n");
			rule_modify(&tcp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			rule_modify(&udp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			rule_modify(&icmp_rules_head, c_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_onoff, c_action);
			break;
		}
	}
	printk("controlinfo: id%u sip:%u-%u dip:%u-%u sport:%u-%u dport:%u-%u time:%d-%d protocol:%u mode:%u action%u\n", c_id,c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_time1, c_time2, c_protocol,c_onoff,c_action);
	printk("-----all rules---------\n");
	printk("tcp:\n");
	rules_traverse(&tcp_rules_head);
	printk("udp:\n");
	rules_traverse(&udp_rules_head);
	printk("icmp:\n");
	rules_traverse(&icmp_rules_head);

	// get current Beijing Time
	// ktime_get_real_ts64(&cur_time);
	rtc_time64_to_tm(cur_time.tv_sec + 8 * 60 * 60, &fmt_time);
	// printk("UTC time :%d-%d-%d %d:%d:%d week %d\n",fmt_time.tm_year+1900,fmt_time.tm_mon+1, fmt_time.tm_mday,fmt_time.tm_hour,fmt_time.tm_min,fmt_time.tm_sec, fmt_time.tm_wday);

	enable_flag = 1;
	// printk("rule: sip:%u-%u dip:%u-%u sport:%u-%u dport:%u-%u protocol:%u\n", c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_protocol);
	return len;
}


struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};


static int __init initmodule(void)
{
	int ret;
	
   	printk("Init Module\n");
   	myhook.hook=hook_func;
   	myhook.hooknum=NF_INET_POST_ROUTING;
   	myhook.pf=PF_INET;
   	myhook.priority=NF_IP_PRI_FIRST;

	rules_init();

   	nf_register_net_hook(&init_net,&myhook);

   	ret = register_chrdev(124, "/dev/controlinfo", &fops); 	
   	//��ϵͳע���豸����ļ�
   	if (ret != 0) printk("Can't register device file! \n");

   	return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "controlinfo");	 // ��ϵͳע���豸����ļ�
    printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
