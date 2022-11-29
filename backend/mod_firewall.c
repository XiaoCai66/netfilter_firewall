
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
    unsigned int saddr1;
    unsigned int saddr2;
	unsigned int daddr1;
    unsigned int daddr2;
    unsigned short sport1;
    unsigned short sport2;
	unsigned short dport1;
    unsigned short dport2;
	struct list_head rule_list;
}rule;

struct list_head icmp_rules_head;
struct list_head tcp_rules_head;
struct list_head udp_rules_head;
int rule_len = 0;
short rule_id = 0;

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

struct sk_buff *tmpskb;
struct iphdr *piphdr;

static int rules_init(void){
	INIT_LIST_HEAD(&tcp_rules_head);
	INIT_LIST_HEAD(&udp_rules_head);
	INIT_LIST_HEAD(&icmp_rules_head);
	return 0;
}

static int rules_add(struct list_head* rules, short id, unsigned int saddr1, unsigned int saddr2, unsigned int daddr1, unsigned int daddr2, unsigned short sport1, unsigned short sport2, unsigned short dport1, unsigned short dport2){
	struct rule *new_rule;
	new_rule = kmalloc(sizeof(struct rule), GFP_KERNEL);
	if(!new_rule) printk("Malloc failed\n");

	rule_len ++;

	new_rule->id = id;
	new_rule->saddr1 = ntohl(saddr1);
	new_rule->saddr2 = ntohl(saddr2);
	new_rule->daddr1 = ntohl(daddr1);
	new_rule->daddr2 = ntohl(daddr2);
	new_rule->sport1 = sport1;
	new_rule->sport2 = sport2;
	new_rule->dport1 = dport1;
	new_rule->dport2 = dport2;
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
	rule_len --;
	return 0;
}

static int rules_traverse(struct list_head* rules){
	struct rule *r;
	list_for_each_entry(r, rules, rule_list){
		printk("rule:%d\n", r->id);
	}
	return 0;
}

/* TODO */
static int rule_check(struct rule *r, unsigned int saddr, unsigned int daddr, unsigned short srcport, unsigned short dstport){
	int ip_match = MATCH;
	int port_match = MATCH;

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
	if(ip_match == MATCH && port_match == MATCH) 
		return MATCH;
	else return NMATCH;
}

// int icmp_check(void){
// 	struct icmphdr *picmphdr;
// 	/* printk("<0>This is an ICMP packet.\n"); */
//    	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

// 	if (picmphdr->type == 0){ // ping reply
// 			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
// 			 	printk("An ICMP packet is denied! \n");
// 				return NF_DROP;
// 			}
// 	}
// 	if (picmphdr->type == 8){ // ping request
// 			if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
// 			 	printk("An ICMP packet is denied! \n");
// 				return NF_DROP;
// 			}
// 	}
//     return NF_ACCEPT;
// }

// int tcp_check(void){
// 	struct tcphdr *ptcphdr;
// 	/* printk("<0>This is an tcp packet.\n"); */
//     ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));

//     /* reject all */
// 	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
// 	 	printk("A TCP packet is denied! \n");
// 		return NF_DROP;
// 	}
// 	else
//       	return NF_ACCEPT;
// }

// int udp_check(void){
// 	struct udphdr *pudphdr;
// 	/* printk("<0>This is an udp packet.\n"); */
//     pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
// 	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
// 	 	printk("A UDP packet is denied! \n");
// 		return NF_DROP;
// 	}
// 	else
//       	return NF_ACCEPT;
// }

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
		printk("udp rule id : %d\n", r->id);
		if(rule_check(r,piphdr->saddr,piphdr->daddr,pudphdr->source,pudphdr->dest) == MATCH){
			printk("dump\n");
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
				printk("dump\n");
				ret = NF_DROP;
				break;
			}
		}
	} else if (picmphdr->type == 8) // ping request
	{
		list_for_each_entry(r, &icmp_rules_head, rule_list){
			printk("rule id : %d\n", r->id);
			if(rule_check(r,piphdr->saddr,piphdr->daddr,0,0) == MATCH){
				printk("dump\n");
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

	if (len == 0){
		enable_flag = 0;
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	c_protocol = *((int*) pchar);
	pchar = pchar + 4;
	c_saddr1 = *((int*) pchar);
	pchar = pchar + 4;
	c_saddr2 = *((int*) pchar);
	pchar = pchar + 4;
	c_daddr1 = *((int*) pchar);
	pchar = pchar + 4;
	c_daddr2 = *((int*) pchar);
	pchar = pchar + 4;
	c_sport1 = *((int*) pchar);
	pchar = pchar + 4;
	c_sport2 = *((int*) pchar);
	pchar = pchar + 4;
	c_dport1 = *((int*) pchar);
	pchar = pchar + 4;
	c_dport2 = *((int*) pchar);
	pchar = pchar + 4;

	switch (c_protocol)
	{
	case 1:// single ban
		printk("new tcp rule\n");
		rules_add(&tcp_rules_head, rule_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2);
		break;
	case 2:// interval ban
		printk("new udp rule\n");
		rules_add(&udp_rules_head, rule_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2);
		break;
	case 3:// time interval ban
		printk("new icmp rule\n");
		rules_add(&icmp_rules_head, rule_id, c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2);
		break;
	
	default:
		printk("wrong protocol\n");
		break;
	}
	
	rule_id++;

	printk("tcp:\n");
	rules_traverse(&tcp_rules_head);
	printk("udp:\n");
	rules_traverse(&udp_rules_head);
	printk("icmp:\n");
	rules_traverse(&icmp_rules_head);

	// get current Beijing Time
	ktime_get_real_ts64(&cur_time);
	rtc_time64_to_tm(cur_time.tv_sec + 8 * 60 * 60, &fmt_time);
	printk("UTC time :%d-%d-%d %d:%d:%d week %d\n",fmt_time.tm_year+1900,fmt_time.tm_mon+1, fmt_time.tm_mday,fmt_time.tm_hour,fmt_time.tm_min,fmt_time.tm_sec, fmt_time.tm_wday);

	enable_flag = 1;
	printk("rule: sip:%u-%u dip:%u-%u sport:%u-%u dport:%u-%u protocol:%u\n", c_saddr1, c_saddr2, c_daddr1, c_daddr2, c_sport1, c_sport2, c_dport1, c_dport2, c_protocol);
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
