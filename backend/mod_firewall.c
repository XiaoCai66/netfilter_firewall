
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


struct list_head rules_head;
int rule_len = 0;
short rule_id = 0;

int enable_flag = 0;

struct nf_hook_ops myhook;

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

struct sk_buff *tmpskb;
struct iphdr *piphdr;

static int rules_init(void){
	if(rule_len == 0)
		INIT_LIST_HEAD(&rules_head);
	return 0;
}

static int rules_add(short id, unsigned int saddr1, unsigned int saddr2, unsigned int daddr1, unsigned int daddr2, unsigned short sport1, unsigned short sport2, unsigned short dport1, unsigned short dport2){
	struct rule *new_rule;
	new_rule = kmalloc(sizeof(struct rule), GFP_KERNEL);
	if(!new_rule) printk("Malloc failed\n");

	rule_len ++;

	new_rule->id = id;
	new_rule->saddr1 = saddr1;
	new_rule->saddr2 = saddr2;
	new_rule->daddr1 = daddr1;
	new_rule->daddr2 = daddr2;
	new_rule->sport1 = sport1;
	new_rule->sport2 = sport2;
	new_rule->dport1 = dport1;
	new_rule->dport2 = dport2;
	INIT_LIST_HEAD(&new_rule->rule_list);

	list_add_tail(&new_rule->rule_list, &rules_head);
	printk("new rule:%d added\n", id);
	return 0;
}

static int rule_delete(short id){
	struct rule *del;
	struct rule *r;
	list_for_each_entry(r, &rules_head, rule_list){
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

static int rules_traverse(void){
	struct rule *r;
	list_for_each_entry(r, &rules_head, rule_list){
		printk("rule:%d\n", r->id);
	}
	return 0;
}

/* TODO */
int rule_check(struct rule *r){
	return MATCH;
}

/* this function checks whether the port matches */
int port_check(unsigned short srcport, unsigned short dstport){
	/* if neither port is set */ 
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
		return MATCH;
	
	/* if source is set */
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport)
			return MATCH;
		else
			return NMATCH;
	}

	/* if destination is set */
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport)
			return MATCH;
		else
			return NMATCH;
	}

	/* if both are set */
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport))
			return MATCH;
		else
			return NMATCH;
	}

	return NMATCH;
}

int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

int icmp_check(void){
	struct icmphdr *picmphdr;
	/* printk("<0>This is an ICMP packet.\n"); */
   	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

	if (picmphdr->type == 0){
			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
	}
	if (picmphdr->type == 8){
			if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
	}
    return NF_ACCEPT;
}

int tcp_check(void){
	struct tcphdr *ptcphdr;
	/* printk("<0>This is an tcp packet.\n"); */
    ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));

    /* reject all */
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	printk("A TCP packet is denied! \n");
		return NF_DROP;
	}
	else
      	return NF_ACCEPT;
}

int udp_check(void){
	struct udphdr *pudphdr;
	/* printk("<0>This is an udp packet.\n"); */
    pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
	 	printk("A UDP packet is denied! \n");
		return NF_DROP;
	}
	else
      	return NF_ACCEPT;
}

/*
unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	if (enable_flag == 0)
		return NF_ACCEPT;
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

	if(piphdr->protocol != controlled_protocol)
      	return NF_ACCEPT;

	/* icmp */
	if (piphdr->protocol  == 1)  
		return icmp_check();
	/* tcp */
	else if (piphdr->protocol  == 6) 
		return tcp_check();
	/* udp */
	else if (piphdr->protocol  == 17) 
		return udp_check();
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
	unsigned short dp;
	unsigned short sp;
	int controlled_type;
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
	controlled_type = *((int*) pchar);
	pchar = pchar + 4;
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);

	switch (controlled_type)
	{
	case 1:// single ban
		printk("type:%d\n",1);
		break;
	case 2:// interval ban
		printk("type:%d\n",2);
		break;
	case 3:// time interval ban
		printk("type:%d\n",3);
		break;
	
	default:
		printk("type:0\n");
		break;
	}

	rules_add(rule_id, controlled_saddr,controlled_saddr,controlled_daddr,controlled_daddr,controlled_srcport,controlled_srcport,controlled_dstport,controlled_dstport);
	rule_id ++;

	if(rule_len %5 == 0) rules_traverse();

	sp = htons(controlled_srcport);
	dp = htons(controlled_dstport);

	enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,sp,dp);
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
