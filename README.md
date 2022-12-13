系统软件课程设计
项目结题报告
===
https://github.com/XiaoCai66/netfilter_firewall
# 一.项目需求分析
### **1.1 需求分析**

Netfilter是Linux内核中的一个网络控制框架，它能够对网络通信中的数据包进行控制。有许多Linux的内核模块防火墙都是基于Netfilter构建的，通过应用层与用户的交互来获得一些控制规则，在内核层借助Netfilter钩子函数来完成网络层的包过滤。

而当前的内核模块包过滤防火墙有以下几个问题：
1. 控制规则简单。当前的实现只能够根据通信双方的IP地址和端口进行检查，不能够拓展到其他的实际需求检查。
2. 不支持多条规则。现在的防火墙只能够支持一条规则，这从实用性上来讲有较大的缺陷。

### **1.2 总体功能要求**

为了开发一个功能相对完善的内核模块包过滤防火墙，我们小组决定开发以下的功能：
* 支持多条过滤规则控制：能够添加多条针对协议、IP地址和端口的过滤规则；能够根据子网段、端口范围等进行批量过滤；
* 基于时间的包过滤控制：能够自定义基于时间段的过滤规则
* GUI：开发一个对用户友好的Linux桌面应用，具有登录、配置、查看等功能

# 二.项目总体设计
根据Linux系统的运行模式，我们的系统设计将主要分为以下两个模块：桌面应用GUI和内核防火墙模块。桌面应用前端与用户交互，获取过滤规则等信息，通过系统调用传递给内核模块，内核模块完成网络控制的功能。
* 桌面应用GUI：主要负责处理与用户交互的功能，方便用户配置规则，然后将规则传递给内核
* 内核模块：主要处理网络控制功能，使用netfilter机制对post routing进行挂钩，根据应用层传递下来的规则进行过滤

![](https://notes.sjtu.edu.cn/uploads/upload_f2efb1b63f655657e484ee4d1d97b2e1.png)

# 三.GUI模块设计
## 3.1 GUI框架设计
GUI与用户进行交互，接受用户的输入，传递给内核进行设置。GUI采用Qt Creator的框架，分为以下四个UI模组：
### 3.1.1 登录界面
登录界面能够实现单用户的防火墙准入功能。识别用户输入的账户密码，匹配时才允许用户登入防火墙。

![](https://notes.sjtu.edu.cn/uploads/upload_d5ef06ab9b27840d81d5bdff637b0678.png)


### 3.1.2 规则管控界面
规则管控界面实现对规则的具体操作和展示。这里采用四个按钮分别对应规则的增删改以及启动关闭。这四个功能除了改变数据库中的状态，还需要改变对应内核的规则状态。最后，利用Qt Creator自带的Tableview控件来展示保存在数据库当中的规则。

![](https://notes.sjtu.edu.cn/uploads/upload_0427c3b6d4a433758be3e1d7f4f1a655.png)

### 3.1.3 添加规则界面
添加规则界面实现对规则的添加，保存成功后同时写入数据库和内核。其中需要撰写的字段包括规则名，原始IP，原始端口，目的IP，目的端口的上下界，服务类型（包括TCP，UDP，ICMP和ALL）以及时间跨度。在IP和端口部分采用Qt自带的Qspinbox，既避免输入String难以判断又能够设置相应的上下界。

![](https://notes.sjtu.edu.cn/uploads/upload_cf72c981c49bf45ca6822fd5b179b9be.png)

### 3.1.4 修改规则界面
修改规则界面大体上与添加规则界面一致，需要从数据库中读出指定的规则，并把相应的元素值赋予到此界面的对应位置上。在修改规则界面中除了服务类型之外全部都可以修改，保存之后也是在数据库和内核对应的规则上做更新。这里不能修改服务是因为在内核当中不同服务需要不同的一套实现代码，不是简单的传参数就可以改变的。因此，如果有相应的需求只能够添加新的服务来实现。

![](https://notes.sjtu.edu.cn/uploads/upload_7f7a4baf75287def558e5650d25e5c0b.png)

## 3.2 数据库设计
数据库采用Sqlite3.因为Qt里自带了连接Sqlite3数据库的组件，用QSqlDatabase::adddatabase("Sqlite")并设置相应的用户名和密码就能够连接到指定的数据库。我们在数据库中新建了rule的表用来存放相应的规则。数据表主要包括以下内容：主键id，模式mode，规则名，原始IP、原始端口、目的IP、目的端口的范围，服务类型，行为（默认拒绝）和时间限制。具体结构如下所示：


| id (integer primary key) | mode (char(5)) | name (varchar(20) unique) | ori_ip_down (char(20)) | ori_ip_up (char(20)) | ori_port_down (int) | ori_port_up (int) | target_ip_down (char(20)) | target_ip_up (char(20)) | target_port_down (int) | target_port_up (int) | service (char(20)) | action (char(1)) | time_begin (char(50)) | time_end (char(50)) |
| ------------------------ | -------------- | ------------------------- | ---------------------- | -------------------- | ------------------- | ----------------- | ------------------------- | ----------------------- | ---------------------- | -------------------- | ------------------ | ---------------- | --------------------- | ------------------- |






# 四.内核模块设计
内核模块接受应用层传递下来的规则，利用规则对数据包进行过滤。
## 4.1 规则设计管理

在内核中，我们设计了rule的结构体，使用id标识每一条规则，字段的具体含义如下

| 变量   | 数据类型    | 含义         |
| ------ | ----------- | ------------ |
| onoff  | short 2字节 | 规则开关     |
| saddr1 | int 4字节   | 源地址下界   |
| saddr2 | int 4字节   | 源地址上界   |
| daddr1 | int 4字节   | 目的地址下界 |
| daddr2 | int 4字节   | 目的地址上界 |
| sport1 | int 4字节   | 源端口下界   |
| sport2 | int 4字节   | 源端口上界   |
| sport1 | int 4字节   | 源端口下界   |
| sport2 | int 4字节   | 源端口上界   |
| time1  | int 4字节   | 时间下界     |
| time2  | int 4字节   | 时间上界     | 
```cpp
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
```
规则通过内核链表进行组织、管理。内核链表是内核实现的有关列表的泛型，提供了添加、删除等接口，能够方便我们在内核中管理数据。我们将三种协议的过滤规则组织成三条链表，实现了对规则的增加、删除、修改三个接口。

```cpp
struct list_head icmp_rules_head;
struct list_head tcp_rules_head;
struct list_head udp_rules_head;

static int rule_add(struct list_head* rules,short id,unsigned int saddr1,unsigned int saddr2,unsigned int daddr1,unsigned int daddr2,unsigned short sport1,unsigned short sport2,unsigned short dport1,unsigned short dport2, int time1, int time2,short onoff,short action);
static int rule_modify(struct list_head* rules,short id,unsigned int saddr1,unsigned int saddr2,unsigned int daddr1,unsigned int daddr2,unsigned short sport1,unsigned short sport2,unsigned short dport1,unsigned short dport2, int time1, int time2,short onoff,short action);
static int rule_delete(struct list_head* rules, short id);
```

## 4.2 过滤方法实现
我们采用黑名单的过滤方式，将匹配的数据包丢弃。我们实现的过滤方式为全匹配过滤，只有当数据包完全符合过滤规则的各个字段才能够进行过滤。我们过滤的字段有源ip，目的ip，源端口，目的端口，时间。

过滤ip时，我们使用inet_aton函数以及ntohl函数将ip字符串转化为int，可以直接比较ip地址的范围。端口我们使用int进行存储。时间控制我们采用UTC标准时间，将时间转化为1970年以来的秒数进行存储。

```cpp
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
```

## 4.3 hook&应用层交互
我们将hook的函数挂钩到post routing的链上，所有经过本机的数据包都会得到检查。挂钩函数中检查数据包的协议类型，然后转到我们存储的不同规则链上面进行检查。

```cpp
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
```

同时，我们编写了write的内核函数，根据应用层传递下来的参数进行操作。最重要的控制信息包括c_order_type,c_id,c_protocol,分别指明了增删改的哪种操作类型、规则id和规则协议。
```cpp
if (copy_from_user(controlinfo, buf, len) != 0){
	printk("Can't get the control rule! \n");
	printk("Something may be wrong, please check it! \n");
	return 0;
}
c_order_type = *((int*) pchar);
c_id = *((int*) (pchar + 4));
c_protocol = *((int*) (pchar + 8));
```

# 五.系统设计
## 5.1 开发环境 工具介绍
开发工具包括VSCode，Qt
* 内核版本5.4
* GUI：Qt5.12.8

## 5.2 源文件
源文件包括GUI和内核两部分，其中mod_firewall.c为内核主要编写的代码。
```
.
├── backend
│   ├── Makefile
│   ├── mod_firewall.c
│   └── test.c
├── frontend
│   ├── add_rule.cpp
│   ├── addrule.cpp
│   ├── add_rule.h
│   ├── addrule.h
│   ├── addrule.ui
│   ├── alterrule.cpp
│   ├── alterrule.h
│   ├── alterrule.ui
│   ├── firewall.pro
│   ├── firewall.pro.user
│   ├── firewall.pro.user.39f7144
│   ├── firewall.pro.user.6854f54
│   ├── firewall_zh_CN.ts
│   ├── login.cpp
│   ├── login.h
│   ├── login.ui
│   ├── main.cpp
│   ├── mainwindow.cpp
│   ├── mainwindow.h
│   ├── mainwindow.ui
│   ├── screen.cpp
│   ├── screen.h
│   └── screen.ui
└── README.md
```

## 5.3 目标程序运行
首先进行内核模块的编译和插入
```
cd ./backend
make
insmod mod_firewall.ko
```
然后Qt工具链编译Qt，打开软件
其中可以使用``dmesg``命令查看内核情况
运行结束后可以删除内核模块
```
rmmod mod_firewall
```


# 六.项目测试
## 6.1 登录
登录界面需要指定用户名和密码才可登入，错误的用户名或密码会禁止登录。

![](https://notes.sjtu.edu.cn/uploads/upload_bb10a0ba2cd9242b414e38e5991a5cbd.png)


## 6.2 TCP服务、添加与启动关闭功能
通过ifconfig命令发现本机IP为192.168.211.129。我们打开网页发现此时是可以上网的。添加一条规则禁止本机的TCP服务。此时查看内核发现rule1已经成功写入。这里的IP要转化为uint型才能够被写入内核。

![](https://notes.sjtu.edu.cn/uploads/upload_d27bbf325b3e511d3394320567f6c9b8.png)

然后我们在打开网页发现此时已经不能上网。

![](https://notes.sjtu.edu.cn/uploads/upload_fe7b5487be22e31696be7b499b1ec8a7.png)

同时查看内核发现tcp报文都被dump掉了。

![](https://notes.sjtu.edu.cn/uploads/upload_b71c4960ecf173df8459c6bc96dda37a.png)

我们再将rule1的mode通过启动关闭按钮改成off，这时候在查看内核发现可以上网。

![](https://notes.sjtu.edu.cn/uploads/upload_b06525007dd1a11f0e523a2d4c5d422c.png)

## 6.3 ICMP服务、时间段设置与修改功能
先ping网关，即ping 192.168.211.1发现能够ping通。

![](https://notes.sjtu.edu.cn/uploads/upload_16d5c8f412fa69fe85f1d44a4b9f16db.png)

添加一条规则禁止本机的ICMP服务并设置相应的时间段。

![](https://notes.sjtu.edu.cn/uploads/upload_d5780eb01e43c1aa6b4688c69c714fe1.png)

查看内核，发现成功写入内核并且在time字段有值。这里的time值表示设置时间到1970年1月1日0点的秒，我们通过这个来判断当前时间是否在指定时间段内。

![](https://notes.sjtu.edu.cn/uploads/upload_dd20580d441e514048cede20d6896dcb.png)

在指定的时间段内发现ping网关ping不通。过了指定时间段之后又能ping通。

![](https://notes.sjtu.edu.cn/uploads/upload_20a2f138d1791f806bb0cac80f0e8e8d.png)


我们修改icmp规则，取消时间段限制，这时网关又不能够ping通。从内核接受和dump的icmp数据包也可以很好的展示结果。

![](https://notes.sjtu.edu.cn/uploads/upload_f27096ca963847f0fc68459262feb9e6.png)



## 6.4 UDP服务与删除功能
我们先ping baidu.com发现可以ping通。之后设置一条规则禁止UDP服务，导致无法与DNS通信来解析域名。
![](https://notes.sjtu.edu.cn/uploads/upload_8a75c5e0c0489d6b6144ff160636d746.png)

查看内核，发现规则已经成功添加。这里数据库规则和内核是保持高度一致的。
![](https://notes.sjtu.edu.cn/uploads/upload_405b726ff480018ca640107c9ecb8e2d.png)

然后ping百度会发现ping不通了，从内核中也可以看到udp的包都被dump掉了。
![](https://notes.sjtu.edu.cn/uploads/upload_60a44f43ccd67f0b6121404d79638961.png)

![](https://notes.sjtu.edu.cn/uploads/upload_90aaabc9b3cca57880439c4e27758972.png)

这里再修改相应的端口，把源端口改为1-100，目的端口改为20000-65535，用于测试端口是否有效。查看内核发现rule3保存成功。

![](https://notes.sjtu.edu.cn/uploads/upload_31996b2a90bd020831c5ab5c3a34185f.png)

这时候再ping baidu.com能够ping通，因为本机的端口不在管控范围内，证实端口控制有效。

![](https://notes.sjtu.edu.cn/uploads/upload_5613d7a8f90dce5181b7a219dc99294f.png)

将udp规则改回来，现在是不能ping通百度的。最后，我们将rule3删除，查看数据库和内核会发现rule3已经被清除。

![](https://notes.sjtu.edu.cn/uploads/upload_f47e2c03696e94b0d1f146dde4a40af9.png)
![](https://notes.sjtu.edu.cn/uploads/upload_14616f77b347415c066fb1cc9385790c.png)

这时再去ping百度发现能够ping通。
![](https://notes.sjtu.edu.cn/uploads/upload_7c21540b6b83b83d868280af1354b301.png)


# 七.项目小结
## 7.1 项目总结
总体来说，我们整个项目的进展和完成度还是非常的不错的，基本实现了初期的目标。我们最终实现了基于ip、端口、协议、时间的过滤规则，规则的增加修改删除，以及用户友好的GUI。我们组的开发节奏比较合理，前期实现了内核功能的基本框架，后期实现了GUI，同时穿插进行了内核和用户层的对接、内核功能的完善、GUI的润色。
项目的开发过程也让我们学到了很多的知识，包括数据库SQLite的使用，SQL语句的编写，计算机网络的知识，内核的运作逻辑等等，有一些新的技能的掌握也是非常有意义的，比如Qt的开发让我们能够在linux下开发GUI，又比如内核态下的编程，与用户态编程有着比较大的不同，再比如说Makefile的编写和使用等等。在debug过程中，我们也遇到了一些困难，比如说数据在应用层和内核之间的传递存在不一致，需要我们一步步溯源查找哪里出了问题。
## 7.2 项目展望
当然，我们的项目也有一些可以继续改进的地方：
* 实现多用户功能：由于时间关系，我们并没有完成多用户的功能，目前只能在内核运行单用户。
* 实现软件自启动：目前，我们需要先插入内核，再打开Qt软件运行，这样的话不够统一，用户体验也比较一般。我们可以实现软件启动时自动插入内核，同时解析数据库的规则，插入到内核中。这样能够与前面提到的多用户功能进行统一，在用户之间切换。

## 7.3 项目分工



| 成员   | 组长 | 工作               | 评分 |
| ------ | ---- | ------------------ | ---- |
| 蔡锶维 | √    | 完成内核功能的开发 | 100  |
| 张昊   |      | 完成桌面GUI的开发  | 100  |
|        |      | 完成数据库的搭建                   |      |

