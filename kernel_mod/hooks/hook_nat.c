#include "helper.h"
#include "hook.h"
#include "tools.h"

// modify!!!
unsigned int hook_nat_in_hj(void* priv,
                            struct sk_buff* skb,
                            const struct nf_hook_state* state) {
    printk("nat_in\n");
    struct NATRecord* record;
    unsigned short sport, dport;
    unsigned int sip, dip;
    u_int8_t proto;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    int hdr_len, tot_len, isMatch;
    // 初始化
    struct iphdr* header = ip_hdr(skb);
    getPort(skb, header, &sport, &dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;

    // modify!!!
    // magic number 3232277504 = IPstr2IPint('192.168.164.0')
    // magic number2 4294967040 = IPstr2IPint('255.255.255.0')
    // 如果源ip来自内网192.168.164.0, 不需要做hook_nat_in操作
    if ((sip & (unsigned int)4294967040) == (unsigned int)3232277504) {
        return NF_ACCEPT;
    }

    // find record here, modify!!!
    record = matchNATRule_hj(sip, dip, dport, &isMatch);
    if (!isMatch || record == NULL) {  // 不符合NAT规则，无需NAT
        return NF_ACCEPT;
    }
    if (record != NULL) {
        // printk("nat_in\n");
        // printk("%u\n",record->saddr);
        // printk("%u\n",record->daddr);
        // printk("%hu\n",record->sport);
        // printk("%hu\n",record->dport);
    }
    header->daddr = htonl(record->saddr);  // modify
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    switch (proto) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)(skb->data + (header->ihl * 4));
            tcpHeader->dest = htons(record->sport);  // modify
            tcpHeader->check = 0;
            skb->csum =
                csum_partial((unsigned char*)tcpHeader, tot_len - hdr_len, 0);
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                                 tot_len - hdr_len,
                                                 header->protocol, skb->csum);
            break;
        case IPPROTO_UDP:
            udpHeader = (struct udphdr*)(skb->data + (header->ihl * 4));
            udpHeader->dest = htons(record->sport);  // modify
            udpHeader->check = 0;
            skb->csum =
                csum_partial((unsigned char*)udpHeader, tot_len - hdr_len, 0);
            udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                                 tot_len - hdr_len,
                                                 header->protocol, skb->csum);
            break;
        case IPPROTO_ICMP:
        default:
            break;
    }
    return NF_ACCEPT;
}

unsigned int hook_nat_out(void* priv,
                          struct sk_buff* skb,
                          const struct nf_hook_state* state) {
    printk("nat_out\n");
    struct connNode *conn, *reverseConn;
    struct NATRecord record;
    int isMatch, hdr_len, tot_len;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    u_int8_t proto;
    unsigned int sip, dip;
    unsigned short sport, dport;

    // 初始化
    struct iphdr* header = ip_hdr(skb);
    getPort(skb, header, &sport, &dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;

    // modify!!!
    // magic number 3232277504 = IPstr2IPint('192.168.164.0')
    // magic number2 4294967040 = IPstr2IPint('255.255.255.0')
    // 如果源ip不在内网192.168.164.0, 不需要做hook_nat_out操作
    if ((sip & (unsigned int)4294967040) != (unsigned int)3232277504) {
        return NF_ACCEPT;
    }

    // 查连接池 NAT_TYPE_SRC
    conn = hasConn(sip, dip, sport, dport);
    // reverse lookup modify!!!
    if (conn == NULL) {
        conn = hasConn(dip, sip, dport, sport);
    }
    if (conn == NULL) {  // 不应出现连接表中不存在的情况
        printk(KERN_WARNING
               "[fw nat] (out)get a connection that is not in the connection "
               "pool!\n");
        return NF_ACCEPT;
    }
    // 确定NAT记录
    if (conn->natType == NAT_TYPE_SRC) {  // 已有
        record = conn->nat;
    } else {
        unsigned short newPort = 0;
        struct NATRecord* rule = matchNATRule(sip, dip, &isMatch);
        if (!isMatch || rule == NULL) {  // 不符合NAT规则，无需NAT
            return NF_ACCEPT;
        }
        // 新建NAT记录
        if (sport != 0) {
            newPort = getNewNATPort(*rule);
            rule->sport = sport;  // modify here U202012007!!!
            rule->dport = newPort;
            if (newPort == 0) {  // 获取新端口失败，放弃NAT
                printk(KERN_WARNING "[fw nat] get new port failed!\n");
                return NF_ACCEPT;
            }
        }
        record = genNATRecord(sip, rule->daddr, sport, newPort);
        // 记录在原连接中
        // printk("nat_out\n");
        // printk("%u\n",record.saddr);
        // printk("%u\n",record.daddr);
        // printk("%hu\n",record.sport);
        // printk("%hu\n",record.dport);
        setConnNAT(conn, record, NAT_TYPE_SRC);
        rule->nowPort = newPort;
    }
    // modify!!!
    // // 寻找反向连接 modify!!!
    // reverseConn = hasConn(dip, record.daddr, dport, record.dport);
    // if (reverseConn == NULL) {  // 新建反向连接入连接池
    //     reverseConn = addConn(dip, record.daddr, dport, record.dport, proto,
    //     0); if (reverseConn == NULL) {  // 创建反向连接失败，放弃NAT
    //         printk(KERN_WARNING "[fw nat] add reverse connection failed!\n");
    //         return NF_ACCEPT;
    //     }
    //     setConnNAT(reverseConn,
    //                genNATRecord(record.daddr, sip, record.dport, sport),
    //                NAT_TYPE_DEST);
    // }
    // addConnExpires(reverseConn, CONN_EXPIRES * CONN_NAT_TIMES);  //
    // 更新超时时间
    addConnExpires(conn, CONN_EXPIRES * CONN_NAT_TIMES);  // 更新超时时间
    // 转换源地址+端口
    header->saddr = htonl(record.daddr);
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    switch (proto) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr*)(skb->data + (header->ihl * 4));
            tcpHeader->source = htons(record.dport);
            tcpHeader->check = 0;
            skb->csum =
                csum_partial((unsigned char*)tcpHeader, tot_len - hdr_len, 0);
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                                 tot_len - hdr_len,
                                                 header->protocol, skb->csum);
            break;
        case IPPROTO_UDP:
            udpHeader = (struct udphdr*)(skb->data + (header->ihl * 4));
            udpHeader->source = htons(record.dport);
            udpHeader->check = 0;
            skb->csum =
                csum_partial((unsigned char*)udpHeader, tot_len - hdr_len, 0);
            udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                                 tot_len - hdr_len,
                                                 header->protocol, skb->csum);
            break;
        case IPPROTO_ICMP:
        default:
            break;
    }
    return NF_ACCEPT;
}
