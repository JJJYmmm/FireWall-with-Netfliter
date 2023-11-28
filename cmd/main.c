#include "contact.h"

// 新增过滤规则时的用户交互
struct KernelResponse cmdAddRule(char* argv[]) {
    // command format : 3:args.name, 4:args.position, 5:args.protocol,
    // 6:args.source_ip, 7:args.source_port, 8:args.dest_ip, 9:args.dest_port,
    // 10:args.act,args.log
    struct KernelResponse empty;
    char after[MAXRuleNameLen + 1], name[MAXRuleNameLen + 1], saddr[25],
        daddr[25], sport[15], dport[15], protoS[6];
    unsigned short sportMin, sportMax, dportMin, dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i;
    empty.code = ERROR_CODE_EXIT;
    // 前序规则名
    if (argv[4][0] == '-' && argv[4][1] == '1' && argv[4][2] == '\0')
        after[0] = '\0';
    else
        memcpy(after, argv[4], sizeof(after));
    // 规则名
    memcpy(name, argv[3], sizeof(name));
    if (strlen(name) == 0 || strlen(name) > MAXRuleNameLen) {
        printf("name too long or too short.\n");
        return empty;
    }
    // 源IP
    memcpy(saddr, argv[6], sizeof(saddr));
    // 源端口
    memcpy(sport, argv[7], sizeof(sport));
    if (strcmp(sport, "any") == 0) {
        sportMin = 0, sportMax = 0xFFFFu;
    } else {
        sscanf(sport, "%hu-%hu", &sportMin, &sportMax);
    }
    if (sportMin > sportMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    // 目的IP
    memcpy(daddr, argv[8], sizeof(daddr));
    // 目的端口
    memcpy(dport, argv[9], sizeof(dport));
    if (strcmp(dport, "any") == 0) {
        dportMin = 0, dportMax = 0xFFFFu;
    } else {
        sscanf(dport, "%hu-%hu", &dportMin, &dportMax);
    }
    if (dportMin > dportMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    // 协议
    memcpy(protoS, argv[5], sizeof(protoS));
    if (strcmp(protoS, "TCP") == 0)
        proto = IPPROTO_TCP;
    else if (strcmp(protoS, "UDP") == 0)
        proto = IPPROTO_UDP;
    else if (strcmp(protoS, "ICMP") == 0)
        proto = IPPROTO_ICMP;
    else if (strcmp(protoS, "any") == 0)
        proto = IPPROTO_IP;
    else {
        printf("This protocol is not supported.\n");
        return empty;
    }
    // 动作
    if (argv[10][0] == 'a')
        action = 1;
    else
        action = 0;
    // 是否记录日志
    if (argv[11][0] == 'y')
        log = 1;
    else
        log = 0;
    return addFilterRule(
        after, name, saddr, daddr,
        (((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
        (((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),
        proto, log, action);
}

struct KernelResponse cmdAddNATRule(char* argv[]) {
    // command format :
    //  '{} nat add {} {} {}'.format( 0:app_name, 3:args.nat_sip,
    //  4:args.nat_dip, 5:args.nat_port)
    struct KernelResponse empty;
    char saddr[25], daddr[25], port[15];
    unsigned short portMin, portMax;
    empty.code = ERROR_CODE_EXIT;
    // 源IP
    memcpy(saddr, argv[3], sizeof(saddr));
    // NAT IP
    memcpy(daddr, argv[4], sizeof(daddr));
    // 目的端口
    memcpy(port, argv[5], sizeof(port));
    if (strcmp(port, "any") == 0) {
        portMin = 0, portMax = 0xFFFFu;
    } else {
        sscanf(port, "%hu-%hu", &portMin, &portMax);
    }
    if (portMin > portMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    return addNATRule(saddr, daddr, portMin, portMax);
}

void wrongCommand() {
    printf("wrong command.\n");
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        // addRule("","rj","192.168.80.138","47.100.10.21",-1,-1,IPPROTO_ICMP,1,NF_DROP);
        // addNATRule("192.168.60.2", "192.168.80.139",20000,35535);
        wrongCommand();
        return 0;
    }
    struct KernelResponse rsp;
    rsp.code = ERROR_CODE_EXIT;
    // 过滤规则相关
    if (strcmp(argv[1], "rule") == 0 || argv[1][0] == 'r') {
        if (strcmp(argv[2], "ls") == 0 || strcmp(argv[2], "list") == 0) {
            // 列出所有过滤规则
            rsp = getAllFilterRules();
        } else if (strcmp(argv[2], "del") == 0) {
            // 删除过滤规则
            if (argc < 4)
                printf("Please input rule name.\n");
            else if (strlen(argv[3]) > MAXRuleNameLen)
                printf("rule name too long!");
            else
                rsp = delFilterRule(argv[3]);
        } else if (strcmp(argv[2], "add") == 0) {
            // 添加过滤规则
            rsp = cmdAddRule(argv);
        } else if (strcmp(argv[2], "default") == 0) {
            // 设置默认规则
            if (argc < 4)
                printf("Input default action in option.\n");
            else if (strcmp(argv[3], "accept") == 0)
                rsp = setDefaultAction(NF_ACCEPT);
            else if (strcmp(argv[3], "deny") == 0)
                rsp = setDefaultAction(NF_DROP);
            else
                printf("Wrong Operation. \"accept\" or \"deny\".\n");
        } else
            wrongCommand();
    } else if (strcmp(argv[1], "nat") == 0 || argv[1][0] == 'n') {
        if (strcmp(argv[2], "ls") == 0 || strcmp(argv[2], "list") == 0) {
            // 列出所有NAT规则
            rsp = getAllNATRules();
        } else if (strcmp(argv[2], "del") == 0) {
            // 删除NAT规则
            if (argc < 4)
                printf("Input nat number in option.\n");
            else {
                int num;
                sscanf(argv[3], "%d", &num);
                rsp = delNATRule(num);
            }
        } else if (strcmp(argv[2], "add") == 0) {
            // 添加NAT规则
            rsp = cmdAddNATRule(argv);
        } else {
            wrongCommand();
        }
    } else if (strcmp(argv[1], "ls") == 0 || argv[1][0] == 'l') {
        // 展示相关
        if (strcmp(argv[2], "log") == 0 || argv[2][0] == 'l') {
            // 过滤日志
            unsigned int num = 0;
            if (argc > 3)
                sscanf(argv[3], "%u", &num);
            rsp = getLogs(num);
        } else if (strcmp(argv[2], "con") == 0 || argv[2][0] == 'c') {
            // 连接状态
            rsp = getAllConns();
        } else if (strcmp(argv[2], "rule") == 0 || argv[2][0] == 'r') {
            // 已有过滤规则
            rsp = getAllFilterRules();
        } else if (strcmp(argv[2], "nat") == 0 || argv[2][0] == 'n') {
            // 已有NAT规则
            rsp = getAllNATRules();
        } else
            wrongCommand();
    } else
        wrongCommand();
    dealResponseAtCmd(rsp);
}

