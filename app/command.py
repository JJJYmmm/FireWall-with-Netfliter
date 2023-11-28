import commands
import argparse

# global var
app_name = './myfw'

# parse command line arguments
def get_parse():
    parser = argparse.ArgumentParser(description='command for my firewall')

    # operation and object
    parser.add_argument('--object', type=str, help='operating object, eg. rule, nat, log', choices=['rule', 'nat', 'log','conn'], required=True)
    parser.add_argument('--op', type=str, help='operation to the object, eg. show, add, delete', choices=['show', 'add', 'del', 'default'], required=True)

    # general options 
    parser.add_argument('--source_ip', type=str, help='source IP address with subnet mask, default: 192.168.164.2/24', default = "192.168.164.2/24")
    parser.add_argument('--source_port', type=str, help='source port, eg. 80-80, default: any', default = "any") 
    parser.add_argument('--dest_ip', type=str, help='destination IP address with subnet mask, default: 192.168.152.2/24', default="192.168.152.2/24")
    parser.add_argument('--dest_port', type=str, help='dest port, eg. 80-80, default: any', default = "any") 

    # rules
    parser.add_argument('--name', type=str, help='rule name', default='default')
    parser.add_argument('--position', type=str, help='rule position in list, before xxx(your input)', default='-1')
    parser.add_argument('--protocol', type=str, help='protocol, eg. TCP,UDP,ICMP,any', choices=['TCP', 'UDP', 'ICMP','any'], default='any')
    parser.add_argument('--act', type=str, help='action, accpet or deny', choices=['accept', 'deny'], default='deny')
    parser.add_argument('--def_act', type=str, help='default action, accpet or deny', choices=['accept', 'deny'], default='deny')
    parser.add_argument('--log', type=str, help='whether to log, yes or not', choices=['yes', 'not'], default='yes')

    # log
    parser.add_argument('--log_num', type=int, help='line number of showed log', default=100)

    # nat
    parser.add_argument('--nat_num', type=int, help='nat number', default=0)
    parser.add_argument('--nat_sip', type=str, help='nat source IP address with subnet mask, default: 192.168.164.2/24', default = "192.168.164.2/24")
    parser.add_argument('--nat_dip', type=str, help='nat IP address, default: 192.168.80.80', default = "192.168.80.80")
    parser.add_argument('--nat_port', type=str, help='nat port, eg. 80-80, default: any', default = "any") 

    return parser

# print msg
def print_msg(cmd):
    msg = commands.getoutput(cmd)
    print(msg)


if __name__ == '__main__':
    parser = get_parse()
    args = parser.parse_args()
    # rule
    if args.object == 'rule':
        if args.op == 'show':
            print_msg('{} ls rule'.format(app_name))
        if args.op == 'add':
            print_msg('{} rule add {} {} {} {} {} {} {} {} {}'.format(app_name,args.name,args.position,args.protocol,args.source_ip,args.source_port,args.dest_ip,args.dest_port,args.act,args.log))
        if args.op == 'del':
            print_msg('{} rule del {}'.format(app_name,args.name))
        if args.op == 'default':
            print_msg('{} rule default {}'.format(app_name,args.def_act))

    # nat
    if args.object == 'nat':
        if args.op == 'show':
            print_msg('{} ls nat'.format(app_name))
        if args.op == 'add':
            print_msg('{} nat add {} {} {}'.format(app_name,args.nat_sip,args.nat_dip,args.nat_port))
        if args.op == 'del':
            print_msg('{} nat del {}'.format(app_name,args.nat_num))

    # log
    if args.object == 'log':
        if args.op == 'show':
            print_msg('{} ls log {}'.format(app_name,args.log_num))

    # conn
    if args.object == 'conn':
        if args.op == 'show':
            print_msg('{} ls connection'.format(app_name))

