#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab:

import sys
import re
import shutil
import os
import string
import argparse
from ipaddress import ip_address, ip_network
from collections import defaultdict
from datetime import datetime

config_local_network = "10.92.0.0/16"
config_public_networks = [
        "89.203.128.0/24",
        "89.203.138.0/24",
        "195.146.116.0/24",
]

# for debugging/development
config_prefix=""

config_qos_conf = "/etc/qos.conf"
config_nat_conf = "/etc/nat.conf"
config_nat_global = "/etc/nat_global.conf"
config_nat_up = "/etc/nat.up"
config_logfile = "/var/log/qos2nat.log"
config_nat_backup = "/etc/nat_backup/nat_conf_"
config_portmap = "/var/www/portmap.txt"

config_dns_db = "libcice.db.new"
config_dns_rev_db = "92.10.db.new"

config_dev_lan="eno1"
config_dev_wan="eno2"

logfile = None

def log(msg):
    if logfile:
        logfile.write(f"{msg}\n")

def logp(msg):
    print(msg)
    log(msg)

class ConfError(RuntimeError):
    """Unexpected content in conf file"""

class Hosts:

    def init_nat_conf(self):

        # from nat.conf
        self.pubip2user = dict()
        self.user2pubip = dict()
        self.ipuser2pubip = dict()
        self.ip2pubip = dict()
        self.ip2portfwd = defaultdict(set) # ip -> set((pubip, src, dst, user, comment))
        self.pubip_port2ip_port = dict() # (pubip, src) -> (ip, dst)

        # what nat.conf updates needed
        self.nat_conf_ips_to_delete = set()
        self.nat_conf_user2pubip_to_add = dict() # user -> pubip
        self.nat_conf_pubip2ip_to_add = defaultdict(set) # pubip -> ip
        self.nat_conf_ips_to_change = dict() # ip -> new_ip
        self.nat_conf_user_renames = dict() # ip -> (olduser, oldpubip, newuser)
        self.nat_conf_pubip_changes = dict() # ip -> (oldpubip, newpubip)

        self.free_public_ips = set(self.all_public_ips)

    def __init__(self):


        # from qos.conf
        self.ip2host = dict()
        self.host2ip = dict()
        self.ip2user = dict()
        self.user2ip = dict()
        self.user2shaping = dict()
        self.users = set()

        self.last_classid = 2089
        self.user2classid = dict()

        self.local_network = ip_network(config_local_network)
        self.all_public_ips = set()
        for net_str in config_public_networks:
            net = ip_network(net_str)
            self.all_public_ips.update(net.hosts())

        self.init_nat_conf()

    def get_classid(self):
        self.last_classid += 1
        return self.last_classid

    def add_qos(self, ip, host, user, shaping = None):
        if ip in self.ip2host:
            host_other = self.ip2host[ip]
            logp(f"Warning: Duplicate IP in qos.conf: {ip} is hosts {host_other} and {host}")
            ip_other = self.host2ip[host_other]
            user_other = self.ip2user[ip_other]
            if user != user_other:
                raise ConfError(f"Duplicate IP in qos.conf: {ip} belongs to users {user_other} and {user}")                
        else:
            self.ip2host[ip] = host

        if host in self.host2ip:
            ip_other = self.host2ip[host]
            user_other = self.ip2user[ip_other]
            logp(f"Warning: Duplicate hostname in qos.conf: {host} is IP {ip_other} (user {user_other}) "
                  f"and {ip} (user {user})")
        else:
            self.host2ip[host] = ip

        self.users.add(user)
        self.ip2user[ip] = user
        if shaping is not None:
            if user in self.user2shaping:
                raise ConfError(f"Multiple via-prometheus lines for user {user}: "
                                   f"{self.user2shaping[user]} and {shaping}")
            self.user2shaping[user] = shaping
            self.user2ip[user] = ip
            self.user2classid[user] = self.get_classid()
            
    def read_qos_conf(self, qosconf):

        line_num = 0
        for line in qosconf:
            line_num += 1
            # remove leading/trailing whitespace
            line = line.strip()

            # empty
            if line == "":
                continue

            # commented out
            m = re.match("#.*", line)
            if m:
                continue

            m = re.match(r"([0-9.]+)[ \t]+([\S]+)[ \t]+#([\S]+).*", line)
            if not m:
                raise ConfError(f"Error parsing qos.conf line {line_num}: {line}")

            (ip, host, shaping) = m.groups()

            try:
                ip = ip_address(ip)
            except ValueError as e:
                raise ConfError(f"Error parsing qos.conf line {line_num}: {e}")

            if host == 'loopback':
                continue

            if ip not in self.local_network:
                raise ConfError(f"Error parsing qos.conf line {line_num}: IP {ip} not in local network {self.local_network}")

            m = re.match(r"via-prometheus-([\S]+)", shaping)
            if m:
                user = host
                shaping = m.group(1)
            else:
                m = re.match(r"sharing-([\S]+)", shaping)
                if not m:
                    raiseConfError(f"Error parsing qos.conf line {line_num} - shaping not recognized: {shaping}")
                user = m.group(1)
                shaping = None

            try:
                self.add_qos(ip, host, user, shaping)
            except ConfError as e:
                raise ConfError(f"Error processing qos.conf line {line_num}: {e}")

        for user in self.users:
            if user not in self.user2shaping:
                logp(f"Warning: No shaping in qos.conf defined for user {user}")

    def add_nat_conf(self, pubip, ip, port_src, port_dst, user, comment):

        if port_src != "*" or port_dst != "*":
            try:
                port_src = int(port_src)
                if port_src < 1 or port_src > 65535:
                    raise ValueError()
            except ValueError:
                raise ConfError(f"invalid external port number {port_src}")
            try:
                port_dst = int(port_dst)
                if port_dst < 1 or port_dst > 65535:
                    raise ValueError()
            except ValueError:
                raise ConfError(f"invalid internal port number {port_dst}")

            self.ip2portfwd[ip].add((pubip, port_src, port_dst, user, comment))

            pubport = (pubip, port_src)
            locport = (ip, port_dst)
            if pubport in self.pubip_port2ip_port:
                other_locport = self.pubip_port2ip_port[pubport]
                if locport == other_locport:
                    logp(f"Warning: In nat.conf multiple lines with same port forward "
                          f"from public {pubip}:{port_src} to local {ip}:{port_dst}")
                else:
                    (other_ip, other_port_dst) = other_locport
                    raise ConfError(f"conflicting port forward from public {pubip}:{port_src} "
                                    f"to local {ip}:{port_dst} with previously seen local "
                                    f"{other_ip}:{other_port_dst}")
            else:
                self.pubip_port2ip_port[pubport] = locport
           
            self.free_public_ips.discard(pubip)
            return

        if ip in self.ip2pubip:
            pubip_other = self.ip2pubip[ip]
            if pubip != pubip_other:
                raise ConfError(f"local IP {ip} is translated to public IP {pubip} but also {pubip_other}")
        else:
            self.ip2pubip[ip] = pubip

        if ip in self.ip2user and user != self.ip2user[ip]:
            self.nat_conf_user_renames[ip] = (user, pubip, self.ip2user[ip])
            return

        if ip in self.ip2user:
            ipuser = self.ip2user[ip]
            if ipuser in self.ipuser2pubip:
                pubip_other = self.ipuser2pubip[ipuser]
                if pubip != pubip_other:
                    logp(f"Warning: In nat.conf {user} has public IP {pubip} but also {pubip_other}")
            else:
                self.ipuser2pubip[ipuser] = pubip
         
        if user in self.user2pubip:
            pubip_other = self.user2pubip[user]
            if pubip != pubip_other:
                logp(f"Warning: In nat.conf {user} has public IP {pubip} but also {pubip_other}")
        else:
            self.user2pubip[user] = pubip

        if pubip in self.pubip2user:
            user_other = self.pubip2user[pubip]
            if user != user_other:
                logp(f"Warning: In nat.conf public IP {pubip} assigned to user {user} but also {user_other}")
        else:
            self.pubip2user[pubip] = user

        self.free_public_ips.discard(pubip)
        
    def write_nat_conf_line(self, pubip, ip, port_src, port_dst, user, comment, natconf_new):
       
        if ip in self.nat_conf_ips_to_delete:
            return

        if ip in self.nat_conf_ips_to_change:
            ip = self.nat_conf_ips_to_change[ip]
        else:
            if ip in self.nat_conf_user_renames:
                (olduser, _, newuser) = self.nat_conf_user_renames[ip]
                if olduser == user:
                    user = newuser
            if ip in self.nat_conf_pubip_changes:
                (oldpubip, newpubip) = self.nat_conf_pubip_changes[ip]
                if oldpubip == pubip:
                    pubip = newpubip
        
        if pubip in self.nat_conf_pubip2ip_to_add:
            for new_ip in self.nat_conf_pubip2ip_to_add[pubip]:
                # we are adding new local IP to existing public IP, so write the line
                # next to existing line
                new_user = self.ip2user[new_ip]
                natconf_new.write(f"{pubip}\t{new_ip}\t*\t*\t# {new_user} added by script\n")
            del (self.nat_conf_pubip2ip_to_add[pubip])
 
        natconf_new.write(f"{pubip}\t{ip}\t{port_src}\t{port_dst}\t# {user}{comment}\n")
        
    def read_nat_conf(self, natconf, natconf_new=None):

        line_num = 0
        for line in natconf:
            line_num += 1

            # remove leading/trailing whitespace
            #line = line.strip()

            m = re.match(r"([0-9.]+)[ \t]+([0-9.]+)[ \t]+([0-9*]+)[ \t]([0-9*]+)[ \t]# ([\S]+)(.*)", line)
            if not m:
                raise ConfError(f"Error parsing nat.conf line {line_num}: {line}")
            
            (pubip, ip, port_src, port_dst, user, comment) = m.groups()

            try:
                pubip = ip_address(pubip)
                ip = ip_address(ip)
            except ValueError as e:
                raise ConfError(f"Error parsing nat.conf line {line_num}: {e}")

            if ip not in self.local_network:
                raise ConfError(f"Error parsing nat.conf line {line_num}: local IP {ip} not in local network {self.local_network}")

            if pubip not in self.all_public_ips:
                raise ConfError(f"Error parsing nat.conf line {line_num}: public IP {pubip} not in libcice.net ranges")
           
            if natconf_new:
                self.write_nat_conf_line(pubip, ip, port_src, port_dst, user, comment, natconf_new) 
            else:
                try:
                    self.add_nat_conf(pubip, ip, port_src, port_dst, user, comment)
                except ConfError as e:
                    raise ConfError(f"Error parsing nat.conf line {line_num}: {e}")

        # check for port forwards from public IPs that are not fully assigned to a user's private IP
        for (pubip, port_src) in self.pubip_port2ip_port:
            if pubip not in self.pubip2user:
                (ip, port_dst) = self.pubip_port2ip_port[(pubip, port_src)]
                # if the public ip is changing, don't warn 
                if ip in self.nat_conf_pubip_changes:
                    continue
                user = self.ip2user[ip]
                logp(f"Warning: port forward for unassigned public IP {pubip}:{port_src} to {ip}:{port_dst} (user {user})")
                    

    def update_nat_conf(self, natconf_old, natconf_new):

        self.read_nat_conf(natconf_old, natconf_new)

        for (pubip, list_ip) in self.nat_conf_pubip2ip_to_add.items():
            for ip in list_ip:
                user = self.ip2user[ip]
                natconf_new.write(f"{pubip}\t{ip}\t*\t*\t# {user} added by script\n")

    def get_new_public_ip(self, user):
        if len(self.free_public_ips) == 0:
            raise ConfError(f"Need new public IP for user {user}, but none left.")
        pubip = self.free_public_ips.pop()
        return pubip

    def find_differences(self):

        found = 0

        for ip in self.ip2pubip:
            if ip not in self.ip2host:
                found += 1
                fwds = ""
                if ip in self.ip2portfwd:
                    fwds = f", including {len(self.ip2portfwd[ip])} defined port forwards"
                pubip = self.ip2pubip[ip]
                user = self.pubip2user[pubip]
                if user in self.user2ip:
                    newIp = self.user2ip[user]
                    if newIp not in self.ip2pubip:
                        logp(f"User {user} (public IP {pubip}): changing primary local IP from {ip} to {newIp}{fwds}")
                        self.nat_conf_ips_to_change[ip] = newIp
                        continue
                logp(f"User {user} (public IP {pubip}): removing local IP {ip}{fwds}")
                self.nat_conf_ips_to_delete.add(ip)
            elif ip in self.nat_conf_user_renames:
                found += 1
                (olduser, oldpubip, newuser) = self.nat_conf_user_renames[ip]
                ipchange = ""
                # qos.conf line changed from user that still exists, or to user that already exists, so change public IP
                if olduser in self.user2ip or newuser in self.user2pubip:
                    if newuser in self.user2pubip:
                        newpubip = self.user2pubip[newuser]
                    elif newuser in self.nat_conf_user2pubip_to_add:
                        newpubip = self.nat_conf_user2pubip_to_add[user]
                    else:
                        newpubip = self.get_new_public_ip(newuser)
                        self.nat_conf_user2pubip_to_add[newuser] = newpubip
                        
                    ipchange = f" and changing public IP {oldpubip} to {newpubip}"
                    self.nat_conf_pubip_changes[ip] = (oldpubip, newpubip)
                fwds = 0
                if ip in self.ip2portfwd:
                    for (fwdpubip, _, _, _, _,) in self.ip2portfwd[ip]:
                        if fwdpubip == oldpubip:
                            fwds += 1
                if fwds == 0:
                    fwdstr = ""
                else:
                    fwdstr = f", including {fwds} defined port forwards"
                logp(f"Renaming user {olduser} to {newuser} for IP {ip}{ipchange}{fwdstr}")

        for ip in self.ip2host:
            if ip not in self.ip2pubip:
                found += 1
                if ip in self.nat_conf_ips_to_change.values():
                    continue
                host = self.ip2host[ip]
                user = self.ip2user[ip]
                if user in self.user2ip and self.user2ip[user] in self.ip2pubip:
                    pubip = self.ip2pubip[self.user2ip[user]]
                    info = f"with existing user's public IP {pubip}"
                elif user in self.nat_conf_user2pubip_to_add:
                    pubip = self.nat_conf_user2pubip_to_add[user]
                    info = f"with pending new user's public IP {pubip}"
                else:
                    pubip = self.get_new_public_ip(user)
                    self.nat_conf_user2pubip_to_add[user] = pubip
                    info = f"with new user's public IP {pubip}"
                    
                logp(f"User {user}: adding local IP {ip} (host {host}) {info}")
                self.nat_conf_pubip2ip_to_add[pubip].add(ip)
        return found

    def write_nat_up(self, nat_up):

        localnet = self.local_network.with_netmask

        for (ip, pubip) in self.ip2pubip.items():
            nat_up.write(f"-A POSTROUTING -s {ip} ! -d {localnet} -j SNAT --to-source {pubip} \n")

            if not ip in self.ip2portfwd:
                continue

            for (pubip, pub_port, loc_port, _, _) in self.ip2portfwd[ip]:
                for proto in ("tcp", "udp"):
                    nat_up.write(f"-A PREROUTING -d {pubip} -p {proto} -m {proto} --dport {pub_port} "
                                 f"-j DNAT --to-destination {ip}:{loc_port}\n")

        nat_up.write("COMMIT\n")

    def write_portmap(self, portmap):

        for (ip, pubip) in self.ip2pubip.items():
            
            if not ip in self.ip2portfwd:
                continue

            for (pubip, pub_port, loc_port, user, comment) in self.ip2portfwd[ip]:
                portmap.write(f"{pubip}\t{ip}\t{pub_port}\t{loc_port}\t# {user}{comment}\n")

    def write_dns_hosts(self, db):
        for (ip, host) in sorted(self.ip2host.items(), key = lambda item: item[1]):
            host = host.replace("_", "-")
            db.write(f"{host:<25} IN A            {ip}\n")

    def write_dns_reverse(self, db):
        current_net = None
        for (ip, host) in sorted(self.ip2host.items(), key = lambda item: item[0]):
            if not current_net or ip not in current_net:
                current_net = ip_network(ip).supernet(new_prefix=24)
                ipp = current_net.network_address.packed
                db.write(";##################################################\n")
                db.write(f"$ORIGIN               {ipp[2]}.{ipp[1]}.{ipp[0]}.in-addr.arpa.\n")
            host = host.replace("_", "-")
            db.write(f"{ip.packed[3]:<14} IN PTR          {host}.libcice.czf.\n")

    def write_iptables_mangle(self, out):
        out.write("*mangle\n")
        out.write(":PREROUTING ACCEPT [0:0]\n")
        out.write(":POSTROUTING ACCEPT [0:0]\n")
        out.write(":INPUT ACCEPT [0:0]\n")
        out.write(":OUTPUT ACCEPT [0:0]\n")
        out.write(":FORWARD ACCEPT [0:0]\n")
        # TODO config
        out.write(f"-A FORWARD -d 10.0.0.0/8 -o {config_dev_wan} -j ACCEPT\n")
        out.write(f"-A POSTROUTING -s 10.0.0.0/8 -o eno1 -j ACCEPT\n")

        for (ip, user) in self.ip2user.items():
            if user not in self.user2classid:
                print (f"skip ip {ip} of user {user} due to no defined shaping")
                continue
            classid = self.user2classid[user]
            post = f"-A POSTROUTING -d {ip} -o {config_dev_lan}"
            forw = f"-A FORWARD -s {ip} -o {config_dev_wan}"
            for match in (post, forw):
                out.write(f"{match} -j CLASSIFY --set-class 1:{classid}\n")
                out.write(f"{match} -j ACCEPT\n")

        out.write(f"-A POSTROUTING -o {config_dev_lan} -j CLASSIFY --set-class 1:3\n")
        out.write(f"-A POSTROUTING -o {config_dev_lan} -j ACCEPT\n")
        out.write(f"-A FORWARD -o {config_dev_wan} -j CLASSIFY --set-class 1:3\n")
        out.write(f"-A FORWARD -o {config_dev_wan} -j ACCEPT\n")
        out.write("COMMIT\n")

    def write_tc(self.out):
        for dev in (config_dev_lan, config_dev_wan):
            out.write(f"qdisc add dev {dev} root handle 1: htb r2q 5 default 1\n")
            out.write(f"class add dev {dev} parent 1: classid 1:2 htb rate 1000Mbit ceil 1000Mbit burst 1300k cburst 1300k prio 0 quantum 20000\n")
            out.write(f"class add dev {dev} parent 1:2 classid 1:1 htb rate 950000kbit ceil 950000kbit burst 1300k cburst 1300k prio 0 quantum 20000\n")
            


hosts = Hosts()
logfile = None

parser = argparse.ArgumentParser()
parser.add_argument("--dns", help=f"generate dns files {config_dns_db} and {config_dns_rev_db} instead of nat",\
                    action="store_true")
parser.add_argument("qos_conf", help=f"qos.conf location, default is {config_qos_conf}",\
                    nargs='?', default=f"{config_prefix}{config_qos_conf}")
parser.add_argument("--devel", help=f"development run, prefix all paths with local directory, don't execute iptables",\
                    action="store_true")
args = parser.parse_args()

if args.devel:
    config_prefix="."

qos_conf_path=f"{config_prefix}{args.qos_conf}"

if args.dns:
    try:
        print(f"Reading {qos_conf_path} ...")
        with open(qos_conf_path, 'r') as qosconf:
            hosts.read_qos_conf(qosconf)

        print(f"Writing {config_dns_db}")
        with open(config_dns_db, 'w') as db:
            hosts.write_dns_hosts(db)

        print(f"Writing {config_dns_rev_db}")
        with open(config_dns_rev_db, 'w') as db:
            hosts.write_dns_reverse(db)

        sys.exit(0)
    except ConfError as e:
        logp(e)
        sys.exit(1)

try:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    logfile = open(f"{config_prefix}{config_logfile}", 'a')
    
    log(f"Start qos2nat.py {timestamp}")

    logp(f"Reading {qos_conf_path} ...")
    with open(qos_conf_path, 'r') as qosconf:
        hosts.read_qos_conf(qosconf)

    nat_conf_pre = f"{config_prefix}{config_nat_backup}{timestamp}_pre"

    logp(f"Creating nat.conf backup {nat_conf_pre}")
    shutil.copyfile(f"{config_prefix}{config_nat_conf}", nat_conf_pre)

    logp("Reading nat.conf...")
    with open(f"{nat_conf_pre}", 'r') as natconf:
        hosts.read_nat_conf(natconf)

    logp("Calculating nat.conf updates:")
    diffs = hosts.find_differences()
    if diffs > 0:
        nat_conf_post = f"{config_prefix}{config_nat_backup}{timestamp}_post"
        logp(f"Writing {nat_conf_post} with {diffs} updates...")
        with open(nat_conf_pre, 'r') as natconf, open(nat_conf_post, 'w') as natconf_new:
            hosts.update_nat_conf(natconf, natconf_new)

        logp("Reading nat.conf.new back to verify no more updates detected...")
        hosts.init_nat_conf()
        with open(nat_conf_post, 'r') as natconf:
            hosts.read_nat_conf(natconf)

        diffs = hosts.find_differences()
        if diffs > 0:
            logp(f"Found {diffs} more unexpected updates, aborting.")
            sys.exit(1)
        else:
            logp(f"No differences, replacing nat.conf with {nat_conf_post}")
            shutil.copyfile(nat_conf_post, f"{config_prefix}{config_nat_conf}")
    else:
        logp("No updates needed")

    logp("Generating nat.up...")
    nat_up_name = f"{config_prefix}{config_nat_up}"
    with open(f"{config_prefix}{config_nat_global}", 'r') as nat_global, open(nat_up_name, 'w') as nat_up:
        nat_up.write("# generated by qos2nat.py\n")
        for line in nat_global:
            nat_up.write(line)
        hosts.write_nat_up(nat_up)

    logp("Generating portmap.txt...")
    with open(f"{config_prefix}{config_portmap}", 'w') as portmap:
        hosts.write_portmap(portmap)

    if not args.devel:
        logp("Loading new nat.up to iptables")
        ret = os.system(f"/usr/sbin/iptables-restore {nat_up_name}")
    else:
        logp("Skipping iptables-restore due to --devel")
        ret = 0

    if ret != 0:
        logp(f"Error {ret} when executing iptables-restore") 
    else:
        logp(f"Done. Number of users: {len(hosts.users)}, number of local IPs: {len(hosts.ip2host)}, "
             f"remaining public IPs: {len(hosts.free_public_ips)}")

    print("Writing mangle.up...")
    with open("mangle.up", 'w') as mangle:
        hosts.write_iptables_mangle(mangle)

except ConfError as e:
    logp(e)
    sys.exit(1)
finally:
    if logfile:
        logfile.close()

