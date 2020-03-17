#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab:

import sys
import re
import shutil
import string
import argparse
import subprocess
import tempfile
from ipaddress import ip_address, ip_network
from collections import defaultdict
import time
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

config_html_preview = "/var/www/today.html"
config_html_day = "/var/www/yesterday.html"
config_logdir = "/var/www/logs/"

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

def td(content):
    return f"<td>{content}</td>"

def tdr(content):
    return f"<td align=\"right\">{content}</td>"

def tr(tds):
    content = ''.join(tds)
    return f"<tr>{content}</tr>\n"

def human(val):
    if val < 1024:
        return str(val)
    val //= 1024

    if val < 1024:
        return f"{val} KB"

    val //= 1024
    if val < 1024:
        return f"{val} MB"

    return f"{val//1024} GB"

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

        # from iptables stats
        self.ip2download = dict()
        self.ip2upload = dict()
        self.ip2traffic = defaultdict(int)

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

            m = re.match(r"via-prometheus-([0-9]+)-([0-9]+)", shaping)
            if m:
                user = host
                shaping = (int(m.group(1)), int(m.group(2)))
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

    def write_nat_up_nft(self, nat_up):

        localnet = self.local_network

        nat_up.write("add map ip nat snat_map { type ipv4_addr : ipv4_addr; }\n")

        for (ip, pubip) in self.ip2pubip.items():
            nat_up.write(f"add element ip nat snat_map {{ {ip} : {pubip} }}\n")

            if not ip in self.ip2portfwd:
                continue

            for (pubip, pub_port, loc_port, _, _) in self.ip2portfwd[ip]:
                for proto in ("tcp", "udp"):
                    nat_up.write(f"add rule ip nat PREROUTING ip daddr {pubip} {proto} dport {pub_port} "
                                 f"dnat to {ip}:{loc_port}\n")
    
        nat_up.write(f"add rule ip nat POSTROUTING ip daddr != {localnet} snat ip saddr map @snat_map\n")

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

    def write_nft_mangle(self, out):
        out.write("flush table ip mangle\n")
        out.write("add table ip mangle\n")

        out.write("add map ip mangle forw_map { type ipv4_addr : verdict; }\n")
        out.write("add map ip mangle post_map { type ipv4_addr : verdict; }\n")

        for (ip, user) in self.ip2user.items():
            if user not in self.user2classid:
                print (f"skip ip {ip} of user {user} due to no defined shaping")
                continue
            classid = self.user2classid[user]
           
            ipstr = str(ip).replace(".", "_")
            for prefix in ("post", "forw"):
                out.write(f"add chain ip mangle {prefix}_{ipstr}\n")
                out.write(f"add rule ip mangle {prefix}_{ipstr} counter packets 0 bytes 0 meta priority set 1:{classid} accept\n")
                out.write(f"add element ip mangle {prefix}_map {{ {ip} : goto {prefix}_{ipstr} }}\n")
            
        out.write("add chain ip mangle forw_common\n")
        out.write("add rule ip mangle forw_common counter packets 0 bytes 0 meta priority set 1:3 accept\n")
        
        out.write("add chain ip mangle post_common\n")
        out.write("add rule ip mangle post_common counter packets 0 bytes 0 meta priority set 1:3 accept\n")
        out.write("add chain ip mangle forward { type filter hook forward priority -150; policy accept; }\n")
        out.write(f"add rule ip mangle forward oifname \"{config_dev_wan}\" ip daddr 10.0.0.0/8 counter packets 0 bytes 0 accept\n")
        out.write(f"add rule ip mangle forward oifname \"{config_dev_wan}\" ip saddr vmap @forw_map\n")
        out.write(f"add rule ip mangle forward oifname \"{config_dev_wan}\" counter packets 0 bytes 0 jump forw_common\n")

        out.write("add chain ip mangle postrouting { type filter hook postrouting priority -150; policy accept; }\n")
        out.write(f"add rule ip mangle postrouting oifname \"{config_dev_lan}\" ip saddr 10.0.0.0/8 counter packets 0 bytes 0 accept\n")
        out.write(f"add rule ip mangle postrouting oifname \"{config_dev_lan}\" ip daddr vmap @post_map\n")
        out.write(f"add rule ip mangle postrouting oifname \"{config_dev_lan}\" counter packets 0 bytes 0 jump post_common\n")


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

    def write_tc_up(self, out):
        for dev in (config_dev_lan, config_dev_wan):
            out.write(f"qdisc add dev {dev} root handle 1: htb r2q 5 default 1\n")
            out.write(f"class add dev {dev} parent 1: classid 1:2 htb rate 1000Mbit ceil 1000Mbit burst 1300k cburst 1300k prio 0 quantum 20000\n")
            out.write(f"class add dev {dev} parent 1:2 classid 1:1 htb rate 950000kbit ceil 950000kbit burst 1300k cburst 1300k prio 0 quantum 20000\n")
            out.write(f"class add dev {dev} parent 1:1 classid 1:1025 htb rate 950000kbit ceil 950000kbit burst 1300k cburst 1300k prio 1 quantum 20000\n")

        for (user, shaping) in self.user2shaping.items():
            (rate, ceil) = shaping
            classid = self.user2classid[user]
            for dev in (config_dev_lan, config_dev_wan):
                out.write(f"class add dev {dev} parent 1:1025 classid 1:{classid} htb rate {rate}kbit ceil {ceil}kbit burst 256k cburst 256k prio 1 quantum 1500\n")
                out.write(f"qdisc add dev {dev} parent 1:{classid} handle {classid} fq_codel\n")

        for dev in (config_dev_lan, config_dev_wan):
            out.write(f"class add dev {dev} parent 1:1025 classid 1:3 htb rate 64kbit ceil 128kbit burst 256k cburst 256k prio 7 quantum 1500\n")
            out.write(f"qdisc add dev {dev} parent 1:3 handle 3 fq_codel\n")
            out.write(f"filter add dev {dev} parent 1:0 protocol ip handle 3 fw flowid 1:3\n")
    
    def read_iptables_stats(self, stats):
        for line in stats:
            line = line.strip()
            #              12093312 16121305318        ACCEPT      all      --       *      eno1         0.0.0.0/0   10.92.1.209
            m = re.match(r"([0-9]+)[ \t]+([0-9]+)[ \t]+ACCEPT[ \t]+all[ \t]+--[ \t]+\*[ \t]+([\S]+)[ \t]+([0-9./]+)[ \t]+([0-9./]+)", line)
            if not m:
                continue

            (pkts, _bytes, dev, src_ip, tgt_ip) = m.groups()

            down = True
            if dev == config_dev_lan and src_ip == "0.0.0.0/0":
                if tgt_ip == "0.0.0.0/0":
                    continue
                ip = ip_address(tgt_ip)
                
            elif dev == config_dev_wan and tgt_ip == "0.0.0.0/0":
                if src_ip == "0.0.0.0/0":
                    continue
                ip = ip_address(src_ip)
                down = False
            else:
                continue
                
            if ip not in self.local_network:
                    continue

            #print (f"IP {ip} {'download' if down else 'upload'} {_bytes} bytes")
            _bytes = int(_bytes)
            self.ip2traffic[ip] = self.ip2traffic[ip] + _bytes
            if down:
                self.ip2download[ip] = _bytes
            else:
                self.ip2upload[ip] = _bytes

    def write_day_html(self, html):
        timestamp = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        html.write("<table border>\n")
        html.write(f"<tr><th colspan=11>Top Traffic Hosts ({timestamp})</th></tr>\n")
        html.write(tr((tdr("#"), td("hostname (user)"), td("ip"), tdr("total"), tdr("down"), tdr("up"))))
        num = 0
        for (ip, traffic) in sorted(self.ip2traffic.items(), key = lambda item: item[1], reverse=True):
            num += 1
            try:
                host = self.ip2host[ip]
            except KeyError:
                host = "(unknown)"
            try:
                user = self.ip2user[ip]
            except KeyError:
                user = "(unknown)"
            if host == user:
                hostuser = host
            else:
                hostuser = f"{host} ({user})"
            down = self.ip2download[ip]
            up = self.ip2upload[ip]
            html.write(tr((tdr(f"<a name=\"{host}\">{num}</a>"), td(hostuser), td(ip), tdr(human(traffic)),\
                           tdr(human(down)), tdr(human(up)))))
        html.write("</table>\n")

    def write_host_logs(self):
        now = int(time.time())
        dt = datetime.fromtimestamp(now)
        timestamp = dt.strftime("%a %b %d %H:%M:%S %Y")
        for (ip, traffic) in self.ip2traffic.items():
            if ip not in self.ip2host:
                continue
            host = self.ip2host[ip]
            user = self.ip2user[ip]
            down = self.ip2download[ip] // (1024*1024)
            up = self.ip2upload[ip] // (1024*1024)
            traffic = traffic // (1024*1024)
            (rate, ceil) = self.user2shaping[user]
            with open(f"{config_prefix}{config_logdir}/{host}.log", 'a') as log:
                log.write(f"{now}\t{host}\t{traffic}\t{down}\t0\t{up}\t{rate}\t{ceil}\t{ceil}\t{timestamp}\n")

def iptables_get_stats(statsfile):
    if args.devel:
        runargs = ["cat", "iptables.stats"]
    else:
        runargs = ["/usr/sbin/iptables", "-L", "-v", "-x", "-n", "-t", "mangle"]
    ret = subprocess.run(runargs, stdout=statsfile, check=True)
                
hosts = Hosts()
logfile = None

parser = argparse.ArgumentParser()
parser.add_argument("--dns", help=f"generate dns files {config_dns_db} and {config_dns_rev_db} instead of nat",\
                    action="store_true")
parser.add_argument("qos_conf", help=f"qos.conf location, default is {config_qos_conf}",\
                    nargs='?', default=f"{config_prefix}{config_qos_conf}")
parser.add_argument("--devel", help=f"development run, prefix all paths with local directory, don't execute iptables",\
                    action="store_true")
parser.add_argument("--dry-run", help=f"dry run on real system, don't actually replace nat.conf or run iptables and tc",\
                    action="store_true")
parser.add_argument("--nft", action="store_true")
parser.add_argument("-p", action="store_true")
parser.add_argument("-r", action="store_true")
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

if args.p:
    try:
        with tempfile.TemporaryDirectory() as tmpdir:

            print(f"Reading {qos_conf_path} ...")
            with open(qos_conf_path, 'r') as qosconf:
                hosts.read_qos_conf(qosconf)

            print("Getting iptables stats")
            with open(f"{tmpdir}/iptables.mangle.old", 'w') as stats:    
                iptables_get_stats(stats)
        
            print(f"Reading iptables.stats ... ")
            with open(f"{tmpdir}/iptables.mangle.old", 'r') as stats:
                hosts.read_iptables_stats(stats)

            if args.dry_run:
                print(f"Writing /tmp/preview.html instead of {config_html_preview} due to --dry-run ... ")
                preview_name = "/tmp/preview.html"
            else:
                print(f"Writing {config_html_preview} ... ")
                preview_name = f"{config_prefix}{config_html_preview}"
            with open(preview_name, 'w') as html:
                hosts.write_day_html(html)
            
        sys.exit(0)
    except ConfError as e:
        logp(e)
        sys.exit(1)

if args.r:
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
 
            print(f"Reading {qos_conf_path} ...")
            with open(qos_conf_path, 'r') as qosconf:
                hosts.read_qos_conf(qosconf)

            print("Getting iptables stats")
            with open(f"{tmpdir}/iptables.mangle.old", 'w') as stats:    
                iptables_get_stats(stats)
            
            print(f"Reading iptables.stats ... ")
            with open(f"{tmpdir}/iptables.mangle.old", 'r') as stats:
                hosts.read_iptables_stats(stats)

            if not args.dry_run:
                print(f"Writing {config_html_day} ... ")
                with open(f"{config_prefix}{config_html_day}", 'w') as html:
                    hosts.write_day_html(html)
            
                print(f"Writing host logs ... ")
                hosts.write_host_logs()

            else:
                print(f"Skipped writing {config_html_day} and host logs due to dry run")

            if args.devel:
                tmpdir = "."

            mangle_new = f"{tmpdir}/iptables.mangle.new"
            print("Writing iptables.mangle.new ...")
            with open(mangle_new, 'w') as mangle:
                hosts.write_iptables_mangle(mangle)
      
            nft_mangle_new = f"/tmp/nft.mangle.new"
            print("Writing nft.mangle.new ...")
            with open(nft_mangle_new, 'w') as mangle:
                hosts.write_nft_mangle(mangle)

            tc_new = f"{tmpdir}/tc.new"
            print("Writing tc.new...")
            with open(tc_new, 'w') as tc_file:
                hosts.write_tc_up(tc_file)

            if not args.devel:
                if not args.dry_run:
                    print("Flushing old tc rules ...")
                    for dev in [config_dev_lan, config_dev_wan]:
                        subprocess.run(["/sbin/tc", "qdisc", "del", "dev", dev, "root"], check=True)
                else:
                    print("Not flushing old tc rules due to dry run.")

                if args.nft:
                    if args.dry_run:
                        print("Testing (no commit) nft.mangle.new via nft -c ... ")
                        subprocess.run(["/usr/sbin/nft", "-c", "-f", nft_mangle_new], check=True)
                    else:
                        print("Loading nft.mangle.new via nft ... ")
                        subprocess.run(["/usr/sbin/nft", "-f", nft_mangle_new], check=True)
                else: 
                    if args.dry_run:
                        print("Testing (no commit) iptables.mangle.new via iptables-restore ... ")
                        subprocess.run(["/usr/sbin/iptables-restore", "-t", mangle_new], check=True)
                    else:
                        print("Loading iptables.mangle.new via iptables-restore ... ")
                        subprocess.run(["/usr/sbin/iptables-restore", mangle_new], check=True)
                
                if args.dry_run:
                    print("Not loading tc.new due to dry run")
                else:
                    print("Loading tc.new via tc -b ...")
                    subprocess.run(["/usr/sbin/tc", "-b", tc_new], check=True)

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
        elif args.dry_run:
            logp(f"No differences, not replacing nat.conf due to --dry-run")
        else:
            logp(f"No differences, replacing nat.conf with {nat_conf_post}")
            shutil.copyfile(nat_conf_post, f"{config_prefix}{config_nat_conf}")
    else:
        logp("No updates needed")

    if args.dry_run:
        logp(f"Generating /tmp/nat.up instead of {config_prefix}{config_nat_up} due to --dry-run")
        nat_up_name = "/tmp/nat.up"
    else:
        logp("Generating nat.up...")
        nat_up_name = f"{config_prefix}{config_nat_up}"
    with open(f"{config_prefix}{config_nat_global}", 'r') as nat_global, open(nat_up_name, 'w') as nat_up:
        nat_up.write("# generated by qos2nat.py\n")
        for line in nat_global:
            nat_up.write(line)
        hosts.write_nat_up(nat_up)

    if args.nft:
        if args.dry_run:
            logp(f"Generating /tmp/nat.up.nft instead of {config_prefix}{config_nat_up}.nft due to --dry-run")
            nat_up_nft_name = "/tmp/nat.up.nft"
        else:
            logp("Generating nat.up.nft...")
            nat_up_nft_name = f"{config_prefix}{config_nat_up}.nft"
        with open(f"{config_prefix}{config_nat_global}.nft", 'r') as nat_global_nft, open(nat_up_nft_name, 'w') as nat_up_nft:
            nat_up_nft.write("# generated by qos2nat.py\n")
            for line in nat_global_nft:
                nat_up_nft.write(line)
            hosts.write_nat_up_nft(nat_up_nft)

    if args.dry_run:
        logp(f"Generating /tmp/portmap.txt instead of {config_prefix}{config_portmap} due to --dry-run")
        portmap_name = "/tmp/portmap.txt"
    else:
        logp("Generating portmap.txt...")
        portmap_name = f"{config_prefix}{config_portmap}"
    with open(portmap_name, 'w') as portmap:
        hosts.write_portmap(portmap)

    if not args.devel:
        if args.nft:
            if args.dry_run:
                print("Testing (no commit) nat.up.nft via nft -t ... ")
                subprocess.run(["/usr/sbin/nft", "-c", "-f", nat_up_nft_name], check=True)
            else:
                logp("Loading new nat.up.nft")
                subprocess.run(["/usr/sbin/nft", "-f", nat_up_nft_name], check=True)
            ret = 0
        else:
            if args.dry_run:
                print("Testing (no commit) nat.up via iptables-restore ... ")
                subprocess.run(["/usr/sbin/iptables-restore", "-t", nat_up_name], check=True)
            else:
                logp("Loading new nat.up to iptables")
                subprocess.run(["/usr/sbin/iptables-restore", nat_up_name], check=True)
            ret = 0
    else:
        logp("Skipping iptables-restore due to --devel")
        ret = 0

    if ret != 0:
        logp(f"Error {ret} when executing iptables-restore") 
    else:
        logp(f"Done. Number of users: {len(hosts.users)}, number of local IPs: {len(hosts.ip2host)}, "
             f"remaining public IPs: {len(hosts.free_public_ips)}")

except ConfError as e:
    logp(e)
    sys.exit(1)
finally:
    if logfile:
        logfile.close()

