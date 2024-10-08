#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab:

import sys
import re
import shutil
import string
import argparse
import subprocess
import tempfile
import glob
from ipaddress import ip_address, ip_network
from collections import defaultdict
import time
from datetime import datetime, date

# for debugging/development
config_prefix=""

config_qos_conf = "/etc/qos.conf"
config_nat_conf = "/etc/nat.conf"
config_nat_global = "/etc/nat_global.conf"
config_nat_up = "/etc/nat.up"
config_logfile = "/var/log/qos2nat.log"
config_nat_backup = "/etc/nat_backup/nat_conf_"
config_portmap = "/var/www/portmap.txt"
config_mangle_up = "/etc/mangle.up"
config_tc_up = "/etc/tc.up"

config_html_preview = "/var/www/today.html"
config_html_day = "/var/www/yesterday.html"
config_logdir = "/var/www/logs/"

logfile = None

errors_not_fatal = False
errors_log = None

verbose_prints = False

# log to file and optionally append error to errors_log
def log(msg, err=False):
    global logfile, errors_log
    if logfile:
        logfile.write(f"{msg}\n")
    if err and errors_log is not None:
        errors_log += f"{msg}\n"

# log to file without newline
def logc(msg):
    global logfile
    if logfile:
        logfile.write(msg)

# log to file and print
def logp(msg, quiet=False):
    global verbose_prints
    if not quiet or verbose_prints:
        print(msg)
    log(msg)

# log to file and print and append to errors_log
def logpe(msg):
    print(msg)
    log(msg, err=True)

# log to file and print without newline
def logpc(msg, quiet=False):
    global verbose_prints
    if not quiet or verbose_prints:
        print(msg, end='')
    logc(msg)

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

    return f"{val/1024:.2f} GB"

def humanmb(val):
    if val < 1024:
        return f"{val} MB"
    val //= 1024

    if val < 1024:
        return f"{val} GB"

    return f"{val/1024:.2f} TB"

def humankbps(val):
    if val < 1000:
        return f"{val} kbps"

    val //= 1000

    return f"{val} Mbps"

class Hosts:

    def init_nat_conf(self):

        # from nat.conf
        self.pubip2user = dict()
        self.user2pubip = dict()
        self.ipuser2pubip = dict()
        self.ip2pubip = dict()
        self.ip2portfwd = defaultdict(set) # ip -> set((pubip, src, dst, user, comment))
        self.pubip_port2ip_port = dict() # (pubip, src) -> (ip, dst)
        self.pubip_port_nowarn = set() # (pubip, src)

        # what nat.conf updates needed
        self.nat_conf_ips_to_delete = set()
        self.nat_conf_user2pubip_to_add = dict() # user -> pubip
        self.nat_conf_pubip2ip_to_add = defaultdict(set) # pubip -> ip
        self.nat_conf_pubip_already_added = set()
        self.nat_conf_ips_to_change = dict() # ip -> new_ip
        self.nat_conf_user_renames = dict() # ip -> (olduser, oldpubip, newuser)
        self.nat_conf_pubip_changes = dict() # ip -> (oldpubip, newpubip)
        # ips of users with private - should be deleted
        self.nat_conf_ips_no_shaping = set()
        # to clean up after bug duplicating nat.conf * * entries
        self.nat_conf_ip_already_written = set()

    def __init__(self):

        # from qos.conf
        self.ip2host = dict()
        self.host2ip = dict()
        self.ip2user = dict()
        self.user2ip = dict()
        self.user2shaping = dict()
        self.users_with_subclasses = set()
        self.ip2shaping = dict()
        self.users = set()

        # from qos.conf config
        self.conf_uplink_mbit = None
        self.local_network = None
        self.all_public_ips = set()
        self.dev_lan = None
        self.dev_wan = None
        self.dns_private_domain = None
        self.dns_db = None
        self.dns_rev_db = None
        self.shaping_classes = dict()
        self.shaping_class2user = dict()
        self.post_message = None

        # from nftables stats
        self.ip2download = dict()
        self.ip2upload = dict()
        self.ip2download_packets = dict()
        self.ip2upload_packets = dict()
        self.ip2traffic = defaultdict(int)

        # from logs
        self.host2traffic_stats = dict() # host -> (total, down, up, speed)

        self.last_classid = 2089
        self.user2classid = dict()
        self.user2superclassid = dict()
        self.ip2classid = dict()

        self.init_nat_conf()

    def get_classid(self):
        self.last_classid += 1
        return self.last_classid

    def get_shaping_ceilh(self, shaping):
        (_type, details) = shaping
        if _type == "legacy":
            (_, ceil) = details
            ceil = humankbps(ceil)
        elif _type == "class":
            cls = details
            ceil = self.shaping_classes[cls]
        elif _type == "speed":
            ceil = details
        else:
            raise RuntimeError(f"Unknown shaping {shaping}")
        return ceil

    def add_qos(self, ip, host, user, shaping):
        if ip in self.ip2host:
            host_other = self.ip2host[ip]
            logpe(f"Warning: Duplicate IP in qos.conf: {ip} is hosts {host_other} and {host}")
            ip_other = self.host2ip[host_other]
            user_other = self.ip2user[ip_other]
            if user != user_other:
                raise ConfError(f"Duplicate IP in qos.conf: {ip} belongs to users {user_other} and {user}")
        else:
            self.ip2host[ip] = host

        if host in self.host2ip:
            ip_other = self.host2ip[host]
            user_other = self.ip2user[ip_other]
            logpe(f"Warning: Duplicate hostname in qos.conf: {host} is IP {ip_other} (user {user_other}) "
                  f"and {ip} (user {user})")
        else:
            self.host2ip[host] = ip

        self.ip2user[ip] = user
        if host == user:
            self.users.add(user)
            if user in self.user2shaping:
                raise ConfError(f"Multiple shaping non-sharing definitions for user {user}: "
                                   f"{self.user2shaping[user]} and {shaping} for ip {ip}")
            self.user2shaping[user] = shaping
            self.user2ip[user] = ip
            if shaping is not None:
                self.user2classid[user] = self.get_classid()
        elif shaping is not None:
            self.ip2shaping[ip] = shaping
            self.ip2classid[ip] = self.get_classid()
            self.users_with_subclasses.add(user)

    def read_qos_conf(self, qosconf, section = None):

        valid_sections = set(["hosts", "config", "classes"])

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

            try:
                m = re.match(r"include \"([\S]+)\"", line)
                if m:
                    subconf_path = f"{config_prefix}{m.group(1)}";
                    with open(subconf_path, 'r') as subconf:
                        self.read_qos_conf(subconf, section);
                    continue

                m = re.match(r"\[([\S]+)\]", line)
                if m:
                    section = m.group(1)
                    if section not in valid_sections:
                        raise ConfError(f"invalid qos.conf section: {line}")
                    if section == "hosts":
                        if self.conf_uplink_mbit is None:
                            raise ConfError(f"missing uplink_mbit=$num in [config]")
                        if not self.local_network:
                            raise ConfError(f"missing lan_range=\"$range\" in [config]")
                        if len(self.all_public_ips) == 0:
                            raise ConfError(f"missing wan_ranges=\"$range1,$range2...\" in [config]")
                        if not self.dev_lan:
                            raise ConfError(f"missing lan_dev=\"$dev\" in [config]")
                        if not self.dev_wan:
                            raise ConfError(f"missing wan_dev=\"$dev\" in [config]")
                        if not self.dns_private_domain:
                            raise ConfError(f"missing dns_private_domain=\"example.tld\" in [config]")
                        if not self.dns_db:
                            raise ConfError(f"missing dns_db=\"/path/to/$domain.db\" in [config]")
                        if not self.dns_rev_db:
                            raise ConfError(f"missing dns_rev_db=\"/path/to/$ip.db\" in [config]")
                    continue

                if section is None:
                    raise ConfError(f"no qos.conf [section] specified")

                if section == "config":
                    m = re.match(r"([\S]+)=\"([^\"]+)\"", line)
                    if not m:
                        m = re.match(r"([\S]+)=(.+)", line)
                        if not m:
                            raise ConfError(f"did not match key=value expected in [config]: {line}")
                    key = m.group(1)
                    val = m.group(2)
                    if key == "uplink_mbit":
                        try:
                            mbits = int(val)
                            self.conf_uplink_mbit = mbits
                        except ValueError as e:
                            raise ConfError(f"could not parse uplink_mbit value: {e}")
                    elif key == "lan_range":
                        try:
                            self.local_network = ip_network(val)
                        except ValueError as e:
                            raise ConfError(f"could not parse lan_range value: {e}")
                    elif key == "wan_ranges":
                        try:
                            for net_str in val.split(","):
                                net = ip_network(net_str)
                                self.all_public_ips.update(net.hosts())
                        except ValueError as e:
                            raise ConfError(f"could not parse wan_ranges value: {e}")
                    elif key == "lan_dev":
                        self.dev_lan = val
                    elif key == "wan_dev":
                        self.dev_wan = val
                    elif key == "dns_private_domain":
                        self.dns_private_domain = val
                    elif key == "dns_db":
                        self.dns_db = val
                    elif key == "dns_rev_db":
                        self.dns_rev_db = val
                    elif key == "post_message":
                        self.post_message = val
                    else:
                        raise ConfError(f"unknown key=value in [config]: {line}")
                    continue
                elif section == "classes":
                    if m := re.match(r"([\S]+)=\"([\S]+)\"", line):
                        pass
                    elif m := re.match(r"([\S]+)=([\S]+)", line):
                        pass
                    else:
                        raise ConfError(f"did not match key=value expected in [classes]: {line}")
                    cls = m.group(1)
                    user = None
                    total_speed = None
                    for prop in m.group(2).split(","):
                        if m := re.match(r"[0-9]+[kKmMgG]?bit", prop):
                            speed = prop
                            self.shaping_classes[cls] = speed
                        elif m := re.match(r"user=([\S]+)", prop):
                            user = m.group(1)
                            self.users.add(user)
                            self.shaping_class2user[cls] = user
                        elif m := re.match(r"total=([0-9]+[kKmMgG]?bit)", prop):
                            total_speed = m.group(1)
                        else:
                            raise ConfError(f"unknown configuration '{prop}' of class {cls}")
                    if user is not None and total_speed is not None:
                        self.user2shaping[user] = ("speed", total_speed)
                    continue

                m = re.match(r"([0-9.]+)[ \t]+([\S]+)[ \t]+#([\S]+).*", line)
                if not m:
                    raise ConfError(f"regex failed: {line}")

                (ip, host, shaping) = m.groups()

                try:
                    ip = ip_address(ip)
                except ValueError as e:
                    raise ConfError(f"IP parsing error: {e}")

                if host == 'loopback':
                    continue

                if ip not in self.local_network:
                    raise ConfError(f"IP {ip} not in local network {self.local_network}")

                if shaping == 'private':
                    user = host
                    shaping = None
                elif m := re.match(r"sharing-([\S]+),([\S]+)", shaping):
                    user = m.group(1)
                    shaping = m.group(2)
                elif m := re.match(r"sharing-([\S]+)", shaping):
                    user = m.group(1)
                    shaping = None
                else:
                    user = host

                if shaping is not None:
                    if m:= re.match(r"speed-([0-9]+[kKmMgG]?bit)", shaping):
                        shaping = ("speed", m.group(1))
                    elif m := re.match(r"via-prometheus-([0-9]+)-([0-9]+)", shaping):
                        speeds = (int(m.group(1)), int(m.group(2)))
                        shaping = ("legacy", speeds)
                    elif m := re.match(r"class-([\S]+)", shaping):
                        cls = m.group(1)
                        if cls not in self.shaping_classes:
                            raise ConfError(f"unknown shaping class: {shaping}")
                        shaping = ("class", cls)
                        if cls in self.shaping_class2user:
                            user = self.shaping_class2user[cls]
                    else:
                        raise ConfError(f"unknown shaping: {shaping}")

                self.add_qos(ip, host, user, shaping)
            except ConfError as e:
                err = f"Error processing qos.conf line {line_num}: {e}"
                if not errors_not_fatal:
                    raise ConfError(err)
                logpe(err)

        self.free_public_ips = set(self.all_public_ips)

        for (ip, user) in self.ip2user.items():
            if user not in self.users:
                raise ConfError(f"qos.conf error: ip {ip} is sharing-{user} but user {user} has no primary entry")

        for user in self.users:
            if user not in self.user2shaping:
                logpe(f"Warning: No shaping in qos.conf defined for user {user}")

    def add_nat_conf(self, pubip, ip, port_src, port_dst, user, comment):

        if port_src != "*" or port_dst != "*":
            if port_src != "all" or port_dst != "all":
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
            if comment.find("nowarn") != -1:
                self.pubip_port_nowarn.add(pubport)
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
            if ipuser in self.user2shaping and self.user2shaping[ipuser] is None:
                self.nat_conf_ips_no_shaping.add(ip)

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

        if pubip in self.nat_conf_pubip2ip_to_add and pubip not in self.nat_conf_pubip_already_added:
            for new_ip in self.nat_conf_pubip2ip_to_add[pubip]:
                # we are adding new local IP to existing public IP, so write the line
                # next to existing line
                new_user = self.ip2user[new_ip]
                natconf_new.write(f"{pubip}\t{new_ip}\t*\t*\t# {new_user} added by script\n")
            self.nat_conf_pubip_already_added.add(pubip)

        is_auto_entry = (port_src == "*" and port_dst == "*")

        if not is_auto_entry or ip not in self.nat_conf_ip_already_written:
            natconf_new.write(f"{pubip}\t{ip}\t{port_src}\t{port_dst}\t# {user}{comment}\n")
            if is_auto_entry:
                self.nat_conf_ip_already_written.add(ip)

    def read_nat_conf(self, natconf, natconf_new=None):

        line_num = 0
        for line in natconf:
            line_num += 1

            # remove leading/trailing whitespace
            #line = line.strip()

            m = re.match(r"([0-9.]+)[ \t]+([0-9.]+)[ \t]+([\S]+)[ \t]([\S]+)[ \t]# ([\S]+)(.*)", line)
            if not m:
                raise ConfError(f"Error parsing nat.conf line {line_num}: {line}")

            (pubip, ip, port_src, port_dst, user, comment) = m.groups()

            try:
                pubip = ip_address(pubip)
                ip = ip_address(ip)
                comment = comment.rstrip()
            except ValueError as e:
                raise ConfError(f"Error parsing nat.conf line {line_num}: {e}")

            if ip not in self.local_network:
                raise ConfError(f"Error parsing nat.conf line {line_num}: local IP {ip} not in local network {self.local_network}")

            if pubip not in self.all_public_ips:
                raise ConfError(f"Error parsing nat.conf line {line_num}: public IP {pubip} not in defined wan_ranges")

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
                if (pubip, port_src) in self.pubip_port_nowarn:
                    continue
                user = self.ip2user[ip]
                logp(f"Warning: port forward for unassigned public IP {pubip}:{port_src} to {ip}:{port_dst} (user {user})")

    def update_nat_conf(self, natconf_old, natconf_new):

        self.read_nat_conf(natconf_old, natconf_new)

        for (pubip, list_ip) in self.nat_conf_pubip2ip_to_add.items():
            if pubip in self.nat_conf_pubip_already_added:
                continue
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
            if ip not in self.ip2host or ip in self.nat_conf_ips_no_shaping:
                if ip not in self.ip2host:
                    reason = "not found in qos.conf"
                else:
                    reason = "marked private"
                found += 1
                fwds = ""
                if ip in self.ip2portfwd:
                    fwds = f", including {len(self.ip2portfwd[ip])} defined port forwards"
                pubip = self.ip2pubip[ip]
                user = self.pubip2user[pubip]
                if ip not in self.ip2host and user in self.user2ip:
                    newIp = self.user2ip[user]
                    if newIp not in self.ip2pubip:
                        logp(f"User {user} (public IP {pubip}): changing primary local IP from {ip} to {newIp}{fwds}")
                        self.nat_conf_ips_to_change[ip] = newIp
                        continue
                logp(f"Removing nat.conf entry from {pubip} to {ip} for user {user} (because {reason}){fwds}")
                self.nat_conf_ips_to_delete.add(ip)
            elif ip in self.nat_conf_user_renames:
                found += 1
                (olduser, oldpubip, newuser) = self.nat_conf_user_renames[ip]
                ipchange = ""
                # qos.conf line changed from user that still exists, or to user that already exists, so change public IP
                if olduser in self.users or newuser in self.user2pubip:
                    fresh = ""
                    if newuser in self.user2pubip:
                        newpubip = self.user2pubip[newuser]
                    elif newuser in self.nat_conf_user2pubip_to_add:
                        newpubip = self.nat_conf_user2pubip_to_add[user]
                    else:
                        newpubip = self.get_new_public_ip(newuser)
                        self.nat_conf_user2pubip_to_add[newuser] = newpubip
                        fresh = "newly assigned "

                    ipchange = f" and changing public IP {oldpubip} to {fresh}{newpubip}"
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
                if self.user2shaping[user] is None:
                    found -= 1
                    continue
                if user in self.user2ip and self.user2ip[user] in self.ip2pubip:
                    pubip = self.ip2pubip[self.user2ip[user]]
                    info = f"with existing user's public IP {pubip}"
                elif user in self.user2pubip:
                    pubip = self.user2pubip[user]
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
                if pub_port == "all" and loc_port == "all":
                    nat_up.write(f"add rule ip nat PREROUTING ip daddr {pubip} "
                                 f"dnat to {ip}\n")
                else:
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
                if pub_port == "all" and loc_port == "all":
                    nat_up.write(f"-A PREROUTING -d {pubip} "
                                 f"-j DNAT --to-destination {ip}")
                else:
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
            db.write(f"{ip.packed[3]:<14} IN PTR          {host}.{self.dns_private_domain}.\n")

    def write_nft_mangle(self, out, reset_stats):
        localnet = self.local_network

        out.write("add table ip mangle\n")
        out.write("delete table ip mangle\n")
        out.write("add table ip mangle\n")

        out.write("add map ip mangle forw_map { type ipv4_addr : verdict; }\n")
        out.write("add map ip mangle post_map { type ipv4_addr : verdict; }\n")

        for (ip, user) in self.ip2user.items():
            if user not in self.user2shaping:
                log(f"skip ip {ip} of user {user} due to no defined shaping")
                continue
            if self.user2shaping[user] is None:
                continue
            if ip in self.ip2classid:
                classid = self.ip2classid[ip]
            else:
                classid = self.user2classid[user]

            ipstr = str(ip).replace(".", "_")
            for prefix in ("post", "forw"):
                _bytes = 0
                packets = 0
                if not reset_stats:
                    if prefix == "post" and ip in self.ip2download:
                        _bytes = self.ip2download[ip]
                        packets = self.ip2download_packets[ip]
                    elif ip in self.ip2upload:
                        _bytes = self.ip2upload[ip]
                        packets = self.ip2upload_packets[ip]

                out.write(f"add chain ip mangle {prefix}_{ipstr}\n")
                out.write(f"add rule ip mangle {prefix}_{ipstr} counter packets {packets} bytes {_bytes} meta priority set 1:{classid} accept\n")
                out.write(f"add element ip mangle {prefix}_map {{ {ip} : goto {prefix}_{ipstr} }}\n")

        out.write("add chain ip mangle forw_common\n")
        out.write("add rule ip mangle forw_common counter packets 0 bytes 0 meta priority set 1:3 accept\n")

        out.write("add chain ip mangle post_common\n")
        out.write("add rule ip mangle post_common counter packets 0 bytes 0 meta priority set 1:3 accept\n")
        out.write("add chain ip mangle forward { type filter hook forward priority -150; policy accept; }\n")
        out.write(f"add rule ip mangle forward oifname \"{self.dev_wan}\" ip daddr {localnet} counter packets 0 bytes 0 accept\n")
        out.write(f"add rule ip mangle forward oifname \"{self.dev_wan}\" ip saddr vmap @forw_map\n")
        out.write(f"add rule ip mangle forward oifname \"{self.dev_wan}\" counter packets 0 bytes 0 jump forw_common\n")

        out.write("add chain ip mangle postrouting { type filter hook postrouting priority -150; policy accept; }\n")
        out.write(f"add rule ip mangle postrouting oifname \"{self.dev_lan}\" ip saddr {localnet} counter packets 0 bytes 0 accept\n")
        out.write(f"add rule ip mangle postrouting oifname \"{self.dev_lan}\" ip daddr vmap @post_map\n")
        out.write(f"add rule ip mangle postrouting oifname \"{self.dev_lan}\" counter packets 0 bytes 0 jump post_common\n")

    def __write_tc_shaping(self, out, classid, parent, shaping, qdisc = True):
        if shaping is None:
            return
        (_type, details) = shaping
        if _type == "legacy":
            (rate, ceil) = details
            rate = f"{rate}kbit"
            ceil = f"{ceil}kbit"
        elif _type == "class":
            cls = details
            #TODO: scale with ceil?
            rate = "200kbit"
            ceil = self.shaping_classes[cls]
        elif _type == "speed":
            rate = "200kbit"
            ceil = details
        else:
            raise RuntimeError(f"Unknown shaping {shaping}")
        for dev in (self.dev_lan, self.dev_wan):
            out.write(f"class add dev {dev} parent 1:{parent} classid 1:{classid} htb rate {rate} ceil {ceil} burst 256k cburst 256k prio 1 quantum 1500\n")
            if qdisc:
                out.write(f"qdisc add dev {dev} parent 1:{classid} handle {classid} fq_codel\n")


    def write_tc_up(self, out):
        top_mbit = self.conf_uplink_mbit
        sub_mbit = int(top_mbit * 0.975)

        for dev in (self.dev_lan, self.dev_wan):
            out.write(f"qdisc add dev {dev} root handle 1: htb r2q 5 default 1\n")
            out.write(f"class add dev {dev} parent 1: classid 1:2 htb rate {top_mbit}Mbit ceil {top_mbit}Mbit burst 14300k cburst 14300k prio 0 quantum 20000\n")
            out.write(f"class add dev {dev} parent 1:2 classid 1:1 htb rate {sub_mbit}Mbit ceil {sub_mbit}Mbit burst 10300k cburst 10300k prio 0 quantum 20000\n")
            out.write(f"class add dev {dev} parent 1:1 classid 1:1025 htb rate {sub_mbit}bit ceil {sub_mbit}Mbit burst 10300k cburst 10300k prio 1 quantum 20000\n")

        for (user, shaping) in self.user2shaping.items():
            parent = 1025
            if user in self.users_with_subclasses:
                super_classid = self.get_classid()
                self.__write_tc_shaping(out, super_classid, parent, shaping, False)
                parent = super_classid
                self.user2superclassid[user] = super_classid
            if user in self.user2classid:
                classid = self.user2classid[user]
                self.__write_tc_shaping(out, classid, parent, shaping)

        for (ip, shaping) in self.ip2shaping.items():
            user = self.ip2user[ip]
            if user in self.user2superclassid:
                parent = self.user2superclassid[user]
            else:
                parent = 1025
            classid = self.ip2classid[ip]
            self.__write_tc_shaping(out, classid, parent, shaping)

        for dev in (self.dev_lan, self.dev_wan):
            out.write(f"class add dev {dev} parent 1:1025 classid 1:3 htb rate 64kbit ceil 128kbit burst 256k cburst 256k prio 7 quantum 1500\n")
            out.write(f"qdisc add dev {dev} parent 1:3 handle 3 fq_codel\n")
            out.write(f"filter add dev {dev} parent 1:0 protocol ip handle 3 fw flowid 1:3\n")

    def read_nft_stats(self, stats):
        table_based = None
        down = None
        table_in_chain = False
        for line in stats:
            line = line.strip()

            if table_based is None:
                m = re.match(r"map forw_map {", line)
                if m:
                    table_based = True
                    continue
                m = re.match(r"chain PREROUTING {", line)
                if m:
                    table_based = False
                    continue
                continue

            if not table_based:
                m = re.match(r"oifname \"([^\"]+)\" ip ([ds]addr) ([0-9.]+) counter packets ([0-9]+) bytes ([0-9]+) meta priority set 1:([0-9]+)", line)
                if not m:
                    continue

                (dev, sdaddr, ip, packets, _bytes, classid) = m.groups()

                if dev == self.dev_lan and sdaddr == "daddr":
                    down = True
                elif dev == self.dev_wan and sdaddr == "saddr":
                    down = False
                else:
                    continue

            else:
                if table_in_chain:
                    m = re.match(f"counter packets ([0-9]+) bytes ([0-9]+) meta priority set 1:([0-9]+)", line)
                    if not m:
                        raise ConfError(f"Unexpected content of chain for {ip} down {down}: {line}")
                    (packets, _bytes, classid) = m.groups()
                    table_in_chain = False
                else:
                    m = re.match(r"chain (post|forw)_([0-9]+)_([0-9]+)_([0-9]+)_([0-9]+) {", line)

                    if not m:
                        continue

                    (_type, ip1, ip2, ip3, ip4) = m.groups()
                    if _type == "post":
                        down = True
                    else:
                        down = False
                    ip = f"{ip1}.{ip2}.{ip3}.{ip4}"
                    table_in_chain = True
                    continue

            ip = ip_address(ip)
            if ip not in self.local_network:
                continue

            _bytes = int(_bytes)
            self.ip2traffic[ip] = self.ip2traffic[ip] + _bytes
            packets = int(packets)
            if down:
                self.ip2download[ip] = _bytes
                self.ip2download_packets[ip] = packets
            else:
                self.ip2upload[ip] = _bytes
                self.ip2upload_packets[ip] = packets

        if table_based is None:
            raise ConfError("Content of nft list table mangle not recognized")

    def write_day_html(self, html):
        if errors_log:
            html.write(f"<pre>{errors_log}</pre>")
        timestamp = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        html.write("<table border>\n")
        html.write(f"<tr><th colspan=7>Top Traffic Hosts ({timestamp})</th></tr>\n")
        html.write(tr((tdr("#"), td("hostname (user)"), td("ip"), tdr("total"), tdr("down"), tdr("up"), tdr("speed"))))
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
                hostuser = f"<a href=\"logs/{host}.log\"><b>{host}</b></a>"
            else:
                hostuser = f"<a href=\"logs/{host}.log\"><b>{host}</b></a> (<a href=\"logs/{user}.log\">{user}</a>)"
            try:
                shaping = self.user2shaping[user]
                ceil = self.get_shaping_ceilh(shaping)
            except KeyError:
                ceil = 0
            down = self.ip2download[ip]
            up = self.ip2upload[ip]
            html.write(tr((tdr(f"<a name=\"{host}\">{num}</a>"), td(hostuser), td(f"{ip}"), tdr(f"<b>{human(traffic)}</b>"),\
                           tdr(human(down)), tdr(human(up)), tdr(ceil))))
        html.write("</table>\n")

    def write_monthyear_html(self, html, header):
        html.write("<table border>\n")
        html.write(f"<tr><th colspan=6>Top Traffic Hosts ({header})</th></tr>\n")
        html.write(tr((tdr("#"), td("hostname"), tdr("total"), tdr("down"), tdr("up"), tdr("speed"))))
        num = 0
        for (host, stats) in sorted(self.host2traffic_stats.items(), key = lambda item: max(item[1][0], item[1][1]), reverse=True):
            num += 1
            (total, down, up, speed) = stats
            html.write(tr((tdr(f"<a name=\"{host}\">{num}</a>"), td(f"<b>{host}</b>"), tdr(f"<b>{humanmb(total)}</b>"),\
                           tdr(humanmb(down)), tdr(humanmb(up)), tdr(f"{humankbps(speed)}"))))
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
            shaping = self.user2shaping[user]
            ceil = self.get_shaping_ceilh(shaping)
            with open(f"{config_prefix}{config_logdir}/{host}.log", 'a') as log:
                log.write(f"{now}\t{host}\t{traffic}\t{down}\t0\t{up}\trate\t{ceil}\t{ceil}\t{timestamp}\n")

    def read_host_log(self, log, ts_start, ts_end):
        stat_host = ""
        stat_traffic = 0
        stat_down = 0
        stat_up = 0
        stat_ceil = 0
        for line in log:
            line = line.strip()
            m = re.match(r"([0-9]+)[ \t]+([\S]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+[0-9]+[ \t]+([0-9]+)[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+)[ \t]+", line)
            if not m:
                print(f"Unmatched line: {line}")
                continue
            (ts, host, traffic, down, up, ceil) = m.groups()
            ts = int(ts)
            if ts < ts_start or ts > ts_end:
                continue
            stat_traffic += int(traffic)
            stat_down += int(down)
            stat_up += int(up)
            stat_host = host
            if int(ceil) > stat_ceil:
                stat_ceil = int(ceil)
        if stat_host != "":
            self.host2traffic_stats[host] = (stat_traffic, stat_down, stat_up, stat_ceil)

    def read_host_logs(self, ts_start, ts_end):
        for log_file in glob.iglob(f"{config_prefix}{config_logdir}/*.log"):
            try:
                with open(log_file, 'r') as log:
                    self.read_host_log(log, ts_start, ts_end)
            except Exception as e:
                print(f"Failed to process {log_file}: {e}")

def nft_get_stats(statsfile):
    if args.devel:
        runargs = ["cat", "nft.stats"]
    else:
        runargs = ["/usr/sbin/nft", "list", "table", "mangle"]
    ret = subprocess.run(runargs, stdout=statsfile)
    return ret.returncode


def get_mangle_stats(tmpdir):
    logpc("nft mangle stats: reading ... ", True)
    ret = 1
    with open(f"{tmpdir}/nft.mangle.old", 'w') as stats:
        ret = nft_get_stats(stats)

    if ret == 0:
        logp(f"parsing ...", True)
        with open(f"{tmpdir}/nft.mangle.old", 'r') as stats:
            hosts.read_nft_stats(stats)
    else:
        logp("Could not get mangle stats (flushed table?), stats will be zero")

def reload_shaping(hosts, tmpdir, reset_stats):

        if args.dry_run and not args.devel:
            mangle_up_name = "/tmp/mangle.up"
            mangle_up_nft_name = "/tmp/mangle.up.nft"
            tc_up_name = "/tmp/tc.up"
        else:
            mangle_up_name = f"{config_prefix}{config_mangle_up}"
            mangle_up_nft_name = f"{config_prefix}{config_mangle_up}.nft"
            tc_up_name = f"{config_prefix}{config_tc_up}"

        logpc(f"Writing {mangle_up_nft_name} ", True)
        with open(mangle_up_nft_name, 'w') as mangle:
            hosts.write_nft_mangle(mangle, reset_stats)

        logp(f"{tc_up_name}", True)
        with open(tc_up_name, 'w') as tc_file:
            hosts.write_tc_up(tc_file)

        if not args.devel:
            if args.dry_run:
                logp(f"Testing (no commit) {mangle_up_nft_name} via nft -c ... ", True)
                subprocess.run(["/usr/sbin/nft", "-c", "-f", mangle_up_nft_name], check=True)
            else:
                logp(f"Loading {mangle_up_nft_name} via nft ... ", True)
                subprocess.run(["/usr/sbin/nft", "-f", mangle_up_nft_name], check=True)

            if not args.dry_run:
                logpc("Flushing old tc rules ... ", True)
                for dev in [hosts.dev_lan, hosts.dev_wan]:
                    subprocess.run(["/sbin/tc", "qdisc", "del", "dev", dev, "root"])
            else:
                logp("Not flushing old tc rules due to dry run.", True)

            if args.dry_run:
                logp(f"Not loading {tc_up_name} due to dry run", True)
            else:
                logp(f"loading {tc_up_name} via tc -b ...", True)
                subprocess.run(["/usr/sbin/tc", "-b", tc_up_name], check=True)
        else:
            logp("Not loading mangle and tc due to --devel", True)

hosts = Hosts()
logfile = None

parser = argparse.ArgumentParser()
parser.add_argument("qos_conf", nargs='?', default=f"{config_prefix}{config_qos_conf}",
                    help=f"qos.conf location, default is {config_qos_conf}")
parser.add_argument("-f", action="store_true",
                    help="force regenerate and reload nat and shaping even if no changes were detected")
parser.add_argument("--dry-run", action="store_true",
                    help="dry run on real system, don't actually replace nat.conf or make changes to nftables and tc")
parser.add_argument("-v", action="store_true",
                    help="verbose printing of detailed steps (otherwise only logged to file)")
parser.add_argument("-p", action="store_true",
                    help="only generate today.html, no nat.conf update or changes to nat or traffic shaping")
parser.add_argument("-r", action="store_true",
                    help="generate yesterday.html and reset packet stats in kernel tables")
parser.add_argument("-m", action="store_true",
                    help="only generate html stats for previous month")
parser.add_argument("-y", action="store_true",
                    help="only generate html stats for previous year")
parser.add_argument("--devel", action="store_true",
                    help="(dev only) development run, prefix all paths with local directory, don't execute nft...")
args = parser.parse_args()

if args.devel:
    config_prefix="."

qos_conf_path=f"{config_prefix}{args.qos_conf}"

if args.v:
    verbose_prints = True

if args.m:
    now = date.today()
    if now.month == 1:
        start_month = 12
        start_year = now.year - 1
    else:
        start_month = now.month - 1
        start_year = now.year
    date_start = datetime(start_year, start_month, 1, 3)
    ts_start = date_start.timestamp()
    ts_end = datetime(now.year, now.month, 1, 3).timestamp()
    hosts.read_host_logs(ts_start, ts_end)
    month_str = date_start.strftime("%b")
    html_name = f"{config_prefix}{config_logdir}html/{start_year}-{month_str}.html"
    print(f"Writing {html_name}")
    with open(html_name, 'w') as html:
        hosts.write_monthyear_html(html, f"{month_str} {start_year}")
    sys.exit(0)

if args.y:
    now = date.today()
    start_year = now.year - 1
    date_start = datetime(start_year, 1, 1, 3)
    ts_start = date_start.timestamp()
    ts_end = datetime(now.year, 1, 1, 3).timestamp()
    hosts.read_host_logs(ts_start, ts_end)
    month_str = "Year"
    html_name = f"{config_prefix}{config_logdir}html/{start_year}-{month_str}.html"
    print(f"Writing {html_name}")
    with open(html_name, 'w') as html:
        hosts.write_monthyear_html(html, f"{month_str} {start_year}")
    sys.exit(0)

if args.p:
    errors_not_fatal = True
    errors_log = ""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            logp(f"Reading {qos_conf_path} ...")
            with open(qos_conf_path, 'r') as qosconf:
                hosts.read_qos_conf(qosconf)

            get_mangle_stats(tmpdir)

            if args.dry_run:
                preview_name = "/tmp/today.html"
            else:
                preview_name = f"{config_prefix}{config_html_preview}"
            logp(f"Writing {preview_name} ...")
            with open(preview_name, 'w') as html:
                hosts.write_day_html(html)

        sys.exit(0)
    except ConfError as e:
        logp(e)
        sys.exit(1)

if args.r:
    errors_not_fatal = True
    errors_log = ""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            logp(f"Reading {qos_conf_path} ...")
            with open(qos_conf_path, 'r') as qosconf:
                hosts.read_qos_conf(qosconf)

            get_mangle_stats(tmpdir)

            if args.dry_run:
                day_name = "/tmp/yesterday.html"
            else:
                day_name = f"{config_prefix}{config_html_day}"

            logp(f"Writing {day_name} ... ")
            with open(day_name, 'w') as html:
                hosts.write_day_html(html)

            if not args.dry_run:
                logp(f"Writing host logs ... ")
                hosts.write_host_logs()
            else:
                logp(f"Skipped writing host logs due to --dry run")

            reload_shaping(hosts, tmpdir, True)

        sys.exit(0)
    except ConfError as e:
        logp(e)
        sys.exit(1)

try:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    logfile = open(f"{config_prefix}{config_logfile}", 'a')

    log(f"Start qos2nat.py {timestamp}")

    logp(f"Reading {qos_conf_path} ...", True)
    with open(qos_conf_path, 'r') as qosconf:
        hosts.read_qos_conf(qosconf)

    nat_conf_pre = f"{config_prefix}{config_nat_backup}{timestamp}_pre"

    logp(f"Creating nat.conf backup {nat_conf_pre}", True)
    shutil.copyfile(f"{config_prefix}{config_nat_conf}", nat_conf_pre)

    logp("Reading nat.conf...", True)
    with open(f"{nat_conf_pre}", 'r') as natconf:
        hosts.read_nat_conf(natconf)

    logp("Calculating nat.conf updates:", True)
    diffs = hosts.find_differences()
    if diffs > 0 or args.f:
        nat_conf_post = f"{config_prefix}{config_nat_backup}{timestamp}_post"
        logp(f"Writing {nat_conf_post} with {diffs} updates...")
        with open(nat_conf_pre, 'r') as natconf, open(nat_conf_post, 'w') as natconf_new:
            hosts.update_nat_conf(natconf, natconf_new)

        logp("Reading nat.conf.new back to verify no more updates detected...", True)
        hosts.init_nat_conf()
        with open(nat_conf_post, 'r') as natconf:
            hosts.read_nat_conf(natconf)

        check_diffs = hosts.find_differences()
        if check_diffs > 0:
            logp(f"Found {check_diffs} more unexpected updates, aborting.")
            sys.exit(1)
        elif args.dry_run:
            logp(f"No differences, but not replacing nat.conf due to --dry-run", True)
        else:
            logp(f"No differences, replacing nat.conf with {nat_conf_post}", True)
            shutil.copyfile(nat_conf_post, f"{config_prefix}{config_nat_conf}")
    else:
        if not args.f:
            logp("No updates needed, exiting. Re-run with -f to force updating nat and traffic shaping.")
            logp("(run with -f is needed for new port forwards or bandwidth changes, which are currently not detected automatically)")
            sys.exit(0)
        else:
            logp("No needed updates detected but continuing due to -f parameter.")

    if args.dry_run:
        nat_up_nft_name = "/tmp/nat.up.nft"
    else:
        nat_up_nft_name = f"{config_prefix}{config_nat_up}.nft"
    logpc(f"Writing {nat_up_nft_name} ", True)
    with open(f"{config_prefix}{config_nat_global}.nft", 'r') as nat_global_nft, open(nat_up_nft_name, 'w') as nat_up_nft:
        for line in nat_global_nft:
            nat_up_nft.write(line)
        hosts.write_nat_up_nft(nat_up_nft)

    if args.dry_run:
        portmap_name = "/tmp/portmap.txt"
    else:
        portmap_name = f"{config_prefix}{config_portmap}"
    logpc(f"{portmap_name} ", True)
    with open(portmap_name, 'w') as portmap:
        hosts.write_portmap(portmap)

    if args.dry_run:
        dns_db_name = "/tmp/dns.db"
        dns_rev_db_name = "/tmp/dns_rev.db"
    else:
        dns_db_name = f"{config_prefix}{hosts.dns_db}"
        dns_rev_db_name = f"{config_prefix}{hosts.dns_rev_db}"
    logpc(f"{dns_db_name} ", True)
    with open(dns_db_name, 'w') as db:
        hosts.write_dns_hosts(db)

    logp(f"{dns_rev_db_name}", True)
    with open(dns_rev_db_name, 'w') as db:
        hosts.write_dns_reverse(db)

    if not args.devel:
        if args.dry_run:
            logp("Testing (no commit) nat.up.nft via nft -t ... ", True)
            subprocess.run(["/usr/sbin/nft", "-c", "-f", nat_up_nft_name], check=True)
        else:
            logp("Loading new nat.up.nft", True)
            subprocess.run(["/usr/sbin/nft", "-f", nat_up_nft_name], check=True)
    else:
        logp("Skipping nftables loading due to --devel", True)

    with tempfile.TemporaryDirectory() as tmpdir:
        get_mangle_stats(tmpdir)

        reload_shaping(hosts, tmpdir, False)

    logp(f"Done. Number of users: {len(hosts.users)}, number of local IPs: {len(hosts.ip2host)}, "
         f"remaining public IPs: {len(hosts.free_public_ips)}")
    if hosts.post_message:
        print(hosts.post_message)


except ConfError as e:
    logp(e)
    sys.exit(1)
finally:
    if logfile:
        logfile.close()

