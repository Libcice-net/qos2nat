#!/usr/bin/python3
# vim:set shiftwidth=4 softtabstop=4 expandtab:

import sys
import re
import ipaddress
from collections import defaultdict

config_local_network = "10.92.0.0/16"
config_public_networks = [
        "89.203.128.0/24",
        "89.203.138.0/24",
        "195.146.116.0/24",
]

class ConfError(RuntimeError):
    """Unexpected content in conf file"""

class Hosts:

    def initNatConf(self):

        # from nat.conf
        self.pubip2user = dict()
        self.user2pubip = dict()
        self.ip2pubip = dict()
        self.ip2portfwd = defaultdict(set) # ip -> set((pubip, src, dst))
        self.pubip_port2ip_port = dict() # (pubip, src) -> (ip, dst)

        # what nat.conf updates needed
        self.natConfIpsToDelete = set()
        self.natConfUsersPubipsToAdd = dict() # user -> pubip
        self.natConfIpsToAdd = defaultdict(set) # pubip -> ip
        self.natConfIpsToChange = dict() # ip -> newIp
        self.natConfUserRenames = dict() # ip -> (olduser, newuser)

        self.free_public_ips = set(self.all_public_ips)

    def __init__(self):

        # from qos.conf
        self.ip2host = dict()
        self.host2ip = dict()
        self.ip2user = dict()
        self.user2ip = dict()
        self.user2shaping = dict()
        self.users = set()

        self.local_network = ipaddress.ip_network(config_local_network)
        self.all_public_ips = set()
        for net_str in config_public_networks:
            net = ipaddress.ip_network(net_str)
            self.all_public_ips.update(net.hosts())

        self.initNatConf()

    def addQos(self, ip, host, user, shaping = None):
        if ip in self.ip2host:
            host_other = self.ip2host[ip]
            print(f"Warning: Duplicate IP in qos.conf: {ip} is hosts {host_other} and {host}")
            ip_other = self.host2ip[host_other]
            user_other = self.ip2user[ip_other]
            if user != user_other:
                raise ConfError(f"Duplicate IP in qos.conf: {ip} belongs to users {user_other} and {user}")                
        else:
            self.ip2host[ip] = host

        if host in self.host2ip:
            ip_other = self.host2ip[host]
            user_other = self.ip2user[ip_other]
            print(f"Warning: Duplicate hostname in qos.conf: {host} is IP {ip_other} (user {user_other}) "
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
            
    def readQosConf(self, qosconf):

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
                print (f"Error parsing qos.conf line {line_num}: {line}")
                break

            ip = m.group(1)
            host = m.group(2)
            shaping = m.group(3)

            try:
                ip = ipaddress.ip_address(ip)
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
                    print (f"Error parsing qos.conf line {line_num} - shaping not recognized: {shaping}")
                    break
                user = m.group(1)
                shaping = None

            try:
                self.addQos(ip, host, user, shaping)
            except ConfError as e:
                raise ConfError(f"Error processing qos.conf line {line_num}: {e}")

        for user in self.users:
            if user not in self.user2shaping:
                print(f"Warning: No shaping in qos.conf defined for user {user}")

    def addNatConf(self, pubip, ip, port_src, port_dst, user):

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

            self.ip2portfwd[ip].add((pubip, port_src, port_dst))

            pubport = (pubip, port_src)
            locport = (ip, port_dst)
            if pubport in self.pubip_port2ip_port:
                other_locport = self.pubip_port2ip_port[pubport]
                if locport == other_locport:
                    print(f"Warning: In nat.conf multiple lines with same port forward "
                          f"from public {pubip}:{port_src} to local {ip}:{port_dst}")
                else:
                    (other_ip, other_port_dst) = other_locport
                    raise ConfError(f"conflicting port forward from public {pubip}:{port_src} "
                                    f"to local {ip}:{port_dst} with previously seen local "
                                    f"{other_ip}:{other_port_dst}")
            else:
                self.pubip_port2ip_port[pubport] = locport
           
            # TODO: warn if some public IP has only forwards but no full NAT? 
            self.free_public_ips.discard(pubip)
            return

        if ip in self.ip2pubip:
            pubip_other = self.ip2pubip[ip]
            if pubip != pubip_other:
                raise ConfError(f"local IP {ip} is translated to public IP {pubip} but also {pubip_other}")
        else:
            self.ip2pubip[ip] = pubip

        if ip in self.ip2user and user != self.ip2user[ip]:
           self.natConfUserRenames[ip] = (user, self.ip2user[ip])

        if user in self.user2pubip:
            pubip_other = self.user2pubip[user]
            if pubip != pubip_other:
                print(f"Warning: In nat.conf {user} has public IP {pubip} but also {pubip_other}")
        else:
            self.user2pubip[user] = pubip

        if pubip in self.pubip2user:
            user_other = self.pubip2user[pubip]
            if user != user_other:
                print(f"Warning: In nat.conf public IP {pubip} assigned to user {user} but also {user_other}")
        else:
            self.pubip2user[pubip] = user

        self.free_public_ips.discard(pubip)
        
    def writeNatConfLine(self, pubip, ip, port_src, port_dst, user, comment, natconf_new):
       
        if ip in self.natConfIpsToDelete:
            return

        if ip in self.natConfIpsToChange:
            ip = self.natConfIpsToChange[ip]
        elif ip in self.natConfUserRenames:
            (olduser, newuser) = self.natConfUserRenames[ip]
            if olduser == user:
                user = newuser
        
        if pubip in self.natConfIpsToAdd:
            for new_ip in self.natConfIpsToAdd[pubip]:
                # we are adding new local IP to existing public IP, so write the line
                # next to existing line
                new_user = self.ip2user[new_ip]
                natconf_new.write(f"{pubip}\t{new_ip}\t*\t*\t# {new_user} added by script\n")
            del (self.natConfIpsToAdd[pubip])
 
        natconf_new.write(f"{pubip}\t{ip}\t{port_src}\t{port_dst}\t# {user}{comment}\n")
        
    def readNatConf(self, natconf, natconf_new=None):

        line_num = 0
        for line in natconf:
            line_num += 1

            # remove leading/trailing whitespace
            #line = line.strip()

            m = re.match(r"([0-9.]+)[ \t]+([0-9.]+)[ \t]+([0-9*]+)[ \t]([0-9*]+)[ \t]# ([\S]+)(.*)", line)
            if not m:
                print (f"Error parsing nat.conf line {line_num}: {line}")
                break
            
            pubip = m.group(1)
            ip = m.group(2)
            port_src = m.group(3)
            port_dst = m.group(4)
            user = m.group(5)
            comment = m.group(6)

            try:
                pubip = ipaddress.ip_address(pubip)
                ip = ipaddress.ip_address(ip)
            except ValueError as e:
                raise ConfError(f"Error parsing nat.conf line {line_num}: {e}")

            if ip not in self.local_network:
                raise ConfError(f"Error parsing nat.conf line {line_num}: local IP {ip} not in local network {self.local_network}")

            if pubip not in self.all_public_ips:
                raise ConfError(f"Error parsing nat.conf line {line_num}: public IP {pubip} not in libcice.net ranges")
           
            if natconf_new:
                self.writeNatConfLine(pubip, ip, port_src, port_dst, user, comment, natconf_new) 
            else:
                try:
                    self.addNatConf(pubip, ip, port_src, port_dst, user)
                except ConfError as e:
                    raise ConfError(f"Error parsing nat.conf line {line_num}: {e}")
                    

    def updateNatConf(self, natconf_old, natconf_new):

        self.readNatConf(natconf_old, natconf_new)

        for (pubip, list_ip) in self.natConfIpsToAdd.items():
            for ip in list_ip:
                user = self.ip2user[ip]
                natconf_new.write(f"{pubip}\t{ip}\t*\t*\t# {user} added by script\n")

    def findDifferences(self):

        found = 0

        for user in self.users:
            if user not in self.user2pubip:
                #print (f"Warning: qos.conf user {user} not in nat.conf")
                pass

        for user in self.user2pubip:
            if user not in self.users:
                #print (f"Warning: nat.conf user {user} not in qos.conf")
                pass

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
                        print(f"User {user} (public IP {pubip}): changing primary local IP from {ip} to {newIp}{fwds}")
                        self.natConfIpsToChange[ip] = newIp
                        continue
                print(f"User {user} (public IP {pubip}): removing local IP {ip}{fwds}")
                self.natConfIpsToDelete.add(ip)
            elif ip in self.natConfUserRenames:
                found += 1
                (olduser, newuser) = self.natConfUserRenames[ip]
                # TODO also count forwards? rename also in forwards lines?
                print(f"Renaming user {olduser} to {newuser} for IP {ip}")
           

        for ip in self.ip2host:
            if ip not in self.ip2pubip:
                found += 1
                if ip in self.natConfIpsToChange.values():
                    continue
                host = self.ip2host[ip]
                user = self.ip2user[ip]
                if user in self.user2ip and self.user2ip[user] in self.ip2pubip:
                    pubip = self.ip2pubip[self.user2ip[user]]
                    info = f"with existing user's public IP {pubip}"
                elif user in self.user2pubip:
                    pubip = self.user2pubip[user]
                    info = f"with existing user's public IP {pubip}"
                elif user in self.natConfUsersPubipsToAdd:
                    pubip = self.natConfUsersPubipsToAdd[user]
                    info = f"with pending new user's public IP {pubip}"
                else:
                    if len(self.free_public_ips) == 0:
                        raise ConfError(f"Need new public IP for local IP {ip} (host {host} of user {user}), but none left.")
                    pubip = self.free_public_ips.pop()
                    self.natConfUsersPubipsToAdd[user] = pubip
                    info = f"with new user's public IP {pubip}"
                    
                print(f"User {user}: adding local IP {ip} (host {host}) {info}")
                self.natConfIpsToAdd[pubip].add(ip)
        return found

hosts = Hosts()
try:
    print("Reading qos.conf...")
    with open("qos.conf", 'r') as qosconf:
        hosts.readQosConf(qosconf)
    print("Reading nat.conf...")
    with open("nat.conf", 'r') as natconf:
        hosts.readNatConf(natconf)
    print("Calculating nat.conf updates:")
    diffs = hosts.findDifferences()
    if diffs > 0:
        print (f"Writing nat.conf.new with {diffs} updates...")
        with open("nat.conf", 'r') as natconf, open("nat.conf.new", 'w') as natconf_new:
            hosts.updateNatConf(natconf, natconf_new)
        hosts.initNatConf()
        print("Reading nat.conf.new back to verity no more updates detected...")
        with open("nat.conf.new", 'r') as natconf:
            hosts.readNatConf(natconf)
        diffs = hosts.findDifferences()
        if diffs > 0:
            print(f"Found {diffs} more unexpected updates, aborting.")
            sys.exit(1)
    else:
        print("No updates needed")
except ConfError as e:
    print(e)
    sys.exit(1)


