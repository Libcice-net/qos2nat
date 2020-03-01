#!/usr/bin/python3

import sys
import re

class QosConfError(RuntimeError):
    """Unexpected content in qos.conf"""

class NatConfError(RuntimeError):
    """Unexpected content in qos.conf"""

# TODO: validate local IPs for 10.92...

class Hosts:

    def __init__(self):
        self.ip2host = dict()
        self.host2ip = dict()
        self.ip2user = dict()
        self.user2shaping = dict()
        self.users = set()

        self.pubip2user = dict()
        self.user2pubip = dict()
        self.ip2pubip = dict()

    def addQos(self, ip, host, user, shaping = None):
        if ip in self.ip2host:
            host_other = self.ip2host[ip]
            print(f"Warning: Duplicate IP in qos.conf: {ip} is hosts {host_other} and {host}")
            ip_other = self.host2ip[host_other]
            user_other = self.ip2user[ip_other]
            if user != user_other:
                raise QosConfError(f"Duplicate IP in qos.conf: {ip} belongs to users {user_other} and {user}")                
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
                raise QosConfError(f"Multiple via-prometheus lines for user {user}: "
                                   f"{self.user2shaping[user]} and {shaping}")
            self.user2shaping[user] = shaping
    
    def readQosConf(self):

        qosconf = open("qos.conf", 'r')

        line_num = 1
        for line in qosconf:
            # remove leading/trailing whitespace
            line = line.strip()

            # empty
            if line == "":
                continue

            # commented out
            m = re.match("#.*", line)
            if m:
                continue

            m = re.match(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ \t]+([\S]+)[ \t]+#([\S]+).*", line)
            if not m:
                print (f"Error parsing qos.conf line {line_num}: {line}")
                break

            ip = m.group(1)
            host = m.group(2)
            shaping = m.group(3)

            if host == 'loopback':
                continue

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
            except QosConfError as e:
                raise QosConfError(f"Error processing qos.conf line {line_num}: {e}")

            line_num += 1

        qosconf.close()

        for user in self.users:
            if user not in self.user2shaping:
                print(f"Warning: No shaping in qos.conf defined for user {user}")

    def addNatConf(self, pubip, ip, port_src, port_dst, user):
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

        if ip in self.ip2pubip:
            pubip_other = self.ip2pubip[ip]
            if pubip != pubip_other:
                print(f"Warning: In nat.conf local IP {ip} translated to public IP {pubip} but also {pubip_other}")
        else:
            self.ip2pubip[ip] = pubip


        if port_src == "*" and port_dst == "*":
            pass

    def readNatConf(self):

        natconf = open("nat.conf", 'r')

        line_num = 1
        for line in natconf:
            # remove leading/trailing whitespace
            line = line.strip()

            m = re.match(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ \t]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[ \t]+([0-9*]+)[ \t]([0-9*]+)[ \t]# ([\S]+)(.*)", line)
            if not m:
                print (f"Error parsing nat.conf line {line_num}: {line}")
                break
            
            pubip = m.group(1)
            ip = m.group(2)
            port_src = m.group(3)
            port_dst = m.group(4)
            user = m.group(5)

            self.addNatConf(pubip, ip, port_src, port_dst, user)

        for user in self.users:
            if user not in self.user2pubip:
                print (f"Warning: qos.conf user {user} not in nat.conf")

        for user in self.user2pubip:
            if user not in self.users:
                print (f"Warning: nat.conf user {user} not in qos.conf")

        for ip in self.ip2host:
            if ip not in self.ip2pubip:
                print(f"Local IP {ip} has no public IP")

        for ip in self.ip2pubip:
            if ip not in self.ip2host:
                print(f"Local IP {ip} has public IP but no qos.conf entry")

hosts = Hosts()
try:
    hosts.readQosConf()
except QosConfError as e:
    print(e)
    sys.exit(1)


hosts.readNatConf()
