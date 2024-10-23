#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class ARPPacket(object):
    def __init__(self,ip_packet,interface):
        self.ip_packet=ip_packet
        self.interface=interface
        self.sent_time=time.time()
        self.retries=0

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # create a list storing the ethaddr of interfaces of the router 
        self.intf_ipaddrs = []
        for interface in self.net.interfaces():
            self.intf_ipaddrs.append(interface.ipaddr)
        # create forwarding table
        # the list of router interfaces 
        self.forwarding_table=[]
        for interface in self.net.interfaces():
            print(f"{interface.ipaddr}")
            print(f"{interface.netmask}")
            ipaddr = interface.ipaddr
            netmask = interface.netmask
            print(f"ipaddr{ipaddr} netmask{netmask} ")
            network_addr = IPv4Address(int(ipaddr)&int(netmask))
            print(f"network_addr:{network_addr}")
            netaddr = IPv4Network(f"{network_addr}/{netmask}") 
            print("netaddr:{netaddr}")
            self.forwarding_table.append({ 
                "network_addr":network_addr,
                "mask":netmask,
                "next_hop":"0.0.0.0",
                "interface": interface,
                "prefixlen":netaddr.prefixlen
            })
        
        # read forwarding table file
        with open('forwarding_table.txt','r') as f:
            lines=f.readlines()
        for line in lines:
            # split the line
            parts=line.strip().split() 
            network_addr=parts[0]
            subnet_mask=parts[1]
            next_hop=IPv4Address(parts[2])
            ifaceName=parts[3]
            intf = self.net.interface_by_name(ifaceName)
            # convert networkaddr and subnet mask to IPv4Network objects
            netaddr = IPv4Network(f"{network_addr}/{subnet_mask}") 
            # add entry to forwarding table
            self.forwarding_table.append({ 
                "network_addr":network_addr,
                "mask":subnet_mask,
                "next_hop":next_hop,
                "interface": intf,
                "prefixlen":netaddr.prefixlen
            })
        self.sorted_forwarding_table = sorted(self.forwarding_table,key=lambda x:x['prefixlen'],reverse=True)
        print("Routing Table:")
        print("{:<20}{:<20}{:<20}{:<20}".format("Network Address","Mask","Next Hop","Interface"))
        for item in self.sorted_forwarding_table:
            print("{:<20}{:<20}{:<20}{:<20}".format(str(item['network_addr']),str(item['mask']),str(item['next_hop']),str(item['interface'].name)))
        self.arp_table={} # create cache arp table
        self.waiting_list={} # queue of ARP packets waiting for resolution

    def match(self,dest_addr):
        for item in self.sorted_forwarding_table:
            prefix = IPv4Address(item["network_addr"])
            mask = IPv4Address(item["mask"])
            dest_ip = IPv4Address(dest_addr)
            # print(f"prefix:{prefix} mask:{mask} dest_ip{dest_ip}\n{int(mask)&int(dest_ip)} {int(prefix)} ")
            matches = (int(mask)&int(dest_ip))==int(prefix)
            if matches == True:
                return item["next_hop"],item["interface"]
        return None

    def send_arp_request(self,dest_ip,interface):
        # construct ARP request packet
        arp_request=Arp()
        arp_request.operation=ArpOperation.Request 
        arp_request.senderhwaddr=interface.ethaddr
        arp_request.senderprotoaddr=interface.ipaddr
        arp_request.targethwaddr='ff:ff:ff:ff:ff:ff'
        arp_request._targetprotoaddr=dest_ip
        # print("successfully create the arp header!")
        # create ethernet packet with ARP request
        ether=Ethernet()
        ether.dst='ff:ff:ff:ff:ff:ff'
        ether.src=interface.ethaddr
        ether.ethertype=EtherType.ARP
        # print("successfully create the ethernet header!")
        # send ARP request
        packet = ether + arp_request
        # print(type(interface))
        # print(type(packet))
        # debugger()
        log_info(f"Sending ARP request {packet}from {interface.name}")
        self.net.send_packet(interface.name,packet)
        print("successfully sended the arp request!\n")

    def send_arp_reply(self,ethdst,targethwaddr,targetprotoaddr,senderprotoaddr,senderhwaddr,interface):
    # construct ARP reply packet
        arp_reply = Arp()
        arp_reply.operation=ArpOperation.Reply
        arp_reply.senderhwaddr=senderhwaddr
        arp_reply.senderprotoaddr=senderprotoaddr
        arp_reply.targethwaddr=targethwaddr
        arp_reply._targetprotoaddr =targetprotoaddr
        # print("successfully create the arp header!")
        # create ethernet packet with ARP request
        ether=Ethernet()
        ether.dst=ethdst
        ether.src=interface.ethaddr
        ether.ethertype=EtherType.ARP
        packet = ether+arp_reply
        # print("successfully create the ethernet header!")
        # send ARP request
        # print(type(interface))
        # print(type(packet))
        # debugger()
        log_info(f"Sending ARP reply {packet}from {interface.name}")
        self.net.send_packet(interface.name,packet)
        print("successfully sended the arp reply!\n")

    def append_waiting_list(self,packet,next_hop,intf):
        if self.waiting_list.get(next_hop) is None:
            print("waiting list hasn't got the item!")
            # print(next_hop)
            # print(type(next_hop))
            #create the queue of packets waiting arp
            queue = [packet]
            self.waiting_list[next_hop]={
                "time":time.time(),
                "retries":0,
                "interface":intf,
                "queue":queue
            }
            print("successfully created the queue!")
            self.send_arp_request(dest_ip = next_hop,interface = intf)
            self.waiting_list[next_hop]["time"] = time.time()
            self.waiting_list[next_hop]["retries"] += 1
        else: 
            print("waiting list has got the item!")
            self.waiting_list[next_hop]["queue"].append(packet)

    def update_arp_cache(self,ipaddr,macaddr):
        self.arp_table[ipaddr] = macaddr # update cache arp table
        print('Cache arp table:')
        print("{:<18}{:<18}".format("IP address","MAC address"))
        for key,value in self.arp_table.items():
            print("{:<18}{:<18}".format(str(key),str(value)))
        print('\n')
        # print(self.waiting_list)
        #send the packets waiting the corresponding arp reply
        if self.waiting_list.get(ipaddr) is not None:
            queue = self.waiting_list[ipaddr]["queue"]
            interface = self.waiting_list[ipaddr]["interface"]
            new_eth = Ethernet()
            new_eth.dst= macaddr
            new_eth.src= interface.ethaddr
            new_eth.ethertype=EtherType.IPv4
            # print(queue)
            for pkt in queue:
                index = pkt.get_header_index(Ethernet)
                if index != -1:
                    del pkt[index]
                pkt.insert_header(0,new_eth)
                log_info(f"sending the packets in waiting queue {pkt} from {interface}")
                self.net.send_packet(interface,pkt)
                print("successfully sended the packet in waiting queue!\n")
            self.waiting_list.pop(ipaddr)

    def forward_packet(self,packet):
        ip_header = packet.get_header(IPv4)
        item = self.match(ip_header.dst)
        if item is not None:# it must be not None,since it has been examine before
            next_hop,intf = item
            print("match successfully!")
            next_hop,intf = self.match(ip_header.dst)
            print(f"next_hop:{next_hop},intf:{intf}")
            if next_hop =="0.0.0.0":
                # print("next_hop is 0.0.0.0")
                macaddr = self.arp_table.get(ip_header.dst)
                if macaddr is not None:
                    # print("get macaddr!")
                    # print(macaddr)
                    new_eth = Ethernet()
                    new_eth.dst= macaddr
                    new_eth.src= intf.ethaddr
                    new_eth.ethertype=EtherType.IPv4
                    index = packet.get_header_index(Ethernet)
                    if index != -1:
                        del packet[index]
                    packet.insert_header(0,new_eth)
                    log_info(f"forwarding packet {packet} from {intf}")
                    self.net.send_packet(intf,packet)
                else:
                    self.append_waiting_list(packet = packet,next_hop = ip_header.dst,intf = intf)
            else:
                #check if the packet needs ARP resolution
                # print(f"next_hop is {next_hop}")
                macaddr = self.arp_table.get(next_hop)
                if macaddr is not None:
                    # print("macaddr is not None")
                    new_eth = Ethernet()
                    new_eth.dst= macaddr
                    new_eth.src= intf.ethaddr
                    new_eth.ethertype=EtherType.IPv4
                    index = packet.get_header_index(Ethernet)
                    if index != -1:
                        del packet[index]
                    packet.insert_header(0,new_eth)
                    log_info(f"forwarding packet {packet} from {intf}")
                    self.net.send_packet(intf,packet)
                else:
                    # print("macaddr is None")
                    self.append_waiting_list(packet = packet,next_hop = next_hop,intf = intf)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"receive packet {packet} from {ifaceName}\n")
        incoming_intf = self.net.interface_by_name(ifaceName)
        eth = packet.get_header(Ethernet)
        if eth.dst != "ff:ff:ff:ff:ff:ff" and eth.dst != incoming_intf.ethaddr:
            return # drop out the packet
        type = eth.ethertype
        if type == EtherType.ARP:
            arp = packet.get_header(Arp)# when the ARP destination IP is held by a port of the router
            if arp.targetprotoaddr in self.intf_ipaddrs:
                if not (arp.operation==ArpOperation.Reply and eth.src=='ff:ff:ff:ff:ff:ff'):
                # if not(eth.src == 'ff:ff:ff:ff:ff:ff' and eth.dst!='ff:ff:ff:ff:ff:ff'):#not trick
                    self.update_arp_cache(ipaddr=arp.senderprotoaddr,macaddr=arp.senderhwaddr)
                    if arp.operation == ArpOperation.Request: #need to send arp reply
                        target_intf = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                        self.send_arp_reply(ethdst = eth.src,targethwaddr=arp.senderhwaddr,targetprotoaddr=arp.senderprotoaddr,senderprotoaddr = target_intf.ipaddr,senderhwaddr = target_intf.ethaddr,interface=incoming_intf)
        elif type == EtherType.IPv4:
            ip_header = packet.get_header(IPv4)
            ip_header.ttl-=1
            if ip_header.dst in self.intf_ipaddrs:
               return # drop the packet
            elif self.match(ip_header.dst) is not None:# succeed matching the correct item
                self.forward_packet(packet)
            else:# there is no macth in the table
                return#drop the packet
        else:
            return 

    def check(self):
        # print("check!")
        delete_list = []
        for key,value in self.waiting_list.copy().items():
            if time.time()-value["time"] > 1:
                if value["retries"]<5:
                    next_hop = key
                    intf = value["interface"]
                    self.send_arp_request(dest_ip = next_hop,interface = intf)
                    self.waiting_list[next_hop]["time"] = time.time()
                    self.waiting_list[next_hop]["retries"] += 1
                else:
                    delete_list.append(key)
        for key in delete_list:
            self.waiting_list.pop(key)

        
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.check()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
   
