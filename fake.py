
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import AsyncSniffer, sendp
from os import urandom
from nodpi import config, local_ip
import asyncio
from base64 import b32encode
from dnslib.dns import DNSRecord, RR, QTYPE, A, DNSQuestion
import socket
from threading import Thread
from time import sleep

ports = [4444]
packets = {}
ttl = {}
to_fake = []

async def send_packet(data, to_port):
    await asyncio.sleep(0.2)
    
    if not packets.get(to_port):
        return False

    data = packets[to_port]["src"] + packets[to_port]["dst"] + packets[to_port]["ack"] + to_port.to_bytes(2) + packets[to_port]["ack2"] + data

    data = b32encode(data).decode()
    data = data.replace("=", "")


    res = "a.0x0.tel"

    for i in range(4):
        res = data[-60:] + "." + res
        data = data[:-60]

    r = DNSRecord()
    r.add_question(DNSQuestion(res))
    r.send("2a01:540:41f:ff00:c911:d325:a937:c65b", ipv6=True, tcp=True)

    del packets[to_port]

    return True

def listen_interface():
    s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while 1:
        tcp, ip = s.recvfrom(10000)
        tcp = TCP(tcp)
        ip = ip[0]
        
        if tcp.dport in ports:
            packets[tcp.dport] = {}
            packets[tcp.dport]["src"] = ip
            packets[tcp.dport]["dst"] =  local_ip
            packets[tcp.dport]["seq"] = tcp.ack
            packets[tcp.dport]["ack"] = tcp.seq + len(tcp.payload)
            tcp.show2()

if __name__ == "__main__":
    Thread(target=listen_interface).start()

