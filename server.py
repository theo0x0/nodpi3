from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer, sendp, sr, sr1, send
from dnslib.server import DNSServer, BaseResolver
from base64 import b32decode
import socket
import time
from threading import Thread
import json


class LocalResolve(BaseResolver):
    def resolve(self,request,handler):

            q = request.questions[0]


            q = str(q.qname).replace(".a.0x0.tel", "").replace(".", "")
            data = b32decode(q)

            src = socket.inet_ntop(socket.AF_INET6, data[:16])
            dst = socket.inet_ntop(socket.AF_INET6, data[16:32])
            seq = int.from_bytes(data[32:36])
            to_port = int.from_bytes(data[36:38])
            ack = int.from_bytes(data[38:42])

            data = data[42:]

            ip = IPv6(src=src, dst=dst)
            tcp = TCP(sport = to_port, dport=443, ack=ack+1, seq=seq, flags="PA")
            tcp.payload = Raw(data)
            send(ip/tcp)
        
            return request.reply()


dns_server = DNSServer(LocalResolve(), address="2a01:540:41f:ff00:c911:d325:a937:c65b", tcp=True)
dns_server.start_thread()