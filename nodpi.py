import threading
def debug():
    while 1:
        pass      
threading.Thread(target=debug).start()  

import socket
import random
import asyncio
from utils import get_domain, get_local_ip, fake_host
from threading import Thread
from os import urandom
import yaml


tasks = []

def is_blocked(host):
    
    for site in blocked:
        if host.find(site) >= 0:
            return True

    return False

async def proxy_conn(r, w):

    http_data = await r.read(1500)

    try:
        type, target = http_data.split(b"\r\n")[0].split(b" ")[0:2]
        host, port = target.split(b":")
    except:
        w.close()
        return
        

    if type != b"CONNECT":
        w.close()
        return
    
    w.write(b'HTTP/1.1 200 OK\n\n')
    await w.drain()

    await make_pipe(r, w, host.decode(), int(port))
      

async def ssl_conn(r, w):
    await make_pipe(r, w)


async def main():
    from fake import AsyncSniffer, listen_interface

    if config["proxy"]:
        
        server = await asyncio.start_server(proxy_conn, "0.0.0.0", config["port"])

        print(f'Прокси запущено на {local_ip}:{config["port"]}')

    if config["dns"]:
        from dns import DNSServer, LocalResolve

        server = await asyncio.start_server(ssl_conn, "0.0.0.0", 443)

        dns_server = DNSServer(LocalResolve())
        dns_server.start_thread()

        print(f'DNS сервер запущен {local_ip}')

    AsyncSniffer(prn=listen_interface, store=False).start()
    print(f"Включена откправка фейк пакетов")

    await server.serve_forever()
    

async def pipe(reader, writer):
    while not reader.at_eof() and not writer.is_closing():
        try:
            writer.write(await reader.read(1500))
            await writer.drain()
        except:
            break


    writer.close()



async def make_pipe(local_reader, local_writer, host = None, port = 443):

    if port == 443:
        data = await local_reader.read(1500)
        host = get_domain(data)

    if config["dns"]:
        from dns import resolve
        ip = resolve(host, config["dns_server"])
    else:
        ip = host

    try:
        remote_reader, remote_writer = await asyncio.open_connection(ip, port, family=socket.AF_INET6)
    except:
        local_writer.close()
        return

    if config["debug"]:
        print("Новое подключение", host)


    if (is_blocked(host) or config["debug"]) and port == 443:
        await fragment(data, remote_writer, host)
    elif port == 443:
        remote_writer.write(data)


    tasks.append(asyncio.create_task(pipe(local_reader, remote_writer)))
    tasks.append(asyncio.create_task(pipe(remote_reader, local_writer)))

    
async def fragment(data, remote_writer, host):
    print(1)

    from fake import send_packet, ports, packets
    _, local_port, _, _ = remote_writer.transport.get_extra_info('socket').getsockname()
    ports.append(local_port)

    fake_data = data.replace(host.encode(), fake_host(host).encode())
    #fake_data = data.copy()

    i=0

    print(2)

    while data:
        remote_writer.write(data[:1])
        await remote_writer.drain()
        i+=1

        data = data[1:]
        fake_data = fake_data[1:]

        print(3)

        if await send_packet(data[:98], local_port):
            await asyncio.sleep(1)
            data = data[98:]
            remote_writer.write(urandom(98)+data)
            await remote_writer.drain()
            print(1)
            break

    print(data.hex())

    #remote_writer.write(data)
    #await remote_writer.drain()
            
        

 

config = yaml.safe_load(open("config.txt").read())
blocked = open("russia-blacklist.txt").read().split()
local_ip = get_local_ip()

if __name__ == "__main__":
    

    print("Версия: 3.0")
    print("Не закрывайте окно")

    asyncio.run(main())
    
    




