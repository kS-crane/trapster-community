from .base import BaseProtocol, BaseHoneypot, UdpTransporter
from .libs import dns
import asyncio, logging
from datetime import datetime, timezone
from struct import unpack, pack
import socket
import random



class LlmnrUdpProtocol(BaseProtocol):
    def __init__(self, config=None):
        if config:
            self.config = config
        self.protocol_name = "llmnr"
        self.llmnr_port = 5355
        self.llmnr_address = '224.0.0.252'
        self.timing = self.config.get('time', 18000)
        self.machine = self.config.get('machine', 'D')
        self.jitter = self.config.get('jitter', 1800)
    
    def connection_made(self, transport) -> None:
        self.transport = transport
        self.loop = asyncio.get_running_loop()
        self.loop.create_task(self.broadcast_llmnr_message())

    def datagram_received(self, data, addr):
        src_ip, src_port = addr
        dst_ip, dst_port = self.transport.get_extra_info('sockname')
        transport_udp = UdpTransporter(dst_ip, dst_port, src_ip, src_port)
        data = dns.decode_dns_message(data) # Take function from dns module
        self.logger.log(self.protocol_name + "." + self.logger.DATA, transport_udp, extra={"query": data})
        
    def parse_llmnr(self, data):
        data = data.decode()
        return data

    def llmnr_query(self):
        """Constructs LLMNR query in DNS format."""
        query = pack(">H", 0x000)  # Random transaction ID
        query += pack(">H", 0x0000 ) #flagsmachine
        query += pack(">H", 1)  #questions
        query += pack(">H", 0)  #answer
        query += pack(">H", 0)  #authority resource 
        query += pack(">H", 0)  #additional

        # Create the DNS query structure
        for part in self.machine.split("."):
            query += pack('B', len(part)) + part.encode('utf-8')
        
        query += pack("B", 0)
        query += pack(">H", 1)
        query += pack(">H", 1) 
        return query

    async def broadcast_llmnr_message(self):
        """Broadcast LLMNR messages to the LLMNR multicast address."""
        print(self.timing, self.machine, self.jitter)
        llmnr_message = self.llmnr_query()  # Specify the name to resolve
        self.transport.sendto(llmnr_message, (self.llmnr_address, self.llmnr_port))
        print(f"Broadcasted LLMNR: {self.machine}")
        total_time = self.timing + random.uniform(-self.jitter, self.jitter)
        await asyncio.sleep(total_time)
        try:
            
            while True:
                llmnr_message = self.llmnr_query()  # Specify the name to resolve
                self.transport.sendto(llmnr_message, (self.llmnr_address, self.llmnr_port))
                print(f"Broadcasted LLMNR: {self.machine}")
                total_time = self.timing + random.uniform(-self.jitter, self.jitter)
                await asyncio.sleep(total_time)
        except Exception as e:
            logging.error(f'[-] LLMNR broadcasting error: {e}')
        except:
            logging.info("LLMNR broadcasting stopped: ")


class LlmnrHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr='0.0.0.0'):
        self.handler = lambda: LlmnrUdpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
        self.llmnr_port = 5355

        self.bindaddr = bindaddr

    async def _start_server(self):
        #listens on tcp + udp port 5355
        loop = asyncio.get_event_loop()

        transport, protocol = await loop.create_datagram_endpoint(lambda: self.handler(), 
             local_addr=(self.bindaddr, self.llmnr_port))
        
