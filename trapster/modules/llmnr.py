from .base import BaseProtocol, BaseHoneypot, UdpTransporter
from .libs import dns
import asyncio, logging
from datetime import datetime, timezone
from struct import unpack, pack


class LlmnrUdpProtocol(BaseProtocol):

    def __init__(self, config=None):
        self.protocol_name = "llmnr"
        self.llmnr_address = '224.0.0.252'
        self.llmnr_port = 5353

        if config:
            self.config = config
    
    def connection_made(self, transport):
        self.transport = transport
        asyncio.ensure_future(self.send_llmnr_request())

    async def send_llmnr_request(self):
       while True:
            llmnr_message = self.llmnr_query("www.hewow.com")  # Specify the name to resolve
            print('Sending LLMNR query:')
            self.transport.sendto(llmnr_message, (self.llmnr_address, self.llmnr_port))
            await asyncio.sleep(1) 
    
    def llmnr_query(self, name):
        """Constructs the LLMNR query in DNS format."""
        query = pack(">H", 0x1234)  # Random transaction ID
        query += pack(">H", 0x0100 ) #flags
        query += pack(">H", 1)  #questions
        query += pack(">H", 0)  #answer
        query += pack(">H", 0)  #authority resource 
        query += pack(">H", 0)  #additional

        # Create the DNS query structure
        for part in name.split("."):
            query += pack('B', len(part)) + part.encode('utf-8')
        
        query += pack("B", 0)
        query += pack(">H", 1)
        query += pack(">H", 1) 
        return query


    
    def datagram_received(self, data, addr):
        src_ip, src_port = addr
        dst_ip, dst_port = self.transport.get_extra_info('sockname')
        transport_udp = UdpTransporter(dst_ip, dst_port, src_ip, src_port)
        data = dns.decode_dns_message(data) # Take function from dns module
        self.logger.log(self.protocol_name + "." + self.logger.DATA, transport_udp, extra={"query": data})

        
    def parse_llmnr(self, data):
        data = data.decode()
        print(data)
        return data


class LlmnrHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr):
        #self.handler = lambda: LlmnrDPProtocol(config=configtcp*
        self.handler = lambda: LlmnrUdpProtocol(config=config)
        self.handler.logger = logger
        self.handler.config = config
        self.llmnr_port = 5355
        self.llmnr_address = '224.0.0.252'

        self.handler_udp = LlmnrUdpProtocol
        self.bindaddr = bindaddr 

    async def _start_server(self):
        #listens on tcp + udp port 5355
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(lambda: self.handler_udp(), 
                                    local_addr=(self.llmnr_address, self.llmnr_port))
        


