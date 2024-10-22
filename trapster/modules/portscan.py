from trapster.modules.base import BaseHoneypot
import asyncio
import aiofiles
import logging
import subprocess
import os
import pwd
import grp
from pathlib import Path

class PortscanHoneypot(BaseHoneypot):
    def __init__(self, config, logger, bindaddr=None):
        self.protocol_name = "portscan"
        self.config = config or {}
        self.logger = logger
        self.filename = self.config.get("filename", "/var/log/portscan.log")
        self.remove_nft_rules = os.path.dirname(__file__)+"/../data/portscan/remove_nftable_rules.sh"
        self.logger_rules = os.path.dirname(__file__)+"/../data/portscan/nft_rules.nft"
        self.nft_rules = os.path.dirname(__file__)+"/../data/portscan/nft_trapster_rules.nft"
        self.nft_config_file = Path('/etc/rsyslog.d/nftables.conf')
        self.interval = 5
        self.file = None
        self.last_pos = 0
        self.loop = asyncio.get_running_loop()

    async def read_file(self):
        pos = await self.get_last_pos()

        if pos > self.last_pos:
            async with aiofiles.open(self.filename, mode='r') as file:
                await file.seek(self.last_pos)
                content = await file.read(pos - self.last_pos)

            self.last_pos = pos
            
            if content:
                await self.parse_log(content)

    async def parse_log(self, content):
        lines = content.splitlines()
        for line in lines:
            if "SYN: " in line:
                split = "SYN: "
                specific_name = 'SYNportscan'
            elif "NULL: " in line:
                split = "NULL: "
                specific_name = 'NULLportscan'
            elif "FIN: " in line:
                split = "FIN: "
                specific_name = 'FINportscan'
            elif "OS: " in line:
                split = "OS: "
                specific_name = 'OSportscan'
            else:
                continue
            
            flags = line.split('RES=')[-1].split(' ')[1:-2]
            data = line.split('RES=')[0].split(split)[-1].split(' ')
            data_dictionary = {}
            for item in data:
                if '=' in item:  
                    key, value = item.split('=', 1)
                    data_dictionary[key] = value
                else:
                    data_dictionary[item] = None

            self.logger.log(specific_name + "." + self.logger.QUERY, None, extra={
                "src_ip" : data_dictionary['SRC'], 
                "dst_ip" : data_dictionary['DST'], 
                "dst_port" : data_dictionary['SPT'],
                "src_port" : data_dictionary['DPT'],
                "flags" : flags
                })  
        return

    async def create_nft_config(self):
        print('Config doesnt exist')
        self.nft_config_file.touch()
        async with aiofiles.open(self.logger_rules, mode='r') as file:
            content = await file.read()
            content = content.format(filename=self.filename)
        async with aiofiles.open(self.nft_config_file, mode='w') as file:
            await file.write(content) 
        subprocess.run(['sudo', '/usr/bin/systemctl', 'restart', 'rsyslog'])
        print('Created config')

    async def get_last_pos(self):
        async with aiofiles.open(self.filename, mode='r') as file:
            await file.seek(0, 2)
            return await file.tell()

    async def _start_server(self):
        print('Removing old Trapster NFTable rules and replace')
        await self.remove_rules()
        subprocess.run(['sudo', 'nft', '-f', self.nft_rules])

        try:
            self.last_pos = await self.get_last_pos()
        except FileNotFoundError:
            print('Creating log file')
            path = Path(self.filename)
            subprocess.run(['sudo', 'touch', self.filename])
            subprocess.run(['sudo', 'chmod', "640", self.filename])
            uid = pwd.getpwnam('syslog').pw_uid
            gid = grp.getgrnam('adm').gr_gid
            os.chown(path, uid, gid)
            self.last_pos = await self.get_last_pos()
            subprocess.run(['sudo', '/usr/bin/systemctl', 'restart', 'rsyslog'])
            #recreate config
            subprocess.run(['sudo', 'rm', self.nft_config_file])
            
        #Create config file if doesnt exist
        if not os.path.exists(self.nft_config_file):
            await self.create_nft_config()

        while True:
            await self.read_file()
            await asyncio.sleep(self.interval)

    async def remove_rules(self):
        subprocess.run(['sudo', 'bash', self.remove_nft_rules], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    async def stop(self):
        #clean nftable rules
        await self.remove_rules()
        await super().stop()

