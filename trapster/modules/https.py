from trapster.modules.http import HttpHandler, HttpHoneypot, HeaderCapitalizationMiddleware

import ssl
import asyncio
import uvicorn
from fastapi import Request
from pathlib import Path
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

from pathlib import Path
import ssl
import datetime

class HttpsHandler(HttpHandler):
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.protocol_name = "https"

class HttpsHoneypot(HttpHoneypot):
    """common class to all trapster instance"""

    def __init__(self, config, logger, bindaddr="0.0.0.0"):
        super().__init__(config, logger, bindaddr)
        self.handler = HttpsHandler(config=config, logger=logger)

        self.COUNTRY_NAME = config.get("country_name") or None
        self.STATE_OR_PROVINCE_NAME = config.get("state_or_province_name") or None
        self.LOCALITY_NAME = config.get("locality_name") or None
        self.ORGANIZATION_NAME = config.get("organization_name") or None
        self.COMMON_NAME = config.get("common_name", "server.internal")
        
        self.key_path = Path(config.get("key", "/etc/trapster/ssl/key.pem"))
        self.certificate_path = Path(config.get("certificate", "/etc/trapster/ssl/certificate.pem"))

        self.generate_certificate()
    
    async def start(self):
        self.handler.setup()
        
        @self.fastapi_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"])
        async def catch_all(request: Request, path: str):
            return await self.handler.handle_request(request)
        
        # Now wrap the FastAPI app with custom ASGI middleware for header capitalization
        self.app = HeaderCapitalizationMiddleware(self.fastapi_app)
        
        # Start the server in a background task
        loop = asyncio.get_running_loop()
        self.task = loop.create_task(self._start_server())
        return self.task
    
    async def _start_server(self):
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certificate_path, keyfile=self.key_path)
        
        config = uvicorn.Config(
            app=self.app,
            host=self.bindaddr,
            port=self.port,
            log_level="error",
            access_log=False,
            server_header=False,
            ssl_keyfile=str(self.key_path),
            ssl_certfile=str(self.certificate_path)
        )
        self.server = uvicorn.Server(config)
        await self.server.serve()

    def generate_certificate(self):
        '''
        Regenerate the certificate at each startup to ensure the configuration values are applied and reflected.
        '''
        #if self.certificate_path.exists() and self.key_path.exists():
        #    return
        #else:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)

        key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()        
        ))

        name_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.COUNTRY_NAME) if self.COUNTRY_NAME else None,
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME) if self.STATE_OR_PROVINCE_NAME else None,
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.LOCALITY_NAME) if self.LOCALITY_NAME else None,
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME) if self.ORGANIZATION_NAME else None,
            x509.NameAttribute(NameOID.COMMON_NAME, self.COMMON_NAME),
        ]
        subject = issuer = x509.Name(filter(None, name_attributes))

        alt_names = x509.SubjectAlternativeName([x509.DNSName('localhost'),])

        certification = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now())
            .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=3650))
            .add_extension(alt_names, False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(self.certificate_path, "wb") as f:
            f.write(certification.public_bytes(serialization.Encoding.PEM))
