import pickle
import ssl
import socket
import threading

from shared.config import Addreses
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import winreg as reg
import logging
import pyotp
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Client:
    def __init__(self):
        self.client_socket=None
        self.SERVER_CA_CERT = """-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUB7BpPzwbWbK9HDxPMHIqlN/WFDgwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MQ4wDAYDVQQKDAVNeU9yZzEPMA0GA1UECwwGTXlVbml0MQ0wCwYDVQQDDARNeUNB
MB4XDTI0MDkzMDIwNTk1OFoXDTI1MDkzMDIwNTk1OFowXDELMAkGA1UEBhMCVVMx
DjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MQ4wDAYDVQQKDAVNeU9yZzEP
MA0GA1UECwwGTXlVbml0MQ0wCwYDVQQDDARNeUNBMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAzfOpSNiwB/Fuopxo0VAfyu/2zbCg7EDMA67c2LyKAcVW
RG9ZMylfuLi/OdjYq26QIXM8rLj8qRBXgjj7AHklSXLD3kULGdoEhzROnZEjNdQu
hUtPGx8NcYY+5B1Jj5fjJtJ5O5CLGEaPkra3pyicKM2PIqJSTvXuAzUHttoUpyyc
lktrogMM6zAdla03YxeXW4Sgzjo+qXqh5Ncl06p/2RVTCQPqxuMO/Ar7I8GCNu6u
u7RXtok2QLHBRLsK6nHXeT+pyMYbFd24xucYRT5CJR7M2bAgoMilBo7Mo1Oy29C/
svQghw2/9D29vq27NAT2yBBbkm9owXlK2XFI5FhiGQIDAQABo1MwUTAdBgNVHQ4E
FgQUIFyYcMH7p9YXdScqxCzV4jCN6uMwHwYDVR0jBBgwFoAUIFyYcMH7p9YXdScq
xCzV4jCN6uMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFB86
hhIxQnMsL2yLFzU6i/G7jC/uNPC9JJKxtQ81Pbz7FJO4xKsVSugiSVBQG4AGz1+e
m91JRaI7kqbQ7y8gTr7KM5fDWmTvlAt481Lq98eGMY+O0T+N+HTccHrR22Rgg+Ew
/v0gGidNJfof1as1rmIt9FjccdvQubnU6VwLytTpO3PByvTl4nampjPh/LO1sF8z
rrY1dzTX3bVVXM/hjhLtnga9Mhx8iKtvJsmo6ubMaG7mPdODS7uLgGkWJw0aA63Q
EVNmVkMFGkZhQiemiwng1bTLKwTr7yYc6yQ/Y9Q8j4Y2k2rcWCg2ROvG2YqQ5b1l
dzZQuZXVEEtJjarOdw==
-----END CERTIFICATE-----
"""
    def create_initial_certificates(self):
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem = client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open("certificates/initial_client_key.pem", "wb") as key_file:
            key_file.write(pem)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")])).sign(client_private_key,hashes.SHA256(),default_backend())

        cert = x509.CertificateBuilder().subject_name(csr.subject)
        cert = cert.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")]))
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.public_key(csr.public_key())
        cert = cert.not_valid_before(datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365))
        cert = cert.sign(client_private_key, hashes.SHA256(), default_backend())
        with open("certificates/initial_client_cert.pem", "wb") as key_file:
            key_file.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_certificates(self,username,password,totp, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CERT): # TODO- MOVE TO AUTH_SERVER
        self.create_initial_certificates()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_socket.connect((host, port))
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="certificates/initial_client_cert.pem", keyfile="certificates/initial_client_key.pem")
        context.load_verify_locations(cadata=self.SERVER_CA_CERT)
        print(f"Client connected to {Addreses.SERVER_IP}:{Addreses.SERVER_PORT}")

        secure_socket = context.wrap_socket(client_socket, server_side=False)
        user_dict={"username":username,"password":password,"totp":totp}
        secure_socket.send(pickle.dumps(user_dict))
        msg=secure_socket.recv(4096)
        if pickle.loads(msg)==-1:
            print("Wrong username or password!")
            return
        client_cert,client_key=pickle.loads(msg)
        with open("certificates/client_cert.pem", "wb") as file:
            file.write(client_cert)
        with open("certificates/client_key.pem", "wb") as file:
            file.write(client_key)

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_verify_locations(cadata=self.SERVER_CA_CERT)
        context.load_cert_chain(certfile="certificates/client_cert.pem", keyfile="certificates/client_key.pem")
        return context

    def create_client_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT):
        context=self.create_ssl_context()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host,port))
        print(f"Client connected to {Addreses.SERVER_IP}:{Addreses.SERVER_PORT}")
        self.client_socket = context.wrap_socket(client_socket, server_side=False) #TODO- change to True


    def start_local_proxy_server(self,host="127.0.0.1",port=8080):
        local_server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        local_server.bind((host,port))
        local_server.listen(5)
        print(f"Local proxy server listening on {host}:{port}")
        while True:
            conn,addr=local_server.accept()
            threading.Thread(target=self.handle_local_clients,args=(conn,)).start()
    def handle_local_clients(self,local_client):
        request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_socket.connect((Addreses.SERVER_IP, Addreses.SERVER_PORT))
        context = self.create_ssl_context()
        server_socket = context.wrap_socket(request_socket, server_side=False)

        threading.Thread(target=self.forward_data, args=(local_client, server_socket), daemon=True).start()
        threading.Thread(target=self.forward_data, args=(server_socket, local_client), daemon=True).start()

        # request = b''
        # try:
        #     while True:
        #         data = conn.recv(4096)
        #         if not data:
        #             break
        #         request += data
        #         if len(data) < 4096:
        #             break
        #     if not request:
        #         conn.close()
        #         return
        #     secure_socket.sendall(request)
        #
        #     # Get response from server
        #     response = b''
        #     while True:
        #         data = secure_socket.recv(4096)
        #         if not data:
        #             print("break")
        #             break
        #         response += data
        #         if len(data) < 4096:
        #             print("break2")
        #             break
        #     print(response)
        #     # Send the response back to the local application
        #     conn.sendall(response)
        # except Exception as e:
        #     print(f"Error handling local client: {e}")
        #     raise e
        # finally:
        #     conn.close()
    def forward_data(self, src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
                logging.info(f"Forwarded {len(data)} bytes from {src.getpeername()} to {dst.getpeername()}")
        except Exception as e:
            logging.error(f"Error forwarding data: {e}")

    def enable_proxy(self, addr):
        internet_settings = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        try:
            with reg.OpenKey(reg.HKEY_CURRENT_USER, internet_settings, 0, reg.KEY_SET_VALUE) as key:
                reg.SetValueEx(key, 'ProxyServer', 0, reg.REG_SZ, addr)
                reg.SetValueEx(key, 'ProxyEnable', 0, reg.REG_DWORD, 1)
                print(f'Proxy settings updated: {addr}')
                return True
        except Exception as error:
            print(f'ERROR: {str(error)}')
        return False

if __name__ == "__main__":
    client = Client()
    client.create_initial_certificates()
    totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET")
    client.get_certificates("aviv", "12345678",totp.now())
    client.create_client_socket()
    client.start_local_proxy_server()
    client.enable_proxy('127.0.0.1:8080')


