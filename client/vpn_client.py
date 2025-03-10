# from docutils.nodes import header
import pickle
import ssl
import socket
import threading
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addreses
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import winreg as reg
import logging
import pyotp
import os.path
from OpenSSL import crypto
import time
import ctypes
import winreg
import select

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
BUFFER_SIZE = 65536

class Client:
    def __init__(self):
        self.client_socket = None
        self.control_socket= None
        self.proxy_list=[]
        self.data_sent=0
        self.current_index=0
        self.stats= {
        "window_size": 5,
        "total_bytes": 0,
        "current_index": 0,
        "arr": [0] * 5,
        "last_time": int(time.time()),
        "active_seconds": 0
        }
        with open("certificates/ca_cert.pem", "r") as key_file:
            self.SERVER_CA_CERT = key_file.read()
        self.next_channel_id=0
        self.local_channel_map={}
        self.send_lock = threading.Lock()
        self.serial=None
    def create_initial_certificates(self):
        logger.info("Generating initial client certificates.")
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

        with open(Addreses.CLIENT_INITIAL_KEY_PATH, "wb") as key_file:
            key_file.write(pem)

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")])
        ).sign(client_private_key, hashes.SHA256(), default_backend())

        cert = x509.CertificateBuilder() \
            .subject_name(csr.subject) \
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")])) \
            .serial_number(x509.random_serial_number()) \
            .public_key(csr.public_key()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
            .sign(client_private_key, hashes.SHA256(), default_backend())

        with open(Addreses.CLIENT_INITIAL_CERT_PATH, "wb") as key_file:
            key_file.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_certificates(self, username, password, totp, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CERT):
        logger.info("Retrieving certificates from the authentication server.")

        try:
            client_socket = socket.create_connection((host, port))
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_cert_chain(
                certfile=Addreses.CLIENT_INITIAL_CERT_PATH,
                keyfile=Addreses.CLIENT_INITIAL_KEY_PATH,
            )
            context.load_verify_locations(cadata=self.SERVER_CA_CERT)
            context.check_hostname = False

            secure_socket = context.wrap_socket(client_socket, server_side=False)
            user_dict = {"username": username, "password": password, "totp": totp}
            secure_socket.send(pickle.dumps(user_dict))
            msg = secure_socket.recv(BUFFER_SIZE)
            if pickle.loads(msg) == -1:
                logger.warning("Authentication failed!")
                return -1

            client_cert, client_key,serial = pickle.loads(msg)
            self.serial=serial
            with open(Addreses.CLIENT_CERT_PATH, "wb") as file:
                file.write(client_cert)
            with open(Addreses.CLIENT_KEY_PATH, "wb") as file:
                file.write(client_key)
        except Exception as e:
            logger.error(f"Error retrieving certificates: {e}")
            raise

    def create_ssl_context(self):
        logger.info("Creating SSL context.")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cadata=self.SERVER_CA_CERT)
        context.load_cert_chain(certfile=Addreses.CLIENT_CERT_PATH,
                                keyfile=Addreses.CLIENT_KEY_PATH)
        return context

    def create_client_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT):
        logger.info("Establishing secure connection to the server.")
        context = self.create_ssl_context()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:

            client_socket.connect((host, port))
            # Provide a hostname if needed, or disable hostname check
            context.check_hostname = False
            self.client_socket = context.wrap_socket(
                client_socket,
                server_side=False,
                server_hostname="clientVPN.example.com"
            )
            logger.info(f"Client connected to {Addreses.SERVER_IP}:{Addreses.SERVER_PORT}")


            server_cert_binary = self.client_socket.getpeercert(binary_form=True)
            if server_cert_binary:
                try:
                    # Convert the DER bytes from the server into an x509 object
                    server_cert_obj = x509.load_der_x509_certificate(
                        server_cert_binary, default_backend()
                    )
                    # logger.info(f"Parsed Server Certificate Subject: {server_cert_obj.subject}")
                    # logger.info(f"Parsed Server Certificate Issuer: {server_cert_obj.issuer}")
                    # logger.info(f"Certificate Serial Number: {server_cert_obj.serial_number}")
                    # logger.info(f"Certificate Valid From: {server_cert_obj.not_valid_before}")
                    # logger.info(f"Certificate Valid Until: {server_cert_obj.not_valid_after}")

                    # Compare with known/expected server certificate on disk
                    try:
                        with open("certificates/server_cert.pem", "rb") as f:
                            known_cert_bytes = f.read()
                        known_cert_obj = x509.load_pem_x509_certificate(
                            known_cert_bytes, default_backend()
                        )

                        # Compare fingerprints (SHA-256)
                        server_fingerprint = server_cert_obj.fingerprint(hashes.SHA256())
                        known_fingerprint = known_cert_obj.fingerprint(hashes.SHA256())

                        if server_fingerprint == known_fingerprint:
                            logger.info("Server certificate matches the known certificate.")
                        else:
                            logger.error("Server certificate does NOT match the known certificate!")
                            # Optionally raise an exception or terminate
                            # raise ssl.SSLError("Server certificate mismatch")
                    except FileNotFoundError:
                        logger.warning(
                            "No known server certificate file found at certificates/server_cert.pem. "
                            "Skipping direct comparison."
                        )
                except Exception as e:
                    logger.error(f"Failed to parse server certificate or compare: {e}")
            else:
                logger.warning("Failed to retrieve server certificate.")
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            raise e

    def start_local_proxy_server(self, host=Addreses.LOCAL_PROXY_IP, port=Addreses.LOCAL_PROXY_PORT):
        logger.info(f"Starting local proxy server on {host}:{port}")
        local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            local_server.bind((host, port))
            local_server.listen(5)
            logger.info(f"Local proxy server listening on {host}:{port}")

            header = {"type": "CHANGE_NAME", "channel_id": 0}
            self.send_frame(header, str(self.serial).encode())

            while True:
                conn, addr = local_server.accept()
                threading.Thread(target=self.handle_local_clients, args=(conn,), daemon=True).start()
                # TODO need to be threading??
        except Exception as e:
            logger.error(f"Error in proxy server: {e}")
            raise e
        finally:
            local_server.close()


    def handle_local_clients(self, local_client_socket):
        channel_id= self.next_channel_id
        self.next_channel_id+=1
        self.local_channel_map[channel_id]= local_client_socket
        header = {"type": "OPEN_CHANNEL","channel_id": channel_id}
        self.send_frame(header, b"\x00")
        # threading.Thread(
        #     target=self.forward_local_to_server,
        #     args=(channel_id, local_client_socket),
        #     daemon=True
        # ).start()

        # try:
        #     request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     request_socket.connect((Addreses.SERVER_IP, Addreses.SERVER_PORT))
        #     context = self.create_ssl_context()
        #     server_socket = context.wrap_socket(request_socket,
        #                                         server_side=False,
        #                                         server_hostname="clientVPN.example.com")
        #
        #     threading.Thread(target=self.forward_data, args=(local_client, server_socket), daemon=True).start()
        #     threading.Thread(target=self.forward_data_to_client, args=(server_socket, local_client), daemon=True).start()
        # except Exception as e:
        #     logger.error(f"Error handling local client: {e}")
        #     raise e

    def forward_local_to_server(self, channel_id, local_socket):
        try:
            while True:
                data = local_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                header = {"type": "DATA", "channel_id": channel_id}
                self.send_frame(header, data)
        except Exception as e:
            logging.error(f"Error in forward_local_to_server: {e}")
        finally:
            self.send_frame({"type": "CLOSE_CHANNEL", "channel_id": channel_id}, b"")

    def send_frame(self, header, payload):
        import pickle
        frame = pickle.dumps((header, payload))
        frame_len = len(frame).to_bytes(4, "big")

        # print(f"Sending frame of size {len(frame)} bytes")  # Debugging output

        # Validate if the socket is still open before sending
        if not hasattr(self, 'client_socket') or not isinstance(self.client_socket, socket.socket):
            print("Error: client_socket is no longer a valid socket")
            return

        with self.send_lock:  # Ensure thread safety #TODO understand lock
            try:
                self.client_socket.sendall(frame_len + frame)
            except (ssl.SSLError, OSError) as e:
                print(f"Socket Error while sending: {e}")
                self.client_socket.close()



    def read_loop(self):
        self.client_socket.settimeout(0.5)  # Set a short timeout to prevent blocking

        while True:
            sockets_to_monitor = [self.client_socket] + [sock for sock in self.local_channel_map.values() if sock]
            readable, _, _ = select.select(sockets_to_monitor, [], [], 0.5)


            for sock in readable:
                if sock is self.client_socket:

                    try:
                        length_bytes = sock.recv(4)
                    except (ssl.SSLWantReadError, socket.timeout, BlockingIOError):
                        continue  # No data available, retry in the next loop

                    if not length_bytes:
                        print("Server disconnected")
                        return  # Exit the loop

                    frame_len = int.from_bytes(length_bytes, 'big')

                    frame_data = b""
                    while len(frame_data) < frame_len:
                        try:
                            chunk = sock.recv(frame_len - len(frame_data))
                            if not chunk:
                                break
                            frame_data += chunk
                        except (ssl.SSLWantReadError, socket.timeout, BlockingIOError,ConnectionResetError):
                            continue  # Wait for more data

                    if frame_data:
                        header, payload = pickle.loads(frame_data)
                        channel_id = header["channel_id"]
                        if header["type"] == "CLOSE_CHANNEL":
                            current_socket = self.local_channel_map.pop(channel_id, None)
                            if current_socket:
                                current_socket.close()
                        elif header["type"] == "DATA":
                            current_socket = self.local_channel_map[channel_id]
                            try:
                                current_socket.sendall(payload)
                                # logger.info(f"Forwarded {len(payload)} bytes from client to {current_socket.getpeername()}")
                            except Exception as e:
                                logger.error(f"Failed in reading loop: {e}")

                else:
                    try:
                        data = sock.recv(BUFFER_SIZE)
                    except (ssl.SSLWantReadError, socket.timeout, BlockingIOError,ConnectionAbortedError):
                        continue  # No data available

                    if data:
                        channel_id = next((k for k, v in self.local_channel_map.items() if v == sock), None)
                        if channel_id is not None:
                            # logger.info(f"Forwarded {len(data)} bytes from {sock.getpeername()} to client")
                            self.send_frame({"type": "DATA", "channel_id": channel_id}, data)

    def forward_data(self, src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
                # logger.info(f"Forwarded {len(data)} bytes from {src.getpeername()} to {dst.getpeername()}")
        except Exception as e:
            logger.error(f"Error forwarding data: {e}")
            raise e
        finally:
            src.close()
            dst.close()
    def forward_data_to_client(self, src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
                self.update(len(data))
                # logger.info(f"Forwarded {len(data)} bytes from {src.getpeername()} to {dst.getpeername()}")
        except Exception as e:
            logger.error(f"Error forwarding data: {e}")
            raise e
        finally:
            src.close()
            dst.close()

    def update(self,l):
        temp_index = self.stats["current_index"]
        if int(time.time()) - self.stats["last_time"] > 0:
            for _ in range(min(self.stats["window_size"], int(time.time()) - self.stats["last_time"])):
                temp_index = (temp_index + 1) % self.stats["window_size"]
                self.stats["total_bytes"] -= self.stats["arr"][temp_index]
                if self.stats["arr"][temp_index] > 0:
                    self.stats["active_seconds"] -= 1
                    self.stats["arr"][temp_index] = 0
            self.stats["current_index"] = temp_index
        if self.stats["arr"][self.stats["current_index"]] == 0:
            self.stats["active_seconds"] += 1
        self.stats["arr"][self.stats["current_index"]] += l
        self.stats["total_bytes"] += l
        self.stats["last_time"] = int(time.time())

    def calculate_speed(self):
        speed= self.stats["total_bytes"] / self.stats["window_size"]
        if speed <= 1024:
            return str(speed) + " Bytes"
        if speed <= 1048576:
            return str(round((speed / 1024),2)) + "KB"
        return str(round((speed / 1048576),2)) + "MB"

    def set_registry_value(self,name, value):
        REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        reg_type = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, name, 0, reg_type, value)
        except Exception as e:
            logger.error(f"Failed to set {name}: {e}")

    def get_registry_value(self,name):
        REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except FileNotFoundError:
            return None
    def enable_proxy(self, addr):
        REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        def elevate():
            if ctypes.windll.shell32.IsUserAnAdmin():
                return  # Already running as Administrator

            # Relaunch the script with admin privileges
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

        elevate()

        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                logger.error("Program needs to run as administrator")
                return
        except:
            logger.error("Program needs to run as administrator")
            return

        proxy_enable = self.get_registry_value("ProxyEnable")
        if proxy_enable != 1:
            self.set_registry_value("ProxyEnable", 1)

        proxy_server = self.get_registry_value("ProxyServer")
        if proxy_server != addr:
            self.set_registry_value("ProxyServer", addr)
    def remove_proxy(self):
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                logger.error("Program needs to run as administrator")
                return
        except:
            logger.error("Program needs to run as administrator")
            return

        proxy_enable = self.get_registry_value("ProxyEnable")
        if proxy_enable != 0:
            self.set_registry_value("ProxyEnable", 0)

    def check_certificates(self):
        """
        Checks if existing client cert + key are present and still valid (not expired).
        If not present or expired, we must regenerate or fetch new certs.
        """
        if os.path.isfile(Addreses.CLIENT_CERT_PATH) and os.path.isfile(Addreses.CLIENT_KEY_PATH):
            with open(Addreses.CLIENT_CERT_PATH, 'r') as cert_file:
                cert_data = cert_file.read()
            x509_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            not_after_bytes = x509_cert.get_notAfter()
            timestamp = not_after_bytes.decode('utf-8').rstrip('Z')
            expiration_date = datetime.datetime.strptime(timestamp, '%Y%m%d%H%M%S')
            # The below line triggers DeprecationWarning in Python 3.12 and up
            current_time = datetime.datetime.utcnow()
            if current_time > expiration_date:
                return False
            return True
        else:
            return False
    def connect_to_control_server(self,host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CONTROL):
        logger.info(f"Connecting to control server at {host}:{port}")
        context = self.create_ssl_context()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        context.check_hostname = False
        self.control_socket = context.wrap_socket(
            sock,
            server_side=False,
            server_hostname="clientVPN.example.com"
        )
        try:
            self.control_socket.sendall("LIST_PROXIES".encode() + b"\n")
            data = self.control_socket.recv(BUFFER_SIZE)
            while True:
                try:
                    response = pickle.loads(data)
                    self.proxy_list=response
                except Exception:
                    print("Error")

                data = self.control_socket.recv(BUFFER_SIZE)

        except Exception as e:
            logger.error(f"Control server connection error: {e}")
        finally:
            self.control_socket.close()
            logger.info("Closed control connection.")


    def update_prefer_proxy(self,ip_proxy):
        self.control_socket.sendall("CHOOSE_PROXY".encode() + b"\n" +ip_proxy.encode())
    def connect(self):
        # # TODO Separate the control ans server and let client choose which one he wants to connect to
        #
        # # Generate initial certificates only if needed
        # if not self.check_certificates():
        #     self.create_initial_certificates()
        #     self.get_certificates(name, password, totp)
        # # Now that we have matching cert and key, proceed with the connection
        # threading.Thread(target=self.connect_to_control_server, daemon=True).start()
        self.create_client_socket()
        threading.Thread(target=self.read_loop, daemon=True).start()
        self.enable_proxy('127.0.0.1:9090')
        self.start_local_proxy_server()


if __name__ == "__main__":
    client = Client()
    totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET")
    client.connect("aviv", "12345678", totp.now())
