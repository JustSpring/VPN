import os
import sys
import ssl
import socket
import threading
import pickle
import select
import logging
import time
import datetime
import ctypes
import winreg
import pyotp

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto

# allow imports from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addresses

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# size of each chunk when we send/receive data
BUFFER_SIZE = 65_536


class Client:
    def __init__(self):
        self.client_socket = None
        self.control_socket = None
        self.proxy_list = []
        self.data_sent = 0
        self.current_index = 0
        # stats to help calculate transfer speed
        self.stats = {
            "window_size": 5,
            "total_bytes": 0,
            "current_index": 0,
            "arr": [0] * 5,
            "last_time": int(time.time()),
            "active_seconds": 0
        }
        # load the CA certificate
        with open("certificates/ca_cert.pem", "r") as f:
            self.SERVER_CA_CERT = f.read()
        self.next_channel_id = 0
        self.local_channel_map = {}
        # locks to avoid race conditions when sending or modifying channels
        self.send_lock = threading.Lock()
        self.local_channel_lock = threading.Lock()

        self.serial = None
        self.kill = False
        self.kill_reason = ""


    def create_initial_certificates(self):
        """Generate client key and self signed cert if we don't have them yet."""

        # ignore if they already exist
        if not os.path.exists(Addresses.CLIENT_INITIAL_KEY_PATH) or not os.path.exists(Addresses.CLIENT_INITIAL_CERT_PATH):
            logger.info("Generating initial client certificates.")
            # make a new RSA key
            client_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            # put the private key in PEM format without encryption
            pem = client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(Addresses.CLIENT_INITIAL_KEY_PATH, "wb") as f:
                f.write(pem)

            # build a CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")
                ])
            ).sign(client_key, hashes.SHA256(), default_backend())
            # self sign the CSR to create a temp cert
            cert = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(csr.subject)
                .serial_number(x509.random_serial_number())
                .public_key(csr.public_key())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .sign(client_key, hashes.SHA256(), default_backend())
            )
            with open(Addresses.CLIENT_INITIAL_CERT_PATH, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_certificates(self, username, password, totp, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT_CERT):
        """get signed client cert/key from the auth server"""

        logger.info("Retrieving certificates from the authentication server.")
        try:
            sock = socket.create_connection((host, port))
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.load_cert_chain(
                certfile=Addresses.CLIENT_INITIAL_CERT_PATH,
                keyfile=Addresses.CLIENT_INITIAL_KEY_PATH,
            )
            ctx.load_verify_locations(cadata=self.SERVER_CA_CERT)
            ctx.check_hostname = False

            ssock = ctx.wrap_socket(sock, server_side=False)
            # send credentials and current TOTP code
            ssock.send(pickle.dumps({
                "username": username,
                "password": password,
                "totp": totp
            }))
            resp = ssock.recv(BUFFER_SIZE)
            if pickle.loads(resp) == -1:
                logger.warning("Authentication failed!")
                return -1
            # unpack the cert, key, and serial
            cert_bytes, key_bytes, serial = pickle.loads(resp)
            self.serial = serial
            with open(Addresses.CLIENT_CERT_PATH, "wb") as f:
                f.write(cert_bytes)
            with open(Addresses.CLIENT_KEY_PATH, "wb") as f:
                f.write(key_bytes)
        except Exception as e:
            logger.error(f"Error retrieving certificates: {e}")
            raise

    def create_ssl_context(self):
        """Prepare the SSL context for VPN data connection."""

        logger.info("Creating SSL context.")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_verify_locations(cadata=self.SERVER_CA_CERT)
        ctx.load_cert_chain(
            certfile=Addresses.CLIENT_CERT_PATH,
            keyfile=Addresses.CLIENT_KEY_PATH
        )
        ctx.check_hostname = False
        return ctx

    def create_client_socket(self, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT):
        """Create a secure connection to the main VPN server"""

        logger.info(f"Connecting to VPN server at {host}:{port}")
        ctx = self.create_ssl_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.connect((host, port))
        # wrap our socket in SSL
        self.client_socket = ctx.wrap_socket(
            raw, server_side=False,
            server_hostname="clientVPN.example.com"
        )
        logger.info("Secure connection established.")
        # TODO stop running if not server
        try:
            server_cert_bin = self.client_socket.getpeercert(binary_form=True)
            if server_cert_bin:
                serv_cert = x509.load_der_x509_certificate(
                    server_cert_bin, default_backend()
                )
                with open("certificates/server_cert.pem", "rb") as f:
                    known = x509.load_pem_x509_certificate(f.read(), default_backend())
                if serv_cert.fingerprint(hashes.SHA256()) == known.fingerprint(hashes.SHA256()):
                    logger.info("Server certificate matches known certificate.")
                else:
                    logger.error("Server certificate mismatch!")
            else:
                logger.warning("No server certificate received.")
        except Exception as e:
            logger.error(f"Certificate check failed: {e}")

    def start_local_proxy_server(self,host=Addresses.LOCAL_PROXY_IP,port=Addresses.LOCAL_PROXY_PORT):
        """Listen locally and tunnel data over the VPN."""

        logger.info(f"Starting local proxy server on {host}:{port}")
        local_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            local_srv.bind((host, port))
            local_srv.listen(5)
            logger.info(f"Local proxy listening on {host}:{port}")
            # let the server know our cert serial
            self.send_frame({"type": "CHANGE_NAME", "channel_id": 0},
                            str(self.serial).encode())

            while True:
                conn, _ = local_srv.accept()
                # handle each incoming local client in its own thread
                threading.Thread(
                    target=self.handle_local_clients,
                    args=(conn,),
                    daemon=True
                ).start()
        except Exception as e:
            logger.error(f"Proxy server error: {e}")
        finally:
            local_srv.close()

    def handle_local_clients(self, local_sock):
        """Assign a channel ID and start forwarding for a new local client."""

        cid = self.next_channel_id
        self.next_channel_id += 1
        with self.local_channel_lock:
            self.local_channel_map[cid] = local_sock

        # inform server to open a new channel
        self.send_frame({"type": "OPEN_CHANNEL", "channel_id": cid}, b"")
        threading.Thread(
            target=self.forward_local_to_server,
            args=(cid, local_sock),
            daemon=True
        ).start()

    def forward_local_to_server(self, channel_id, local_sock):
        """Read from local socket and send data across VPN to server."""
        try:
            while True:
                data = local_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                self.send_frame({"type": "DATA", "channel_id": channel_id}, data)
        except Exception as e:
            logger.error(f"Error in forward_local_to_server: {e}")
        finally:
            self.send_frame({"type": "CLOSE_CHANNEL", "channel_id": channel_id}, b"")

    def send_frame(self, header, payload):
        """Package a length + header + payload and send it over the VPN socket."""

        frame = pickle.dumps((header, payload))
        length = len(frame).to_bytes(4, "big")
        if not self.client_socket:
            logger.error("No client socket to send frame")
            return
        with self.send_lock:
            try:
                self.client_socket.sendall(length + frame)
            except (ssl.SSLError, OSError) as e:
                logger.error(f"Socket send error: {e}")
                self.client_socket.close()

    def read_loop(self):
        """Continuously read incoming frames from server and locally."""

        self.client_socket.settimeout(0.5)
        while True:
            with self.local_channel_lock:
                localsocks = list(self.local_channel_map.values())
            # watch both server socket and all local channels
            to_monitor = [self.client_socket] + [s for s in localsocks if s]
            readable, _, _ = select.select(to_monitor, [], [], 0.5)

            for sock in readable:
                if sock is self.client_socket:
                    # data from server (to local)
                    try:
                        length_bytes = sock.recv(4)
                    except ConnectionResetError:
                        logger.warning("Proxy disconnected")
                        self.kill=True
                        self.kill_reason = "Proxy disconnected"
                    except (ssl.SSLWantReadError, socket.timeout, BlockingIOError):
                        continue
                    if not length_bytes:
                        logger.info("Server disconnected")
                        return
                    frame_len = int.from_bytes(length_bytes, "big")
                    data = b""
                    while len(data) < frame_len:
                        try:
                            chunk = sock.recv(frame_len - len(data))
                            if not chunk:
                                break
                            data += chunk
                        except (ssl.SSLWantReadError, socket.timeout,
                                BlockingIOError, ConnectionResetError):
                            continue
                    if data:
                        hdr, payload = pickle.loads(data)
                        cid = hdr["channel_id"]
                        if hdr["type"] == "CLOSE_CHANNEL":
                            with self.local_channel_lock:
                                s = self.local_channel_map.pop(cid, None)
                            if s:
                                s.close()
                        elif hdr["type"] == "DATA":
                            s = self.local_channel_map.get(cid)
                            if s:
                                try:
                                    s.sendall(payload)
                                except Exception as e:
                                    logger.error(f"Forward error: {e}")
                else:
                    # data from a local client (to server)
                    try:
                        data = sock.recv(BUFFER_SIZE)
                    except (ssl.SSLWantReadError, socket.timeout,
                            BlockingIOError, ConnectionAbortedError):
                        continue
                    if data:
                        cid = next((k for k,v in self.local_channel_map.items() if v==sock), None)
                        if cid is not None:
                            self.send_frame({"type": "DATA","channel_id":cid}, data)
                            self.update(len(data))

    def update(self, l):
        """Keep a rolling window to calc transfer speed."""

        now = int(time.time())
        idx = self.stats["current_index"]
        # How many full seconds have gone since last updated
        delta = now - self.stats["last_time"]
        if delta > 0:
            # For each second that has passed (up to window_size) slide the window forward
            for _ in range(min(self.stats["window_size"], delta)):
                idx = (idx + 1) % self.stats["window_size"]
                # Subtract the bytes that were in this slot from the total
                self.stats["total_bytes"] -= self.stats["arr"][idx]
                # If that slot had activity remove from active_seconds
                if self.stats["arr"][idx] > 0:
                    self.stats["active_seconds"] -= 1
                    self.stats["arr"][idx] = 0
            self.stats["current_index"] = idx

        # If this is the first byte in the current second slot count another active second
        if self.stats["arr"][idx] == 0:
            self.stats["active_seconds"] += 1
        # Add the new byte count to this slot
        self.stats["arr"][idx] += l
        self.stats["total_bytes"] += l
        self.stats["last_time"] = now

    def calculate_speed(self):
        """Convert rolling byte count into readable speed."""

        speed = self.stats["total_bytes"] / self.stats["window_size"]
        if speed <= 1024:
            return f"{speed:.0f} Bytes"
        if speed <= 1_048_576:
            return f"{speed/1024:.2f} KB"
        return f"{speed/1_048_576:.2f} MB"

    def set_registry_value(self, name, value):
        """Helper to write to Windows Internet Settings registry."""

        REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        reg_type = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, name, 0, reg_type, value)
        except Exception as e:
            logger.error(f"Failed to set registry {name}: {e}")

    def get_registry_value(self, name):
        """Get a value from the Windows Internet Settings registry."""
        REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except FileNotFoundError:
            return None

    def enable_proxy(self, addr):
        """Enable Windows proxy with admin rights."""
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            logger.error("Admin required for proxy")
            return False

        def elevate():
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv),
                None, 1
            )
            # sys.exit()
        elevate()


        if self.get_registry_value("ProxyEnable") != 1:
            self.set_registry_value("ProxyEnable", 1)
        if self.get_registry_value("ProxyServer") != addr:
            self.set_registry_value("ProxyServer", addr)
        return True

    def remove_proxy(self):
        """Turn off Windows proxy settings."""

        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            logger.error("Admin required to remove proxy")
            return
        if self.get_registry_value("ProxyEnable") != 0:
            self.set_registry_value("ProxyEnable", 0)

    # def check_certificates(self):
    #     """Verify client cert is still valid (not expired)."""
    #     if os.path.isfile(Addresses.CLIENT_CERT_PATH) and os.path.isfile(Addresses.CLIENT_KEY_PATH):
    #         with open(Addresses.CLIENT_CERT_PATH, 'rb') as f:
    #             data = f.read()
    #         cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
    #         exp = cert.get_notAfter().decode('utf-8').rstrip('Z')
    #         exp_dt = datetime.datetime.strptime(exp, '%Y%m%d%H%M%S')
    #         if datetime.datetime.utcnow() > exp_dt:
    #             return False
    #         return True
    #     return False

    def connect_to_control_server(self, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT_CONTROL):
        """Connect to control server."""

        logger.info(f"Connecting to control server {host}:{port}")
        ctx = self.create_ssl_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        ss = ctx.wrap_socket(sock, server_side=False,
                             server_hostname="clientVPN.example.com")
        self.control_socket = ss
        try:
            ss.sendall(b"LIST_PROXIES\n")
            data = ss.recv(BUFFER_SIZE)
            while data:
                try:
                    self.proxy_list = pickle.loads(data)
                except Exception as e:
                    logger.error(f"Control parse error: {e}")
                    self.kill_reason = "Control server error"
                    self.kill = True
                data = ss.recv(BUFFER_SIZE)
        except Exception as e:
            logger.error(f"Control connection error: {e}")
        finally:
            ss.close()
            self.kill_reason = "Control server error2"
            self.kill=True
            logger.info("Control connection closed")

    def update_prefer_proxy(self, ip_proxy):
        """Tell the control server to switch to a specific proxy."""
        if self.control_socket:
            self.control_socket.sendall(b"CHOOSE_PROXY\n" + ip_proxy.encode())
        logging.info(f"Send preferred proxy to server: {ip_proxy}")

    def connect(self):
        """set up SSL, start data threads, and enable proxy."""
        self.create_client_socket()
        threading.Thread(target=self.read_loop, daemon=True).start()
        # self.enable_proxy('127.0.0.1:9090')
        self.start_local_proxy_server()


if __name__ == "__main__":
    client = Client()
    totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET").now()
    client.get_certificates("aviv", "12345678", totp)
    client.connect()