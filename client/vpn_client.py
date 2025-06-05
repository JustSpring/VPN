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
import errno

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
BUFFER_SIZE = 16_384


class Client:
    def __init__(self):
        self.client_socket = None
        self.control_socket = None
        self.local_proxy_srv = None
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
        return 0

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
                    return False
            else:
                logger.warning("No server certificate received.")
        except Exception as e:
            logger.error(f"Certificate check failed: {e}")

    def start_local_proxy_server(self,host=Addresses.LOCAL_PROXY_IP,port=Addresses.LOCAL_PROXY_PORT):
        """Listen locally and tunnel data over the VPN."""

        logger.info(f"Starting local proxy server on {host}:{port}")

        local_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_srv.bind((host, port))
        local_srv.listen(100)

        # store a handle so we can close it from another thread when kill is raised
        self.local_proxy_srv = local_srv
        logger.info(f"Local proxy listening on {host}:{port}")
        self.send_frame({"type": "CHANGE_NAME", "channel_id": 0},
                        str(self.serial).encode())
        try:
            while not self.kill:
                try:
                    conn, _ = local_srv.accept()
                except OSError:
                    # listening socket was closed elsewhere
                    break

                # double-check in case kill went up while we were in accept()
                if self.kill:
                    conn.close()
                    break

                threading.Thread(
                    target=self.handle_local_clients,
                    args=(conn,),
                    daemon=True
                ).start()
        finally:
            try:
                local_srv.close()
            except Exception:
                pass
            logger.info("Local proxy server stopped")

    def handle_local_clients(self, local_sock):
        """Assign a channel ID and start forwarding for a new local client."""
        if self.kill:
            try:
                local_sock.close()
            finally:
                return
        cid = self.next_channel_id
        self.next_channel_id += 1
        with self.local_channel_lock:
            self.local_channel_map[cid] = local_sock

        # inform server to open a new channel
        try:
            self.send_frame({"type": "OPEN_CHANNEL", "channel_id": cid}, b"")
        except Exception as e:
            logger.error(f"Couldn't OPEN_CHANNEL for {cid}: {e}")
            # cleanup and just exit this handler
            try:
                local_sock.close()
            except:
                pass
            with self.local_channel_lock:
                self.local_channel_map.pop(cid, None)
            return

        # only start forwarding if OPEN_CHANNEL succeeded
        threading.Thread(
            target=self.forward_local_to_server,
            args=(cid, local_sock),
            daemon=True
        ).start()

    def forward_local_to_server(self, channel_id, local_sock):
        """
        Transfer bytes from the local TCP client into the VPN tunnel.
        """
        local_sock.setblocking(False)
        half_closed = False  # True after FIN from browser

        try:
            while True:
                if not half_closed:
                    try:
                        data = local_sock.recv(BUFFER_SIZE)
                    except (BlockingIOError, ConnectionResetError):
                        data = None  # no new data right now
                    except OSError:
                        data = None
                        half_closed = True

                    if data is None:
                        pass  # nothing to send this iteration

                    elif data == b"":  # FIN from browser (write side closed)
                        half_closed = True

                    else:
                        # normal upstream data
                        self.send_frame({"type": "DATA",
                                         "channel_id": channel_id}, data)
                        self.update(len(data))

                if self.kill or channel_id not in self.local_channel_map:
                    break
                time.sleep(0.01)

        finally:
            # Actual teardown happens when read_loop processes CLOSE_CHANNEL
            try:
                local_sock.close()
            except OSError:
                pass

    def send_frame(self, header, payload):
        """Package a length + header + payload and send it over the VPN socket."""

        if not self.client_socket or self.client_socket.fileno() < 0:
            raise OSError("No live VPN socket for send_frame")

        frame = pickle.dumps((header, payload))
        packet = len(frame).to_bytes(4, "big") + frame
        view = memoryview(packet)

        with self.send_lock:
            while view:
                try:
                    sent = self.client_socket.send(view)
                    view = view[sent:]

                except ssl.SSLWantWriteError:
                    time.sleep(0.005)
                    continue

                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, 10035):
                        time.sleep(0.005)
                        continue
                    logger.error(f"Socket send fatal: {e}")
                    raise

    # def _recv_all(self, n):
    #     """
    #     Read exactly n bytes from self.client_socket.
    #     """
    #     buf = b""
    #     while len(buf) < n:
    #         try:
    #             chunk = self.client_socket.recv(n - len(buf))
    #             if not chunk:  # EOF  connection closed gracefully
    #                 return None
    #             buf += chunk
    #         except (ssl.SSLWantReadError, socket.timeout, BlockingIOError):
    #             # non-fatal – just try again until timeout in select()
    #             continue
    #     return buf

    def read_loop(self):
        """Continuously read incoming frames from server and locally."""

        self.client_socket.setblocking(False)
        rx_buf = bytearray()  # holds incoming data
        expected_len = None   # how long the next full frame is supposed to be

        def process_frame(hdr, payload):
            cid = hdr["channel_id"] # cid= channel ID

            if hdr["type"] == "CLOSE_CHANNEL": # hdr= header
                # close local socket when the server says it's done
                with self.local_channel_lock:
                    s = self.local_channel_map.pop(cid, None)
                if s:
                    try:
                        s.shutdown(socket.SHUT_WR)   # tell browser we're done writing
                    except OSError:
                        pass
                    s.close()

            elif hdr["type"] == "DATA":
                # server sent some data we need to forward to the local browser
                with self.local_channel_lock:
                    s = self.local_channel_map.get(cid)
                if s:
                    try:
                        logger.info(f"[←] ch{cid} {len(payload)} bytes server→local")
                        s.sendall(payload)
                        self.update(len(payload))
                    except Exception as e:
                        logger.error(f"local send on ch{cid}: {e}")
                        s.close()
                        with self.local_channel_lock:
                            self.local_channel_map.pop(cid, None)
                        try:
                            self.send_frame({"type": "CLOSE_CHANNEL", "channel_id": cid}, b"")
                        except Exception:
                            pass
                else:
                    # local socket is already gone so notify server to close too
                    try:
                        self.send_frame({"type": "CLOSE_CHANNEL", "channel_id": cid}, b"")
                    except Exception:
                        pass

        while True:

            # build the list of sockets to monitor (VPN socket + all browser sockets)
            with self.local_channel_lock:
                local_socks = [s for s in self.local_channel_map.values()
                               if s and s.fileno() >= 0]
            if self.client_socket.fileno() < 0:
                logger.warning("TLS socket closed – leaving read_loop")
                return
            sockets_to_monitor = [self.client_socket] + local_socks

            try:
                readable, _, _ = select.select(sockets_to_monitor, [], [], 0.5)
            except ValueError:
                # One of the sockets probably got closed right after we checked it
                continue

            # Incoming data
            if self.client_socket in readable:
                try:
                    chunk = self.client_socket.recv(BUFFER_SIZE)
                except ssl.SSLWantReadError:
                    chunk = b""
                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, 10035):
                        chunk = b""
                    else:
                        logger.warning(f"TLS recv fatal: {e}")
                        return

                except ssl.SSLZeroReturnError:
                    logger.info("Server closed TLS connection")
                    return

                if chunk:
                    rx_buf += chunk

                # Try to unpack as many full frames as we've got
                while True:
                    if expected_len is None:
                        if len(rx_buf) < 4:
                            break
                        expected_len = int.from_bytes(rx_buf[:4], "big")
                        del rx_buf[:4]

                    if len(rx_buf) < expected_len:
                        break

                    frame = bytes(rx_buf[:expected_len])
                    del rx_buf[:expected_len]
                    expected_len = None

                    try:
                        hdr, payload = pickle.loads(frame)
                    except Exception as e:
                        logger.error(f"frame decode error: {e}")
                        continue

                    process_frame(hdr, payload)

            for sock in (s for s in readable if s is not self.client_socket):
                # local to server
                if sock.fileno() < 0:  # ignore dead sockets
                    continue

                try:
                    data = sock.recv(BUFFER_SIZE)
                except (BlockingIOError, ssl.SSLWantReadError,
                        ssl.SSLZeroReturnError, ConnectionResetError,
                        ConnectionAbortedError):
                    continue
                except OSError as e:
                    logger.warning(f"dead local socket: {e}")
                    data = b""

                if not data:
                    # browser closed the connection so clean it up
                    with self.local_channel_lock:
                        cid = next((k for k, v in self.local_channel_map.items()
                                    if v == sock), None)
                        if cid is not None:
                            try:
                                self.send_frame({"type": "CLOSE_CHANNEL",
                                                 "channel_id": cid}, b"")
                            except Exception:
                                pass
                            self.local_channel_map.pop(cid, None)
                    sock.close()
                    continue
                    
                # normal data upload from browser to server
                with self.local_channel_lock:
                    cid = next((k for k, v in self.local_channel_map.items()
                                if v == sock), None)
                if cid is not None:
                    try:
                        self.send_frame({"type": "DATA", "channel_id": cid}, data)
                        self.update(len(data))
                    except Exception as e:
                        logger.error(f"send DATA on ch{cid}: {e}")

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
                # If that slot had activity remove it
                self.stats["arr"][idx] = 0
            self.stats["current_index"] = idx


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
            self.kill_reason = "Server disconnected"
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
        self.start_local_proxy_server()


if __name__ == "__main__":
    client = Client()
    totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET").now()
    client.get_certificates("aviv", "12345678", totp)
    client.connect()
