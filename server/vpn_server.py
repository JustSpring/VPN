import ssl
import socket
import threading
import sys
import os
from math import trunc
from create_keys import create_all_keys
# Ensure shared config path is added for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addresses
import logging
import pickle
import subprocess
from cryptography import x509
import manage_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Maximum number of bytes to read at once
BUFFER_SIZE=65536
class Server:
    """
        Main VPN server class.
        Manages SSL contexts, sockets, client handling, and tunneling.
        """
    def __init__(self):
        self.socket = None
        self.socket_auth = None
        self.socket_control = None
        self.context = None
        self.cert_context = None
        self.control_context = None
        self.proxy_list = []
        # Active client connections. keyed by IP.
        self.clients_socket={}
        # Reset the active users table each time the server starts
        manage_db.recreate_active_table()

    def create_ssl_context(self):
        """Set up the SSL context for the main VPN tunnel."""

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=Addresses.SERVER_CERT_PATH,
            keyfile=Addresses.SERVER_KEY_PATH
        )
        context.verify_mode = ssl.CERT_REQUIRED  # demand client certs
        # context.check_hostname = False
        context.load_verify_locations("certificates/ca_cert.pem")
        self.context = context
        logging.info("Standard SSL context created.")

    def create_auth_context(self):
        """
        SSL context for the  auth server.
        """
        cert_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert_context.load_cert_chain(
            certfile=Addresses.SERVER_CERT_PATH,
            keyfile=Addresses.SERVER_KEY_PATH
        )
        # skip client cert verification for auth service (they still didn't get it)
        cert_context.verify_mod = ssl.CERT_NONE
        # cert_context.check_hostname = False
        cert_context.load_verify_locations("certificates/ca_cert.pem")
        self.cert_context = cert_context
        logging.info("Certificate SSL context created.")

    def create_control_context(self):
        """SSL context for the control server channel."""

        control_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        control_context.load_cert_chain(
            certfile=Addresses.SERVER_CERT_PATH,
            keyfile=Addresses.SERVER_KEY_PATH
        )
        control_context.verify_mode = ssl.CERT_REQUIRED
        control_context.check_hostname = False
        control_context.load_verify_locations("certificates/ca_cert.pem")
        self.control_context = control_context
        logging.info("Control SSL context created.")

    def create_server_socket(self, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT):
        """Create and bind the main VPN socket."""

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        self.socket = server_socket
        logging.info(f"Standard Server is up on {host}:{port}")

    def create_auth_server_socket(self, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT_CERT):
        """Create and bind the authentication socket."""

        server_socket_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_auth.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket_auth.bind((host, port))
        self.socket_auth = server_socket_auth
        logging.info(f"Authentication Server is up on {host}:{port}")

    def create_control_socket(self, host=Addresses.SERVER_IP, port=Addresses.SERVER_PORT_CONTROL):
        """Create and bind the control socket."""

        server_socket_ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_ctrl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket_ctrl.bind((host, port))
        self.socket_control = server_socket_ctrl
        logging.info(f"Control Server is up on {host}:{port}")

    def receive_clients(self):
        """Accept incoming client connections and generate tunnel threads."""

        self.socket.listen(100)
        logging.info("Standard Server is listening for connections.")
        while True:
            try:
                connection, client_address = self.socket.accept()
                logging.info(f"Standard Server got a connection from {client_address}")

                # Wrap in SSL and hand off to tunnel handler
                secure_socket = self.context.wrap_socket(connection, server_side=True)
                threading.Thread(target=self.tunnel, args=(secure_socket,client_address,), daemon=True).start()

            except Exception as e:
                logging.error(f"Error accepting standard client: {e}")


    def receive_clients_auth(self):
        """Accept incoming connections on the auth server to give certificate."""

        self.socket_auth.listen(100)
        logging.info("Authentication Server is listening for connections.")
        while True:
            try:
                connection, client_address = self.socket_auth.accept()
                logging.info(f"Authentication Server got a connection from {client_address}")

                secure_socket = self.cert_context.wrap_socket(connection, server_side=True)
                threading.Thread(target=self.check_user_transfer_cert, args=(secure_socket,client_address,), daemon=True).start()
            except Exception as e:
                logging.error(f"Error accepting Authentication client: {e}")


    def receive_clients_control(self):
        """Listen for control connections"""
        while True:
            self.socket_control.listen(5)
            logging.info("Control Server is listening for connections.")
            try:
                connection, client_address = self.socket_control.accept()
                logging.info(f"Control Server got a connection from {client_address}")

                secure_socket = self.control_context.wrap_socket(connection, server_side=True)
                # Store by client IP for kicking.
                self.clients_socket[client_address[0]]=secure_socket
                cipher = secure_socket.cipher()
                logging.info(f"TLS Cipher Suite Used: {cipher[0]}, Protocol: {cipher[1]}, Key Bits: {cipher[2]}")

                # Retrieve client cert and add them to databases
                cert_der = secure_socket.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der)
                serial_number = cert.serial_number
                username=manage_db.get_user_username(serial_number)
                manage_db.add_active_user(username,client_address[0],str(serial_number))
                manage_db.add_logging(username, "connected to Control Server")

                threading.Thread(
                    target=self.handle_control_client,
                    args=(self,secure_socket, client_address,username),
                    daemon=True
                ).start()

            except Exception as e:
                logging.error(f"Error accepting control client: {e}")

    def handle_control_client(self, server, secure_socket, client_address,username):
        """
        Process commands from an authenticated control client.
        Supported commands: LIST_PROXIES, CHOOSE_PROXY <ip>
        """
        logging.info(f"[CONTROL] Started control thread for {client_address}")

        try:
            while True:
                data = secure_socket.recv(4096)
                if not data:
                    break # client disconnected

                command = data.decode('utf-8', errors='ignore').strip()
                logging.info(f"[CONTROL] Received command from {client_address}: {command}")

                if command.upper() == "LIST_PROXIES":
                    secure_socket.sendall(pickle.dumps(server.proxy_list))
                elif command.startswith("CHOOSE_PROXY"):
                    # Change the active proxy for this user
                    manage_db.update_active_proxy(username, command.split()[1])
                    logging.info(f"Updated Proxy {command.split()[1]} for {username}")
                else:
                    response = f"Unknown command: {command}\n"
                    secure_socket.sendall(response.encode())

        except Exception as e:
            logging.error(f"[CONTROL] Error in control client thread: {e}")
        finally:
            secure_socket.close()
            logging.info(f"[CONTROL] Control client {client_address} disconnected.")
            manage_db.delete_active_user_by_ip(client_address[0])

    def find_all_proxy(self):
        """Scan configured proxy IPs and return those accepting connections."""

        self.proxy_list = []
        for ip in Addresses.SERVER_PROXY_IPS:
            if self.check_socket_open(ip,Addresses.SERVER_PROXY_PORT):
                self.proxy_list.append(ip)
        logging.info(f"detected the following proxies: {self.proxy_list}")
        return self.proxy_list

    def check_socket_open(self,ip, port):
        """Test TCP connection to given ip:port. Returns True if open."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Timeout for the socket operation
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return True
            else:
                return False
        except socket.error as E:
            logging.error(f"Socket error: {E}")
            return False
        finally:
            sock.close()

    def check_user_transfer_cert(self,socket, client_address):
        """Handle authentication requests and issue certificates."""

        try:
            res = socket.recv(4096)
            user_dict = pickle.loads(res)
            username = user_dict.get("username")
            password = user_dict.get("password")
            totp = user_dict.get("totp")

            if not username or not password or not totp:
                raise ValueError("Missing required fields in user dictionary")

            ans = manage_db.check_user(username, password, totp)
            if ans != 0:
                manage_db.add_logging(client_address[0],
                            "Failed attempt signing in as " + username + " - " + password + " - " + totp)
                socket.send(pickle.dumps(-1))  # failure

            else:
                manage_db.add_logging(client_address[0], "successfully signed in as " + username)
                cert_data = create_all_keys()
                manage_db.update_user_cert_serial(username, cert_data[2])
                socket.send(pickle.dumps(cert_data))
        except Exception as e:
            logging.error(f"Error in check user & transfer_cert: {e}")
            socket.close()

    def tunnel(self, client_socket, client_addr):
        """Forward traffic between the client and a chosen proxy."""
        logging.info(f"[TUNNEL] STARTING tunnel for {client_addr}")

        proxy_port = Addresses.SERVER_PROXY_PORT
        proxy_host = manage_db.get_active_proxy(ip=client_addr[0])

        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect((proxy_host, proxy_port))
        logging.info(f"[TUNNEL] Connected to proxy {proxy_host}:{proxy_port} for {client_addr}")

        # spawn bi-directional forwards
        t1 = threading.Thread(
            target=self.forward,
            args=(client_socket, proxy_socket, f"{client_addr} → {proxy_host}:{proxy_port}"),
            daemon=True
        )
        t2 = threading.Thread(
            target=self.forward,
            args=(proxy_socket, client_socket, f"{proxy_host}:{proxy_port} → {client_addr}"),
            daemon=True
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        logging.info(f"[TUNNEL] CLOSED tunnel for {client_addr}")

    def forward(self, source, destination, tag):
        """Read from source and write to destination until closed, logging each chunk."""
        try:
            while True:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    logging.info(f"[FORWARD {tag}] EOF reached, shutting down.")
                    try:
                        source.shutdown(socket.SHUT_RD)
                    except:
                        pass
                    break

                logging.info(f"[FORWARD {tag}] {len(data)} bytes")
                destination.sendall(data)

        except Exception as e:
            logging.error(f"[FORWARD {tag}] Error: {e}")

        finally:
            for s in (source, destination):
                try:
                    s.close()
                except:
                    pass


    def kick(self,ip):
        """Forcefully disconnect a control client by IP."""

        sock=self.clients_socket.pop(ip)
        if not sock:
            return False
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            logging.info(f"Kicked user with ip:{ip}")
            manage_db.delete_active_user_by_ip(ip)
            return True
        except Exception as E:
            logging.error(f"Error kicking {ip} from VPN_SERVER.py: {E}")
            return False
