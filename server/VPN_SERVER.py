import ssl
import socket
import threading
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addreses
import auth_handler
import logging
from log_manager import add_logging
import pickle
import subprocess
from cryptography import x509
import active_users
import users_table
# >>> Import the new file <<<
from control_handler import handle_control_client

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
BUFFER_SIZE=65536
# TODO Add Revocation List
class Server:
    def __init__(self):
        self.socket = None
        self.socket_auth = None
        self.socket_control = None
        self.context = None
        self.cert_context = None
        self.control_context = None
        self.proxy_list = []
        # Optional: If you want to do on-the-fly shutdown
        # self.request_shutdown = False

    def create_ssl_context(self):
        """
        This is the main VPN server context
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=Addreses.SERVER_CERT_PATH,
            keyfile=Addreses.SERVER_KEY_PATH
        )
        context.verify_mode = ssl.CERT_REQUIRED  # optional
        context.check_hostname = False
        context.load_verify_locations("certificates/ca_cert.pem")
        self.context = context
        logging.info("Standard SSL context created.")

    def create_cert_context(self):
        cert_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert_context.load_cert_chain(
            certfile=Addreses.SERVER_CERT_PATH,
            keyfile=Addreses.SERVER_KEY_PATH
        )
        # cert_context.verify_mode = ssl.CERT_REQUIRED  # optional
        cert_context.verify_mod = ssl.CERT_NONE
        # cert_context.verify_mode = ssl.CERT_REQUIRED
        cert_context.check_hostname = False
        cert_context.load_verify_locations("certificates/ca_cert.pem")
        self.cert_context = cert_context
        logging.info("Certificate SSL context created.")

    def create_control_context(self):
        control_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        control_context.load_cert_chain(
            certfile=Addreses.SERVER_CERT_PATH,
            keyfile=Addreses.SERVER_KEY_PATH
        )
        control_context.verify_mode = ssl.CERT_REQUIRED
        control_context.check_hostname = False
        control_context.load_verify_locations("certificates/ca_cert.pem")
        self.control_context = control_context
        logging.info("Control SSL context created.")

    def create_server_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        self.socket = server_socket
        logging.info(f"Standard Server is up on {host}:{port}")

    def create_auth_server_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CERT):
        server_socket_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_auth.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket_auth.bind((host, port))
        self.socket_auth = server_socket_auth
        logging.info(f"Authentication Server is up on {host}:{port}")

    def create_control_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CONTROL):
        server_socket_ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_ctrl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket_ctrl.bind((host, port))
        self.socket_control = server_socket_ctrl
        logging.info(f"Control Server is up on {host}:{port}")

    def receive_clients(self):
        # Main VPN server
        self.socket.listen(100)
        logging.info("Standard Server is listening for connections.")
        while True:
            try:
                connection, client_address = self.socket.accept()
                logging.info(f"Standard Server got a connection from {client_address}")
                # name = active_users.get_name_by_ip(client_address[0])

                # Wrap the connection in TLS using the main VPN context
                secure_socket = self.context.wrap_socket(connection, server_side=True)
                threading.Thread(target=self.tunnel, args=(secure_socket,client_address,), daemon=True).start()

            except Exception as e:
                logging.error(f"Error accepting standard client: {e}")
                # (Optional) break if you want to exit on error
                # break

            # If you have an on-the-fly shutdown flag, you can check it here
            # if self.request_shutdown:
            #    break

    def receive_clients_auth(self):
        # Auth server
        self.socket_auth.listen(100)
        logging.info("Authentication Server is listening for connections.")
        while True:
            try:
                connection, client_address = self.socket_auth.accept()
                logging.info(f"Authentication Server got a connection from {client_address}")

                secure_socket = self.cert_context.wrap_socket(connection, server_side=True)
                threading.Thread(target=auth_handler.transfer_cert, args=(secure_socket,client_address,), daemon=True).start()

                # TODO Make one file no need for auth_handler.py and no need fot thread
            except Exception as e:
                logging.error(f"Error accepting Authentication client: {e}")
                # (Optional) break if you want to exit on error
                # break

    def receive_clients_control(self):
        while True:
            # Control server
            self.socket_control.listen(5)
            logging.info("Control Server is listening for connections.")
            try:
                connection, client_address = self.socket_control.accept()
                logging.info(f"Control Server got a connection from {client_address}")

                # Wrap the socket in TLS using the control context
                secure_socket = self.control_context.wrap_socket(connection, server_side=True)

                cipher = secure_socket.cipher()
                logging.info(f"TLS Cipher Suite Used: {cipher[0]}, Protocol: {cipher[1]}, Key Bits: {cipher[2]}")
                # print(secure_socket.getpeercert())
                cert_der = secure_socket.getpeercert(binary_form=True)
                # Parse the DER-formatted certificate
                cert = x509.load_der_x509_certificate(cert_der)
                # Extract the serial number
                serial_number = cert.serial_number
                username=users_table.get_username(serial_number)
                active_users.add_user(username,client_address[0],str(serial_number))
                # name = active_users.get_name_by_ip(client_address[0])
                add_logging(username, "connected to Control Server")
                threading.Thread(
                    target=handle_control_client,
                    args=(self, secure_socket, client_address,username),
                    daemon=True
                ).start()

            except Exception as e:
                logging.error(f"Error accepting control client: {e}")


    def find_all_proxy(self):
        self.proxy_list = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Timeout for the socket operation

        for ip in Addreses.SERVER_PROXY_IPS:
            if self.check_socket_open(ip,Addreses.SERVER_PROXY_PORT):
                self.proxy_list.append(ip)
        logging.info(f"detected the following proxies: {self.proxy_list}")

    def check_socket_open(self,ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Timeout for the socket operation
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return True
            else:
                return False
        except socket.error as err:
            print(f"Socket error: {err}")
            return False
        finally:
            sock.close()

    def recv_exact(sock, n):
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


    def tunnel(self,client_socket, client_addr):

        proxy_port = Addreses.SERVER_PROXY_PORT
        logging.info("STARTING TUNNEL")
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # try:
        proxy_host = active_users.get_proxy_by_ip(client_addr[0])
        proxy_socket.connect((proxy_host, proxy_port))
        logging.info(f"Connected to proxy server: {proxy_host}:{proxy_port} from {client_addr}")
        local_ip, local_port = proxy_socket.getsockname()

        # active_users.add_port_entry(local_port, local_ip, active_users.get_name_by_ip(client_addr[0]))
        # Start forwarding in both directions using threads
        client_to_proxy = threading.Thread(target=self.forward, args=(client_socket, proxy_socket), daemon=True)
        proxy_to_client = threading.Thread(target=self.forward, args=(proxy_socket, client_socket), daemon=True)
        client_to_proxy.start()
        proxy_to_client.start()

        # Wait for both threads to finish
        client_to_proxy.join()
        proxy_to_client.join()

        # except Exception as e:
        #     logging.error(f"Error establishing tunnel: {e}")
        # finally:
        #     proxy_socket.close()
        #     client_socket.close()
        #     logging.info("Tunnel closed.")

    def forward(self,source, destination):
        try:
            while True:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    sock.close()
                    if channel_id in channel_map:  # Ensure deletion only happens when key exists
                        del channel_map[channel_id]
                    continue
                destination.sendall(data)
        except Exception as e:
            logging.error(f"Error forwarding data: {e}")

if __name__ == "__main__":
    server = Server()

    # 1. Create the necessary SSL contexts
    server.create_ssl_context()       # For main VPN
    server.create_cert_context()      # For auth server
    server.create_control_context()   # For control server
    server.find_all_proxy()
    # 2. Create sockets for each service
    server.create_server_socket()
    server.create_auth_server_socket()
    server.create_control_socket()    # e.g. on Addreses.SERVER_PORT_CONTROL

    # 3. Start each service in its own thread (except the main one if you want it blocking)
    threading.Thread(target=server.receive_clients_auth, daemon=True).start()
    threading.Thread(target=server.receive_clients_control, daemon=True).start()

    # 4. Finally, run the main server on the main thread
    server.receive_clients()
