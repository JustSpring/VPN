import ssl
import socket
import threading
import tunnel
from shared.config import Addreses
import auth_handler
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#TODO Add Revocation List
class Server:
    def __init__(self):
        self.socket = None
        self.socket_auth = None
        self.context = None
        self.cert_context = None

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=Addreses.SERVER_CERT_PATH, keyfile=Addreses.SERVER_KEY_PATH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("certificates/ca_cert.pem")
        self.context = context
        logging.info("Standard SSL context created.")

    def create_cert_context(self):
        cert_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert_context.load_cert_chain(certfile=Addreses.SERVER_CERT_PATH, keyfile=Addreses.SERVER_KEY_PATH)
        self.cert_context = cert_context
        logging.info("Certificate SSL context created.")

    def create_server_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        self.socket = server_socket
        logging.info(f"Standard Server is up on {host}:{port}")

    def create_auth_server_socket(self, host=Addreses.SERVER_IP, port=Addreses.SERVER_PORT_CERT):
        server_socket_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket_auth.bind((host, port))
        self.socket_auth = server_socket_auth
        logging.info(f"Authentication  Server is up on {host}:{port}")

    def receive_clients(self):
        server_socket = self.socket
        server_socket.listen(100)
        logging.info("Standard Server is listening for connections.")
        while True:
            try:
                connection, client_address = server_socket.accept()
                logging.info(f"Standard Server got a connection from {client_address}")
                secure_socket = self.context.wrap_socket(connection, server_side=True)
                threading.Thread(target=tunnel.tunnel, args=(secure_socket,), daemon=True).start()
            except Exception as e:
                logging.error(f"Error accepting standard client: {e}")

    def receive_clients_auth(self):
        server_socket_cert = self.socket_auth
        server_socket_cert.listen(100)
        logging.info("Authentication Server is listening for connections.")
        while True:
            try:
                connection, client_address = server_socket_cert.accept()
                logging.info(f"Authentication Server got a connection from {client_address}")
                secure_socket = self.cert_context.wrap_socket(connection, server_side=True)
                threading.Thread(target=auth_handler.transfer_cert, args=(secure_socket,), daemon=True).start()
            except Exception as e:
                logging.error(f"Error accepting Authentication client: {e}")

if __name__ == "__main__":
    server = Server()
    server.create_ssl_context()
    server.create_cert_context()
    server.create_server_socket()
    server.create_auth_server_socket()
    threading.Thread(target=server.receive_clients_auth, daemon=True).start()
    server.receive_clients()