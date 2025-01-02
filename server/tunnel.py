# tunnel.py
import socket
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addreses
import logging
import threading
import users_table
import active_users
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def tunnel(client_socket,client_ip):
    # proxy_host = Addreses.SERVER_PROXY_IP
    proxy_port = Addreses.SERVER_PROXY_PORT
    logging.info("STARTING TUNNEL")
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        proxy_host = active_users.get_proxy_by_ip(client_ip)
        # Connect to the proxy server

        proxy_socket.connect((proxy_host, proxy_port))
        logging.info(f"Connected to proxy server: {proxy_host}:{proxy_port}")

        # Start forwarding in both directions using threads
        client_to_proxy = threading.Thread(target=forward, args=(client_socket, proxy_socket), daemon=True)
        proxy_to_client = threading.Thread(target=forward, args=(proxy_socket, client_socket), daemon=True)
        client_to_proxy.start()
        proxy_to_client.start()

        # Wait for both threads to finish
        client_to_proxy.join()
        proxy_to_client.join()

    except Exception as e:
        logging.error(f"Error establishing tunnel: {e}")
    finally:
        proxy_socket.close()
        client_socket.close()
        logging.info("Tunnel closed.")


def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                logging.info(f"No more data from {source.getpeername()}, closing connection.")
                break
            destination.sendall(data)
            logging.info(f"Forwarded {len(data)} bytes from {source.getpeername()} to {destination.getpeername()}")
    except Exception as e:
        logging.error(f"Error forwarding data: {e}")


if __name__ == "__main__":
    pass
