import socket
import threading
import logging
from urllib.parse import urlparse
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addreses

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Proxy:
    def __init__(self, host="192.168.68.135", port=Addreses.SERVER_PROXY_PORT):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        logging.info(f"Proxy server listening on {self.host}:{self.port}")

    def start(self):
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Accepted connection from {addr}")
                threading.Thread(target=self.handle_client_request, args=(client_socket,), daemon=True).start()
            except Exception as e:
                logging.error(f"Error accepting client connection: {e}")

    def handle_client_request(self, client_socket):
        try:
            request = self.recv_all(client_socket)
            if not request:
                client_socket.close()
                return
            if isinstance(request, bytes):
                request = request.decode('utf-8', errors='ignore')

            if request.startswith("CONNECT"):
                self.handle_https(request, client_socket)
                return
            elif "HTTP" in request:
                self.handle_http(request, client_socket)
                return
            elif self.is_ftp_request(request):
                self.handle_ftp(client_socket, request)
                return

            logging.warning("Unsupported protocol or malformed request.")
            client_socket.close()

        except Exception as e:
            logging.error(f"Error handling client request: {e}")
            client_socket.close()

    def forward_data(self, src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception as e:
            logging.error(f"Error forwarding data: {e}")

    def handle_http(self, request, client_socket):
        try:
            lines = request.split('\r\n')
            if not lines:
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 3:
                return

            method, url, protocol = parts
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 80

            for line in lines:
                if line.lower().startswith('host:'):
                    host_header = line.split(':', 1)[1].strip()
                    if ':' in host_header:
                        host, port = host_header.split(':')
                        port = int(port)
                    else:
                        host = host_header
                    break

            dst_socket = socket.create_connection((host, port))
            dst_socket.settimeout(30)

            dst_socket.sendall(request.encode())

            threading.Thread(target=self.forward_data, args=(client_socket, dst_socket), daemon=True).start()
            threading.Thread(target=self.forward_data, args=(dst_socket, client_socket), daemon=True).start()

        except Exception as e:
            logging.error(f"Error handling HTTP request: {e}")
            client_socket.close()

    def handle_https(self, request, client_socket):
        try:
            lines = request.split('\r\n')
            if not lines:
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 3:
                return

            _, host_port, _ = parts
            if ':' in host_port:
                host, port = host_port.split(':')
                port = int(port)
            else:
                host = host_port
                port = 443

            dst_socket = socket.create_connection((host, port))
            dst_socket.settimeout(30)

            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            threading.Thread(target=self.forward_data, args=(client_socket, dst_socket), daemon=True).start()
            threading.Thread(target=self.forward_data, args=(dst_socket, client_socket), daemon=True).start()

        except Exception as e:
            logging.error(f"Error handling HTTPS request: {e}")
            client_socket.close()

    def is_ftp_request(self, request):
        ftp_commands = ["USER", "PASS", "LIST", "RETR", "STOR", "QUIT", "PORT", "PASV"]
        for cmd in ftp_commands:
            if request.startswith(cmd):
                return True
        return False

    def handle_ftp(self, client_socket, request):
        try:
            lines = request.split('\r\n')
            ftp_host = None
            for line in lines:
                if line.startswith("USER"):
                    # Extract host from USER command, e.g., USER ftp.server.com
                    ftp_host = line.split()[1]
                    break

            if not ftp_host:
                logging.error("Could not extract FTP host from request.")
                client_socket.close()
                return

            ftp_port = 21  # Default FTP port
            ftp_socket = socket.create_connection((ftp_host, ftp_port))
            ftp_socket.settimeout(30)

            threading.Thread(target=self.forward_data, args=(client_socket, ftp_socket), daemon=True).start()
            threading.Thread(target=self.forward_data, args=(ftp_socket, client_socket), daemon=True).start()

        except Exception as e:
            logging.error(f"Error handling FTP request: {e}")
            client_socket.close()

    def recv_all(self, sock):
        data = b''
        try:
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                data += part
                if len(part) < 4096:
                    break
        except socket.timeout:
            logging.warning("Receive operation timed out.")
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
        finally:
            sock.settimeout(None)
        return data

if __name__ == "__main__":
    proxy_server = Proxy()
    proxy_server.start()
