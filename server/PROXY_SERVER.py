import socket
import threading
from shared.config import Addreses
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Proxy:
    def __init__(self, host=Addreses.SERVER_PROXY_IP, port=Addreses.SERVER_PROXY_PORT):
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
            print(request)
            if not request:
                client_socket.close()
                return

            dst_host, dst_port,connect = self.get_host_port(request)
            if not dst_host or not dst_port:
                logging.error("Failed to parse host and port from request.")
                client_socket.close()
                return

            logging.info(f"Forwarding request to {dst_host} on port {dst_port}")

            dst_socket = socket.create_connection((dst_host, dst_port))
            dst_socket.settimeout(30)  # set timeout to prevent blocking indefinitely
            if connect:
                print("sent 200")
                client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                dst_socket.sendall(request)

            # Start bidirectional forwarding
            client_to_server = threading.Thread(target=self.forward_data, args=(client_socket, dst_socket), daemon=True)
            server_to_client = threading.Thread(target=self.forward_data, args=(dst_socket, client_socket), daemon=True)

            client_to_server.start()
            server_to_client.start()




        except Exception as e:
            logging.error(f"Error handling client request: {e}")
            client_socket.close()
        except socket.timeout:
            logging.warning("Receive operation timed out.")
        # finally:
        #     client_socket.close()

    def forward_data(self, src, dst):
        try:
            print(src)
            while True:
                data = src.recv(4096)
                if not data:
                    break
                logging.info(f"Attempting to Forward {len(data)} bytes from {src.getpeername()} to {dst.getpeername()}")
                dst.sendall(data)
                logging.info(f"Forwarded {len(data)} bytes from {src.getpeername()} to {dst.getpeername()}")
        except Exception as e:
            logging.error(f"Error forwarding data: {e}")
            raise e


    def get_host_port(self, request):

        if isinstance(request, bytes):
            request = request.decode('utf-8', errors='ignore')
        if request.startswith("CONNECT"):
            connect=True
        else:
            connect=False
        # Split the request into lines
        lines = request.split('\r\n')
        if not lines:
            return None, None

        # Extract the request line (e.g., GET http://example.com/ HTTP/1.1)
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 3:
            return None, None

        method, url, protocol = parts

        # Parse the URL to extract components
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port

        # Default ports based on the scheme
        if not port:
            if parsed_url.scheme == 'http':
                port = 80
            elif parsed_url.scheme == 'https':
                port = 443
            else:
                port = 80  # Default to 80 if scheme is unrecognized

        # Override with Host header if present
        for line in lines:
            if line.lower().startswith('host:'):
                host_header = line.split(':', 1)[1].strip()
                if ':' in host_header:
                    host, port_str = host_header.split(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = port  # Keep previous port if conversion fails
                else:
                    host = host_header
                break

        return host, port,connect

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
            sock.settimeout(None)  # Reset timeout
        return data

if __name__ == "__main__":
    proxy_server = Proxy()
    proxy_server.start()