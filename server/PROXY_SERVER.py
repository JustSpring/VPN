import select
import socket
import threading
import logging
from urllib.parse import urlparse
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addreses
import log_manager
import active_users
from urllib.parse import urlparse
import pickle
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
BUFFER_SIZE = 65536
from cryptography import x509

class Proxy:
    # Fix host for different proxy
    def __init__(self, host=Addreses.SERVER_PROXY_IPS[0], port=Addreses.SERVER_PROXY_PORT):
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

    def handle_client_request2(self, client_socket,addr):
        channel_map={}
        threading.Thread(target=self.read_loop, args=(channel_map,), daemon=True).start()
        try:
            request = self.recv_all(client_socket)
            if not request:
                client_socket.close()
                return
            if isinstance(request, bytes):
                request = request.decode('utf-8', errors='ignore')

            if request.startswith("CONNECT"):
                self.handle_https(request, client_socket,addr)
                return
            elif "HTTP" in request:
                self.handle_http(request, client_socket,addr)
                return
            elif self.is_ftp_request(request):
                self.handle_ftp(client_socket, request)
                return
            logging.warning("Unsupported protocol or malformed request.")
            client_socket.close()

        except Exception as e:
            logging.error(f"Error handling client request: {e}")
            client_socket.close()

    def handle_client_request(self, client_socket):
        #TODO GET NAME BY CERT
        channel_map = {}
        threading.Thread(target=self.read_loop, args=(channel_map,client_socket,), daemon=True).start()

    def get_host_port(self, payload):
        lines = payload.split('\n')
        host = None
        port = None

        connect_line = next((line for line in lines if line.startswith("CONNECT")), None)
        if connect_line:
            url = connect_line.split()[1] if len(connect_line.split()) > 1 else None
            if url:
                parsed_url = urlparse(f"http://{url}")
            else:
                logging.error("Invalid CONNECT line format!")
                return None, None
        else:
            # Handle regular HTTP methods
            request_line = lines[0] if len(lines) > 0 else None
            if request_line and len(request_line.split()) > 1:
                url = request_line.split()[1]
                parsed_url = urlparse(url)
            else:
                logging.error("Invalid request line format!")
                return None, None

        host = parsed_url.hostname
        if parsed_url.port:
            port = parsed_url.port
        elif parsed_url.scheme == "http":
            port = 80
        elif parsed_url.scheme == "https":
            port = 443
        elif parsed_url.scheme == "ftp":
            port = 21
        else:
            port = None
            logging.error(f"Port not found in payload! PORT IS {port}")

        return host, port

    def read_loop(self,channel_map,client_socket):
        name="NONE"
        while True:
            try:
                sockets_to_monitor = [client_socket] + [info["socket"] for info in channel_map.values() if info["socket"]]
                readable, _, _ = select.select(sockets_to_monitor, [], [], 0.5)
                for sock in readable:
                    if sock is client_socket:
                        # Data from the client (VPN user)
                        length_bytes = client_socket.recv(4)
                        if not length_bytes:
                            break  # Client disconnected
                        frame_len = int.from_bytes(length_bytes, 'big')
                        # Ensure full frame is received
                        frame_data = b""
                        while len(frame_data) < frame_len:
                            chunk = client_socket.recv(frame_len - len(frame_data))
                            if not chunk:
                                break
                            frame_data += chunk

                        header, payload = pickle.loads(frame_data)
                        # logging.info(payload)
                        channel_id = header["channel_id"]
                        if header["type"]=="CHANGE_NAME":
                            name=active_users.get_name_by_cert(payload.decode('utf-8', errors='ignore'))
                        if header["type"] == "OPEN_CHANNEL":
                            channel_map[channel_id] = {"socket":None,"host":None,"port":None,"protocol":None}
                        elif header["type"] == "DATA":
                            entry= channel_map.get(channel_id) # TODO WHAT IS GET
                            if not entry:
                                continue
                            current_socket=entry.get("socket")
                            if not current_socket:
                                host, port = self.get_host_port(payload.decode('utf-8', errors='ignore'))
                                protocol= self.determine_protocol(payload, port)
                                if not host or not port:
                                    continue

                                current_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                current_socket.connect((host, port))
                                entry["socket"] = current_socket
                                entry["host"] = host
                                entry["port"] = port
                                entry["protocol"] = protocol
                                if payload.startswith(b"CONNECT"):
                                    self.send_frame(
                                        {"type": "DATA", "channel_id": channel_id},
                                        b"HTTP/1.1 200 Connection Established\r\n\r\n",
                                        client_socket
                                    )
                                else:
                                    current_socket.sendall(payload)

                            else:
                                current_socket.sendall(payload)



                    else:
                        channel_id = next((k for k, v in channel_map.items() if v["socket"] == sock), None)
                        if channel_id is None:
                            continue
                        try:
                            data = sock.recv(BUFFER_SIZE)
                            if not data:
                                sock.close()
                                if channel_map[channel_id]:
                                    del channel_map[channel_id]
                                continue
                            header = {"type": "DATA", "channel_id": channel_id}
                            self.send_frame(header,data,client_socket)
                            # logging.info(f"Forwarded {len(data)} bytes from {sock.getpeername()} to {client_socket.getpeername()}")

                        except Exception as e:
                            print(f"Error reading from remote socket {sock.getpeername()} - {e}")
                            sock.close()
                            del channel_map[channel_id]
                    current_entry=None
                    for channel_id, entry in channel_map.items():
                        if entry["socket"] == sock:
                            current_entry= entry
                    if current_entry and current_entry["host"]:
                        log_manager.add_full_logging(name,current_entry["host"],current_entry["port"],current_entry["protocol"])
            except Exception as e:
                logging.error(f"Error in read_loop: {e}")

    def send_frame(self, header, payload,client_socket):
        try:
            frame = pickle.dumps((header, payload))
            frame_len = len(frame).to_bytes(4, "big")
            client_socket.sendall(frame_len + frame)
            # logging.info(f"Forwarded {len(payload)} bytes from proxy to {client_socket.getpeername()}")
        except Exception as e:
            logging.info(f"Error sending frame to client via server: {e}")
    def handle_request(self,client_sock,channel_id,internet_sock,payload):
        if not internet_sock:
            print("what the heck")
        if payload.startswith(b'CONNECT'):
            self.send_frame({"type": "DATA", "channel_id": channel_id},b'HTTP/1.1 200 Connection Established\r\n\r\n',client_sock) #TODO CHECK THIS
        internet_sock.sendall(payload)
        return
        host,port=self.get_host_port(payload.decode('utf-8', errors='ignore'))
        if port==80: #HTTP
            internet_sock.sendall(payload)
            logging.info(f"Forwarded {len(payload)} bytes from proxy to {internet_sock.getpeername()}")
        elif port==443: #HTTPS
            self.send_frame({"type": "DATA", "channel_id": channel_id},b'HTTP/1.1 200 Connection Established\r\n\r\n',client_sock) #TODO CHECK THIS
            internet_sock.sendall(payload)
        else:
            logging.error("PROTOCOL NOT SUPPORTED")
            print(payload.decode('utf-8', errors='ignore'))

    def determine_protocol(self, payload, port):
        text = payload.decode('utf-8', errors='ignore').upper()
        if text.startswith("CONNECT") or port == 443:
            return "HTTPS"
        elif self.is_ftp_request(text):
            return "FTP"
        else:
            if "HTTP" in text:
                return "HTTP"
            else:
                return "OTHER"

    def is_ftp_request(self, request):
        ftp_commands = ["USER", "PASS", "LIST", "RETR", "STOR", "QUIT", "PORT", "PASV"]
        for cmd in ftp_commands:
            if request.startswith(cmd):
                return True
        return False

    def forward_data(self, src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
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
            name = active_users.get_name_by_port(client_address[1])
            if name:
                log_manager.add_full_logging(name,host,port,"HTTP")

            dst_socket = socket.create_connection((host, port))
            dst_socket.settimeout(30)

            dst_socket.sendall(request.encode())

            threading.Thread(target=self.forward_data, args=(client_socket, dst_socket), daemon=True).start()
            threading.Thread(target=self.forward_data, args=(dst_socket, client_socket), daemon=True).start()

        except Exception as e:
            logging.error(f"Error handling HTTP request: {e}")
            client_socket.close()

    def handle_https(self, request, client_socket,client_address):
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
            name=active_users.get_name_by_port(client_address[1])
            if name:
                log_manager.add_full_logging(name,host,port ,"HTTPS")
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
