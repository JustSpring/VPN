import select
import socket
import threading
import logging
import pickle
import sys
import os
from urllib.parse import urlparse

# add parent directory to path for shared imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addresses
import manage_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
BUFFER_SIZE = 65536

class Proxy:
    def __init__(self, host=Addresses.SERVER_PROXY_IPS[0], port=Addresses.SERVER_PROXY_PORT):
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
                threading.Thread(
                    target=self.handle_client_request,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except Exception as e:
                logging.error(f"Error accepting client connection: {e}")

    def handle_client_request(self, client_socket, client_address):
        logging.info(f"Spawning read loop for client {client_address}")
        channel_map = {}
        self.read_loop(channel_map, client_socket)

    def read_loop(self, channel_map, client_socket):
        name = "NONE"
        try:
            while True:
                # build monitored sockets
                sockets = [client_socket] + [info["socket"] for info in channel_map.values() if info.get("socket")]
                # detect closed client
                if client_socket.fileno() < 0:
                    logging.info("Client socket closed, exiting read_loop.")
                    return

                readable, _, _ = select.select(sockets, [], [], 0.5)
                for sock in readable:
                    if sock is client_socket:
                        # read frame length
                        try:
                            length_bytes = sock.recv(4)
                        except (ConnectionResetError, OSError) as e:
                            logging.info(f"Client disconnected/reset: {e}")
                            return
                        if not length_bytes:
                            logging.info("Client disconnected cleanly.")
                            return
                        frame_len = int.from_bytes(length_bytes, 'big')
                        # read full frame
                        frame_data = b''
                        while len(frame_data) < frame_len:
                            chunk = sock.recv(frame_len - len(frame_data))
                            if not chunk:
                                logging.warning("Frame truncated; exiting read_loop.")
                                return
                            frame_data += chunk
                        # unpack
                        header, payload = pickle.loads(frame_data)
                        cid = header.get("channel_id")

                        # handle control headers
                        if header.get("type") == "CHANGE_NAME":
                            name = manage_db.get_active_name(
                                cert=payload.decode('utf-8', errors='ignore')
                            )
                        elif header.get("type") == "OPEN_CHANNEL":
                            channel_map[cid] = {"socket": None, "host": None, "port": None, "protocol": None}
                        elif header.get("type") == "DATA":
                            entry = channel_map.get(cid)
                            if not entry:
                                continue
                            # open downstream socket if first DATA
                            if entry["socket"] is None:
                                host, port = self.get_host_port(
                                    payload.decode('utf-8', errors='ignore')
                                )
                                if not host or not port:
                                    logging.error(f"Invalid host/port for channel {cid}, closing channel.")
                                    del channel_map[cid]
                                    continue
                                try:
                                    downstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    downstream.settimeout(10)
                                    downstream.connect((host, port))
                                except Exception as e:
                                    logging.error(f"Could not connect to {host}:{port}: {e}")
                                    del channel_map[cid]
                                    continue
                                proto = self.determine_protocol(payload, port)
                                entry.update({"socket": downstream, "host": host, "port": port, "protocol": proto})
                                if payload.startswith(b"CONNECT"):
                                    # reply to client for CONNECT
                                    self.send_frame(
                                        {"type": "DATA", "channel_id": cid},
                                        b"HTTP/1.1 200 Connection Established\r\n\r\n",
                                        client_socket
                                    )
                                else:
                                    downstream.sendall(payload)
                            else:
                                # normal data relay
                                try:
                                    entry["socket"].sendall(payload)
                                except Exception as e:
                                    logging.error(f"Error sending to downstream ({cid}): {e}")
                                    entry["socket"].close()
                                    del channel_map[cid]
                            if entry and entry["host"]:
                                manage_db.add_full_logging(name, entry["host"], entry["port"],
                                                             entry["protocol"])
                    else:
                        # data from remote host back to client
                        cid = next((k for k, v in channel_map.items() if v.get("socket") == sock), None)
                        if cid is None:
                            continue
                        try:
                            data = sock.recv(BUFFER_SIZE)
                        except ConnectionResetError as e:
                            logging.info(f"Remote host reset channel {cid}: {e}")
                            sock.close()
                            del channel_map[cid]
                            continue
                        if not data:
                            logging.info(f"Channel {cid} closed by remote.")
                            sock.close()
                            del channel_map[cid]
                            continue
                        # forward back to client
                        self.send_frame({"type": "DATA", "channel_id": cid}, data, client_socket)
        except Exception as e:
            logging.error(f"Unexpected error in read_loop: {e}")
        finally:
            # cleanup
            for entry in channel_map.values():
                s = entry.get("socket")
                if s:
                    try: s.close()
                    except: pass
            try: client_socket.close()
            except: pass

    def send_frame(self, header, payload, client_socket):
        # drop if client closed
        if client_socket.fileno() < 0:
            return
        try:
            frame = pickle.dumps((header, payload))
            length = len(frame).to_bytes(4, 'big')
            client_socket.sendall(length + frame)
        except Exception:
            # ignore sending errors once connection dead
            pass

    def get_host_port(self, payload_str):
        lines = payload_str.split('\n')
        connect_line = next((l for l in lines if l.startswith("CONNECT")), None)
        if connect_line:
            parsed = urlparse(f"http://{connect_line.split()[1]}")
        else:
            parts = lines[0].split()
            parsed = urlparse(parts[1]) if len(parts) > 1 else None
        if not parsed:
            return None, None
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return parsed.hostname, port

    def determine_protocol(self, payload, port):
        txt = payload.decode('utf-8', errors='ignore').upper()
        if txt.startswith("CONNECT") or port == 443:
            return "HTTPS"
        if self.is_ftp_request(txt):
            return "FTP"
        if "HTTP" in txt:
            return "HTTP"
        return "OTHER"

    def is_ftp_request(self, request):
        cmds = ["USER","PASS","LIST","RETR","STOR","QUIT","PORT","PASV"]
        return any(request.startswith(cmd) for cmd in cmds)

if __name__ == "__main__":
    proxy_server = Proxy()
    proxy_server.start()
