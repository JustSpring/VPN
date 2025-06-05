# Proxy_server.py

import select
import socket
import threading
import logging
import pickle
import sys
import os
from urllib.parse import urlparse
import re

# add parent directory to path for shared imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.config import Addresses
import manage_db

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
BUFFER_SIZE = 16_384

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
        """
        Handle requests.
        """
        name = "NONE"

        try:
            while True:
                # build the list of sockets we care about
                sockets = [client_socket] + [
                    info["socket"] for info in channel_map.values()
                    if info.get("socket") and info["socket"].fileno() >= 0
                ]

                # quit if the socket already closed
                if client_socket.fileno() < 0:
                    return

                readable, _, _ = select.select(sockets, [], [], 0.5)

                for sock in readable:
                    # ───────────────────── data FROM CLIENT ──────────────────
                    if sock is client_socket:
                        # read frame header length
                        try:
                            length_bytes = sock.recv(4)
                        except (ConnectionResetError, OSError) as e:
                            logging.info(f"Client disconnected/reset: {e}")
                            return
                        if not length_bytes:
                            logging.info("Client disconnected.")
                            return

                        frame_len = int.from_bytes(length_bytes, 'big')

                        # read the rest of the frame
                        frame_data = b''
                        while len(frame_data) < frame_len:
                            chunk = sock.recv(frame_len - len(frame_data))
                            if not chunk:
                                logging.warning("Frame truncated; exiting.")
                                return
                            frame_data += chunk

                        header, payload = pickle.loads(frame_data)
                        cid = header.get("channel_id")

                        if header.get("type") == "CHANGE_NAME":
                            name = manage_db.get_active_name(
                                cert=payload.decode('utf-8', errors='ignore'))
                            continue

                        if header.get("type") == "OPEN_CHANNEL":
                            channel_map[cid] = {"socket": None,
                                                "host": None,
                                                "port": None,
                                                "protocol": None}
                            continue

                        if header.get("type") == "CLOSE_CHANNEL":
                            entry = channel_map.pop(cid, None)
                            if entry and entry.get("socket"):
                                try:
                                    entry["socket"].shutdown(socket.SHUT_RDWR)
                                except Exception:
                                    pass
                                entry["socket"].close()
                            continue

                        if header.get("type") == "DATA":
                            entry = channel_map.get(cid)
                            if not entry:
                                continue

                            # if first DATA frame open socket
                            if entry["socket"] is None:
                                host, port = self.get_host_port(
                                    payload.decode('utf-8', errors='ignore'))

                                if not host:
                                    logging.error(f"[Proxy] No host header "
                                                  f"for channel {cid}; closing.")
                                    self.send_frame({"type": "CLOSE_CHANNEL",
                                                     "channel_id": cid},
                                                     b"", client_socket)
                                    del channel_map[cid]
                                    continue

                                logging.info(f"[Proxy] Opening downstream "
                                             f"{cid} → {host}:{port}")
                                downstream = socket.socket(socket.AF_INET,
                                                           socket.SOCK_STREAM)
                                downstream.settimeout(10)
                                try:
                                    downstream.connect((host, port))
                                except Exception as e:
                                    logging.error(f"[Proxy] connect() failed "
                                                  f"({cid}) {host}:{port}: {e}")
                                    downstream.close()
                                    self.send_frame({"type": "CLOSE_CHANNEL",
                                                     "channel_id": cid},
                                                     b"", client_socket)
                                    del channel_map[cid]
                                    continue

                                proto = self.determine_protocol(payload, port)
                                entry.update({"socket": downstream,
                                              "host": host,
                                              "port": port,
                                              "protocol": proto})

                                if payload.startswith(b"CONNECT"):
                                    self.send_frame({"type": "DATA",
                                                     "channel_id": cid},
                                                     b"HTTP/1.1 200 Connection "
                                                     b"Established\r\n\r\n",
                                                     client_socket)
                                else:
                                    downstream.sendall(payload)
                                    logging.info(f"[C→S] ch={cid:3}  {len(payload):5} bytes  →  "
                                                 f"{host}:{port}   (initial)")
                            else:
                                try:
                                    entry["socket"].sendall(payload)
                                    logging.info(f"[C→S] ch={cid:3}  {len(payload):5} bytes  →  "
                                                 f"{entry['host']}:{entry['port']}")
                                except Exception as e:
                                    logging.error(f"Downstream send error "
                                                  f"({cid}): {e}")
                                    entry["socket"].close()
                                    del channel_map[cid]
                                    self.send_frame({"type": "CLOSE_CHANNEL",
                                                     "channel_id": cid},
                                                     b"", client_socket)

                            # logging
                            if entry and entry["host"]:
                                manage_db.add_full_logging(
                                    name, entry["host"],
                                    entry["port"], entry["protocol"])

                    # ───────────────── data FROM DOWNSTREAM ─────────────────
                    else:
                        cid = next((k for k, v in channel_map.items()
                                    if v.get("socket") == sock), None)
                        if cid is None:
                            continue

                        try:
                            data = sock.recv(BUFFER_SIZE)
                        except (ConnectionResetError, OSError) as e:
                            logging.info(f"Remote reset on channel {cid}: {e}")
                            sock.close()
                            del channel_map[cid]
                            self.send_frame({"type": "CLOSE_CHANNEL",
                                             "channel_id": cid}, b"", client_socket)
                            continue

                        if not data:                       # EOF from remote
                            logging.info(f"Channel {cid} closed by remote.")
                            sock.close()
                            del channel_map[cid]
                            self.send_frame({"type": "CLOSE_CHANNEL",
                                             "channel_id": cid},
                                             b"", client_socket)
                            continue

                        self.send_frame({"type": "DATA",
                                         "channel_id": cid},
                                         data, client_socket)
                        logging.info(f"[S→C] ch={cid:3}  {len(data):5} bytes  ←  "
                                     f"{channel_map[cid]['host']}:{channel_map[cid]['port']}")

        except Exception as e:
            logging.error(f"Unexpected error in read_loop: {e}")

        finally:
            # tidy all sockets
            for entry in channel_map.values():
                s = entry.get("socket")
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
            try:
                client_socket.close()
            except Exception:
                pass

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

        # 1) CONNECT host:port
        if lines[0].startswith("CONNECT"):
            hostport = lines[0].split()[1]
            if ':' in hostport:
                host, port = hostport.split(':', 1)
                return host, int(port)
            return hostport, 443

        # 2) HTTP GET http://host/...
        first = lines[0].split()
        if len(first) > 1:
            parsed = urlparse(first[1])
            if parsed.hostname:
                return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)

        # 3) Host: header
        for l in lines:
            if l.lower().startswith("host:"):
                hostport = l.split(":", 1)[1].strip()
                if ':' in hostport:
                    host, port = hostport.split(':', 1)
                    return host, int(port)
                return hostport, 80

        # Could not determine
        return None, None

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
