# control_handler.py
import logging
import pickle
import active_users

"""
This module defines how to handle control connections from an admin or control client.
"""

def handle_control_client(server, secure_socket, client_address,username):
    """
    Handles incoming commands on the server's control port.
    'server' is the main server instance, so we can access server properties or methods.
    """
    logging.info(f"[CONTROL] Started control thread for {client_address}")

    try:
        while True:
            data = secure_socket.recv(4096)
            if not data:
                # Client closed the connection
                break

            command = data.decode('utf-8', errors='ignore').strip()
            logging.info(f"[CONTROL] Received command from {client_address}: {command}")

            # Example 1: SHUTDOWN
            if command.upper() == "SHUTDOWN":
                response = "Server will shut down soon...\n"
                secure_socket.sendall(response.encode())
                # (Optional) Add any actual shutdown logic you want here, e.g.:
                # server.request_shutdown = True
                # or server.stop_all_threads()
                break

            elif command.upper() == "LIST_PROXIES":
                secure_socket.sendall(pickle.dumps(server.proxy_list))

            elif command.startswith("CHOOSE_PROXY"):
                active_users.update_proxy(username,command.split()[1])
                # response = "Hello from the control server!\n"
                # secure_socket.sendall(response.encode())

            else:
                response = f"Unknown command: {command}\n"
                secure_socket.sendall(response.encode())

    except Exception as e:
        logging.error(f"[CONTROL] Error in control client thread: {e}")
    finally:
        secure_socket.close()
        logging.info(f"[CONTROL] Control client {client_address} disconnected.")
