import socket
import threading
import win32file
import win32event
import winerror
import pywintypes

# Server TAP Adapter Name
TAP_DEVICE_NAME = r'\\.\Global\{{{GUID}}}.tap'.format(GUID='6C846D6C-8DC2-4374-A01B-F61F8E36B248')

# Server IP and Port
SERVER_HOST = "127.0.0.1"  # Localhost
SERVER_PORT = 1194         # VPN Port

def open_tap_device():
    """Open the server TAP device with overlapped I/O."""
    try:
        handle = win32file.CreateFile(
            TAP_DEVICE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
            None
        )
        print("TAP device opened successfully!")
        return handle
    except Exception as e:
        print(f"Failed to open TAP device: {e}")
        raise

def read_tap(handle):
    """Read packets from TAP device using overlapped I/O."""
    buffer_size = 4096
    buffer = win32file.AllocateReadBuffer(buffer_size)

    while True:
        try:
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
            hr = win32file.ReadFile(handle, buffer, overlapped)
            if hr == winerror.ERROR_IO_PENDING:
                win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
                nbytes = win32file.GetOverlappedResult(handle, overlapped, True)
            else:
                nbytes = win32file.GetOverlappedResult(handle, overlapped, False)

            if nbytes == 0:
                continue

            data = buffer[:nbytes]
            win32event.ResetEvent(overlapped.hEvent)
            yield data

        except Exception as e:
            print(f"Error reading TAP device: {e}")
            # Optionally handle specific exceptions or attempt to continue
            break  # or continue based on the exception

def write_tap(handle, data):
    """Write packets to TAP device using overlapped I/O."""
    if not data:
        return
    try:
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        hr = win32file.WriteFile(handle, data, overlapped)
        if hr == winerror.ERROR_IO_PENDING:
            win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
            win32file.GetOverlappedResult(handle, overlapped, True)
        elif hr != 0:
            raise pywintypes.error(hr, 'WriteFile', 'Unknown error')
        win32event.ResetEvent(overlapped.hEvent)
    except Exception as e:
        print(f"Error writing to TAP device: {e}")


def handle_client(client_socket, tap_handle):
    """Handle traffic between client and TAP adapter."""
    try:
        threading.Thread(target=forward_client_to_tap, args=(client_socket, tap_handle), daemon=True).start()
        threading.Thread(target=forward_tap_to_client, args=(tap_handle, client_socket), daemon=True).start()
    except Exception as e:
        print(f"Error handling client: {e}")

def forward_client_to_tap(client_socket, tap_handle):
    """Forward traffic from client to TAP adapter."""
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("Client disconnected.")
                break
            write_tap(tap_handle, data)
        except Exception as e:
            print(f"Error forwarding client to TAP: {e}")
            break

def forward_tap_to_client(tap_handle, client_socket):
    """Forward traffic from TAP adapter to client."""
    for data in read_tap(tap_handle):
        try:
            if not data:
                continue
            client_socket.sendall(data)
        except Exception as e:
            print(f"Error forwarding TAP to client: {e}")
            break

def run_server():
    """Run the VPN server."""
    tap_handle = open_tap_device()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Client connected from {addr}")
        handle_client(client_socket, tap_handle)

if __name__ == "__main__":
    run_server()
