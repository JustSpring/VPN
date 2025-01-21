import socket
import threading
import win32file
import win32event
import winerror
import pywintypes

# Client TAP Adapter Name
TAP_DEVICE_NAME = r'\\.\Global\{{{GUID}}}.tap'.format(GUID='C7BE34AA-0757-4657-85AB-8AF4B803B801')

# Server Address
SERVER_HOST = "192.168.68.137"  # Replace with your server's IP address
SERVER_PORT = 1194              # VPN Port

def open_tap_device():
    """Open the client TAP device with overlapped I/O."""
    try:
        handle = win32file.CreateFile(
            TAP_DEVICE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL | win32file.FILE_FLAG_OVERLAPPED,
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

    # Allocate buffer and create overlapped structure once
    buffer = win32file.AllocateReadBuffer(buffer_size)
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)

    while True:
        try:
            # Reset the event before starting the operation
            win32event.ResetEvent(overlapped.hEvent)

            hr = win32file.ReadFile(handle, buffer, overlapped)
            if hr == winerror.ERROR_IO_PENDING:
                win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
                nbytes = win32file.GetOverlappedResult(handle, overlapped, True)
            else:
                nbytes = win32file.GetOverlappedResult(handle, overlapped, False)

            if nbytes == 0:
                continue

            data = buffer[:nbytes]
            yield data

        except pywintypes.error as e:
            if e.winerror == winerror.ERROR_OPERATION_ABORTED:
                print("Read operation aborted, retrying...")
                continue
            else:
                print(f"Error reading TAP device: {e}")
                break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break

def write_tap(handle, data):
    """Write packets to TAP device using overlapped I/O."""
    if not data:
        return

    # Create overlapped structure and event
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)

    try:
        win32event.ResetEvent(overlapped.hEvent)

        hr = win32file.WriteFile(handle, data, overlapped)
        if hr == winerror.ERROR_IO_PENDING:
            win32event.WaitForSingleObject(overlapped.hEvent, win32event.INFINITE)
            win32file.GetOverlappedResult(handle, overlapped, True)
        elif hr != 0:
            raise pywintypes.error(hr, 'WriteFile', 'Unknown error')
    except pywintypes.error as e:
        if e.winerror == winerror.ERROR_OPERATION_ABORTED:
            print("Write operation aborted, retrying...")
        else:
            print(f"Error writing to TAP device: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def forward_tap_to_server(tap_handle, server_socket):
    """Forward traffic from TAP to server."""
    for data in read_tap(tap_handle):
        try:
            if not data:
                continue
            server_socket.sendall(data)
        except Exception as e:
            print(f"Error forwarding TAP to server: {e}")
            break

def forward_server_to_tap(server_socket, tap_handle):
    """Forward traffic from server to TAP adapter."""
    while True:
        try:
            data = server_socket.recv(4096)
            if not data:
                print("Server disconnected.")
                break
            write_tap(tap_handle, data)
        except Exception as e:
            print(f"Error forwarding server to TAP: {e}")
            break

def run_client():
    """Run the VPN client."""
    tap_handle = open_tap_device()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

    thread1 = threading.Thread(target=forward_tap_to_server, args=(tap_handle, server_socket))
    thread2 = threading.Thread(target=forward_server_to_tap, args=(server_socket, tap_handle))
    thread1.start()
    thread2.start()

    # Keep the main thread alive by joining the threads
    thread1.join()
    thread2.join()

if __name__ == "__main__":
    run_client()