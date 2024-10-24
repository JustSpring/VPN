import os
class Addreses():
    # Server IP and Ports
    SERVER_IP="192.168.68.129"
    SERVER_PORT=443
    SERVER_PORT_CERT=442
    SERVER_PROXY_IP="192.168.68.129"
    SERVER_PROXY_PORT = 2345
    LOCAL_PROXY_IP="127.0.0.1"
    LOCAL_PROXY_PORT = 8080

    # Paths for certificates
    CERT_DIR = os.path.join(os.getcwd(), 'certificates')
    SERVER_CERT_PATH = os.path.join(CERT_DIR, 'server_cert.pem')
    SERVER_KEY_PATH = os.path.join(CERT_DIR, 'server_key.pem')
    CLIENT_INITIAL_KEY_PATH = os.path.join(CERT_DIR, 'initial_client_key.pem')
    CLIENT_INITIAL_CERT_PATH = os.path.join(CERT_DIR, 'initial_client_cert.pem')
    CLIENT_CERT_PATH = os.path.join(CERT_DIR, 'client_cert.pem')
    CLIENT_KEY_PATH = os.path.join(CERT_DIR, 'client_key.pem')
    CA_CERT_PATH = os.path.join(CERT_DIR, 'ca_cert.pem')

