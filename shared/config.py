import os


class Addresses:
    # Server IP and Ports
    SERVER_IP="192.168.68.131"
    SERVER_PORT=8081
    SERVER_PORT_CERT=441 # 442
    SERVER_PORT_CONTROL = 331
    SERVER_PROXY_IPS=["192.168.68.131","192.168.68.146"]
    SERVER_PROXY_PORT = 2255
    LOCAL_PROXY_IP="0.0.0.0"
    LOCAL_PROXY_PORT = 9090


    # Paths for certificates
    CERT_DIR = os.path.join(os.getcwd(), 'certificates')
    SERVER_CERT_PATH = os.path.join(CERT_DIR, 'server_cert.pem')
    SERVER_KEY_PATH = os.path.join(CERT_DIR, 'server_key.pem')
    CLIENT_INITIAL_KEY_PATH = os.path.join(CERT_DIR, 'initial_client_key.pem')
    CLIENT_INITIAL_CERT_PATH = os.path.join(CERT_DIR, 'initial_client_cert.pem')
    CLIENT_CERT_PATH = os.path.join(CERT_DIR, 'client_cert.pem')
    CLIENT_KEY_PATH = os.path.join(CERT_DIR, 'client_key.pem')
    CA_CERT_PATH = os.path.join(CERT_DIR, 'ca_cert.pem')

    # Paths for databases
    ACTIVE_DIR = os.path.join(os.getcwd(), 'active_users.db')
    FULL_LOG_DIR = os.path.join(os.getcwd(), 'full_log.db')
    LOG_DIR = os.path.join(os.getcwd(), 'log.db')
    USERS_DIR = os.path.join(os.getcwd(), 'users.db')
