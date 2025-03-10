import pickle
from users_table import check_user,update_cert_serial
from create_keys import create_all_keys
import logging
from log_manager import add_logging

logging.basicConfig(level=logging.INFO)

def transfer_cert(socket,client_address):
    try:
        res = socket.recv(4096)
        user_dict = pickle.loads(res)
        username = user_dict.get("username")
        password = user_dict.get("password")
        totp = user_dict.get("totp")

        if not username or not password or not totp:
            raise ValueError("Missing required fields in user dictionary")

        ans = check_user(username, password, totp)
        if ans != 0:
            add_logging(client_address[0],"Failed attempt signing in as "+username+" - "+ password+" - "+totp)
            socket.send(pickle.dumps(-1))  # Send failure response

        else:
            add_logging(client_address[0],"successfully signed in as "+username)
            cert_data = create_all_keys()
            update_cert_serial(username,cert_data[2])
            print(f"cert is {cert_data[2]}")
            socket.send(pickle.dumps(cert_data))
    except Exception as e:
        logging.error(f"Error in transfer_cert: {e}")
        socket.close()