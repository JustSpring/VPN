import pickle
from users_table import check_user
from create_keys import create_all_keys
def transfer_cert(socket):
    res=socket.recv(4096)
    user_dict=pickle.loads(res)
    username,password,totp=None,None,None
    if isinstance(user_dict,dict):
        if "username" in user_dict:
            username=user_dict["username"]
        if "password" in user_dict:
            password=user_dict["password"]
        if "totp" in user_dict:
            totp=user_dict["totp"]
    if not username or not password or not totp:
        socket.close()
        return
    ans = check_user(username, password,totp)
    if ans != 0:
        msg=ans
    else:
        msg= create_all_keys()
    socket.send(pickle.dumps(msg))
