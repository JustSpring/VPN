files= ["client/vpn_client.py","server/auth_handler.py","server/create_keys.py","server/PROXY_SERVER.py","server/tunnel.py","server/users_table.py","server/VPN_SERVER.py","shared/config.py"]
for file in files:
    print(file)
    with open(file, 'r') as file_content:
        print(file_content.read())
    print("----------------")
