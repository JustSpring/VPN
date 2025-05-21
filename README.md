# SpringConnect- Custom VPN Solution

## Overview
This project is a **custom VPN (Virtual Private Network)** solution developed in **Python**, focusing on secure communication and proxy-based traffic redirection.

Clients connect to the internet through **secure proxies** chosen from a list provided by the server. All communication is encrypted via **TLS 1.3**, and clients are authenticated using **multi-factor authentication** and **certificates**.

---

## Key Features

### Security
- **TLS 1.3 Encryption** for all traffic between client and server
- **Elliptic Curve Diffie-Hellman (ECDHE)** for key exchange
- **AES-256 GCM** symmetric encryption with **HMAC-SHA-384**
- **Mutual Certificate Authentication**: both client and server verify each other's certificate
- **Multi-Factor Authentication**: Username + Password + TOTP (Time-Based One-Time Password)

### Network Architecture
- **Proxy-Based Routing**: traffic is tunneled through a proxy server selected by the client
- **Client-Side Proxy Management**: local proxy runs on 127.0.0.1 and transparently redirects traffic
- **Secure HTTP/S Support**

### Client UI
- Select desired proxy from available options
- Real-time speed monitoring
- Persistent certificates and authentication tokens
- Simple graphical interface using Kivy

### Server UI
- View connected users and proxy servers
- Add, update, or delete users
- Force user disconnection (“kick”)
- View proxy status and logs
- Manage TOTP secrets and credentials

---
## Configuration & Prerequisites

All components require **Python 3.8** to be installed.

### Server
**Required libraries:**  
`kivy`, `pyotp`, `qrcode`, `keyring`, `cryptography`, `pillow`  
Install with:
```bash
pip install kivy pyotp qrcode keyring cryptography pillow
```
### Client
**Required libraries:**  
`kivy`, `pyotp`, `cryptography`, `pyOpenSSL` 
Install with:
```bash
pip install kivy pyotp cryptography pyopenssl
```
### Remote Proxy
**Required libraries:**  
`pyotp`, `keyring`
Install with:
```bash
pip install pyotpkeyring
```

---

## Security Notes

- Encrypted traffic with authenticated peers
- Secure key exchange (ECDHE)
- Certificate pinning prevents MITM attacks
- Only certificates signed by server are allowed

---

## Screenshots

### Client UI
Easy login with TOTP, proxy selection, and live speed stats  
![Client UI1](https://github.com/user-attachments/assets/38f39a0f-9f2a-4978-83f5-243960a18821)
![Client UI2](https://github.com/user-attachments/assets/d59745ca-2a5b-4913-8963-1ed4f1232bb8)
![Client UI3](https://github.com/user-attachments/assets/6bb92572-9bd7-4cdc-90d5-a055a5089472)
![Client UI4](https://github.com/user-attachments/assets/086c8f92-cea4-42b5-9299-1d73034758ca)

### Server UI
Full user and proxy management from an admin panel  
![Server UI](https://github.com/user-attachments/assets/a90ae0db-8c7b-4b84-819d-658b69e6ba86)
![Server UI](https://github.com/user-attachments/assets/11be1bf7-972f-448a-827f-52986532e9b0)

---

## Project Structure


```text
VPN/
├── shared/
│   ├── config.py
│   └── logo.ico
├── server/
│   ├── active_users.db
│   ├── create_keys.py
│   ├── full_log.db
│   ├── log.db
│   ├── manage_db.py
│   ├── proxy_server.py
│   ├── server_UI.py
│   ├── users.db
│   ├── vpn_server.py
│   └── certificates/
│       ├── ca_cert.pem
│       ├── ca_key.pem
│       ├── server_cert.pem
│       ├── server_key.pem
│       └── client/
│           ├── client_cert.pem
│           ├── client_csr.pem
│           └── client_key.pem
└── client/
    ├── client_UI.py
    ├── vpn_client.py
    └── certificates/
        ├── ca_cert.pem
        ├── ca_cert_chain.pem
        ├── ca_key.pem
        ├── client_cert.pem
        ├── client_key.pem
        ├── initial_client_cert.pem
        ├── initial_client_key.pem
        ├── server_cert.pem
        └── server_key.pem

