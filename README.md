# Custom VPN Solution
## Overview
This project is a custom VPN (Virtual Private Network) solution developed in Python, focusing on secure communication and strong encryption.
It features SSL/TLS encryption, multi-factor authentication (username/password, TOTP, and certificates), machine-specific certificates, and a full client and server UI for easy management.
The VPN provides encrypted tunnels for traffic while ensuring robust security and flexible control for both users and administrators.
## Key Features
* SSL/TLS Encryption: Secure communication between clients and servers.
* Multi-Factor Authentication: Combines username/password, TOTP (Time-Based One-Time Password), and certificates for strong protection.
* Machine-Specific Certificates: Only authenticated devices can connect to the VPN.
* FTP Support: Securely handles FTP traffic alongside HTTP/S traffic.
* Client-Side UI: A user-friendly interface for configuring and managing VPN connections easily.
* Server-Side UI: Manage users directly from the server (add, edit, and delete users; change usernames and passwords).
* Server Selection: Clients can select the server they wish to connect to (for performance or regional access).
* Real-Time Speed Monitoring: Displays upload and download speeds during VPN use.
* Automatic Registry Modification: Updates system registry settings to redirect traffic through the VPN's local proxy, and restores original settings upon disconnection.

## Current Status
The VPN solution is fully functional and actively maintained.
* Core features like secure HTTPS proxy, FTP support, multi-factor authentication, client-server communication, server selection, speed monitoring, and automatic registry redirection are already implemented.
* The system is stable and user-friendly.

## Screenshots

### 📸 Client Side UI
> *The client interface allows easy connection setup, server selection, real-time speed monitoring, and management of VPN settings.*

![Client Side UI Screenshot1](https://github.com/user-attachments/assets/a7bb0ceb-177f-458c-9939-2b2d13aac44c)
![Client Side UI Screenshot2](https://github.com/user-attachments/assets/f136bb25-3b18-49a1-82b2-d855d221f8eb)
![Client Side UI Screenshot3](https://github.com/user-attachments/assets/af6bf85c-39e9-444f-99ae-3e1f1c66acbb)
### 📸 Server Side UI
> *The server interface provides user management capabilities, allowing administrators to add, edit, or delete users and manage authentication settings easily.*

![Server Side UI Screenshot1](https://github.com/user-attachments/assets/8c57ff19-51d2-496b-b36d-37d081f2e6f3)
![Server Side UI Screenshot2](https://github.com/user-attachments/assets/57632a15-0561-4318-8551-2498348fa3d7)


