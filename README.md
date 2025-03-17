# Custom VPN Solution (Work in Progress)
## Overview
This project is a custom VPN (Virtual Private Network) solution developed using Python, with a focus on secure communication and encryption techniques. The VPN implements key features such as SSL/TLS for secure communication, user authentication with multi-factor security (username/password, TOTP, and certificates), and machine-specific certificate generation. The solution is designed to provide secure, encrypted tunnels for data traffic while ensuring robust authentication and encryption.
## Key Features
* SSL/TLS Encryption: Secure communication between clients and servers.
* Multi-Factor Authentication: Combines username/password, TOTP, and certificates for robust security.
* Machine-Specific Certificates: Ensures that only authenticated devices can connect.
* FTP Support: Added functionality for handling FTP traffic securely.
* Client-Side UI: A user-friendly interface that allows clients to easily configure and manage their VPN connection.
* Server Selection: Clients can choose which server to connect to, providing flexibility for optimized performance or regional access.
* Real-Time Speed Monitoring: Users can now see the speed of data transfer in real time.
* Automatic Registry Modification: The VPN automatically updates the system registry to redirect traffic through the local proxy IP and restores the original settings when the connection ends.
## Planned Features
* Multi-Protocol Support: Expanding the local proxy to support a variety of protocols beyond HTTP/S, including DNS and more.
* Multi-Hop Routing: Future versions will allow users to route their traffic through multiple VPN servers, increasing anonymity and security.
* Advanced Encryption: Additional encryption protocols and customization options to enhance security and flexibility.
* Traffic Shaping and Monitoring: Features for monitoring and shaping network traffic to adapt for various use cases (e.g., gaming, streaming, secure communication).
* Kill Switch: Ensures that if the VPN connection is interrupted, all network traffic is blocked to prevent data leaks.
* Remote Access Support: The VPN will be accessible from computers outside the local network via the internet.
## Current Status
The VPN solution is actively under development. The current version includes core functionalities such as secure connections, HTTP/S proxy support, FTP support, certificate-based authentication, and a UI for client-side management. Users can now select their desired server, adding flexibility to the VPN's operation. Additionally, real-time speed monitoring has been implemented, allowing users to track their data transfer speeds, and the VPN now automatically modifies the system registry to redirect traffic through the local proxy IP, restoring it to its original state upon disconnection. Advanced features like multi-hop routing, traffic shaping, and kill switch functionality are planned for future iterations.
