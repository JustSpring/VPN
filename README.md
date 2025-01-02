# Custom VPN Solution (Work in Progress)
## Overview
This project is a custom VPN (Virtual Private Network) solution developed using Python, with a focus on secure communication and encryption techniques. The VPN implements key features such as SSL/TLS for secure communication, user authentication with multi-factor security (username/password, TOTP, and certificates), and machine-specific certificate generation. The solution is being designed to provide secure, encrypted tunnels for data traffic while ensuring robust authentication and encryption.
## Planned Features
* Multi-protocol Support: Expanding the local proxy to support a variety of protocols beyond HTTP/S, including FTP, DNS, and more.
* Multi-hop Routing: Future versions will allow users to route their traffic through multiple VPN servers, increasing anonymity and security.
* Advanced Encryption: Additional encryption protocols and customization options will be added to enhance security and flexibility.
* Traffic Shaping and Monitoring: Features for monitoring and shaping network traffic will be included, making the VPN adaptable for various use cases (e.g., gaming, streaming, secure communication).
* Kill Switch (Planned Feature): The VPN will incorporate a kill switch mechanism, ensuring that if the VPN connection is interrupted, all network traffic will be blocked to prevent any potential data leaks. This feature will safeguard against unencrypted traffic being transmitted outside the VPN in case of unexpected disconnections.
* Remote Access Support: The VPN will be able to get accessed from computers outside the local network (via the internet).
## Current Status
This VPN solution is still under development. Features such as multi-hop VPN routing, advanced traffic handling, and optimizations for different network conditions are planned but not yet implemented. The current version focuses on the core functionality of secure connections, HTTP/S proxy support, and basic certificate-based authentication.
