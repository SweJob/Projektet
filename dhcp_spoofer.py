import socket
from scapy.all import *
from encrypted_comm import encrypt_message, decrypt_message, load_fernet_key

# Remote server settings
REMOTE_SERVER_IP = "your_remote_server_ip"
REMOTE_SERVER_PORT = 12345

allowed_hosts = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]  # Allowed MAC addresses
original_dhcp_server = "192.168.1.254"  # Original DHCP server

def is_allowed_host(mac_address: str) -> bool:
    """Check if the MAC address is in the allowed hosts list."""
    return mac_address in allowed_hosts

def forward_dhcp_request(pkt):
    """Forward DHCP request to the original DHCP server."""
    send(pkt, dst=original_dhcp_server)

def handle_dhcp(pkt):
    """Main DHCP packet handler with host-specific filtering."""
    if DHCP in pkt:
        mac_address = pkt[Ether].src
        if is_allowed_host(mac_address):
            dhcp_type = pkt[DHCP].options[0][1]

            if dhcp_type == 1:  # DHCP Discover
                handle_dhcp_discover(pkt)

            elif dhcp_type == 3:  # DHCP Request
                handle_dhcp_request(pkt)
        else:
            print(f"Forwarding request for {mac_address} to the original DHCP server")
            forward_dhcp_request(pkt)

def send_command_to_server(command: str):
    """Send an encrypted command to the remote server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((REMOTE_SERVER_IP, REMOTE_SERVER_PORT))

    encrypted_command = encrypt_message(command, FERNET_KEY)
    client_socket.send(encrypted_command.encode('utf-8'))

    encrypted_response = client_socket.recv(1024).decode('utf-8')
    response = decrypt_message(encrypted_response, FERNET_KEY)
    print(f"Server response: {response}")

    client_socket.close()

def start_dhcp_server():
    """Start the DHCP server and listen for DHCP packets."""
    print("DHCP Server is running...")
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp)

if __name__ == "__main__":
    # Example: Sending command to the server
    send_command_to_server("start_dhcp")

    # Starting the DHCP server
    start_dhcp_server()

