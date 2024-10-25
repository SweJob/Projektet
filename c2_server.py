import socket
import threading
from encrypted_comm import encrypt_message, decrypt_message

# Settings for server
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345

# Configuration
dhcp_running = False
allowed_hosts = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]  # Allowed MAC addresses

def handle_client(client_socket):
    """Handles incoming commands from the DHCP client."""
    global dhcp_running, allowed_hosts
    while True:
        try:
            encrypted_data = client_socket.recv(1024).decode('utf-8')
            if not encrypted_data:
                break
            command = decrypt_message(encrypted_data)
            print(f"Received command: {command}")

            if command == "start_dhcp":
                dhcp_running = True
                response = "DHCP started"
            elif command == "stop_dhcp":
                dhcp_running = False
                response = "DHCP stopped"
            elif command.startswith("set_config"):
                new_config = command.split(" ")[1:]
                allowed_hosts = new_config  # Update allowed hosts
                response = f"Updated allowed hosts: {new_config}"
            else:
                response = "Unknown command"

            client_socket.send(encrypt_message(response).encode('utf-8'))

        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()

def start_server():
    """Starts the remote server to handle DHCP commands."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
