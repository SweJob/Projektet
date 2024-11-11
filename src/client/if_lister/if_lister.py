"""
This module provides functionality to list all available network interfaces on the host machine, 
including their IP addresses. The network interfaces are retrieved using the `psutil` library 
and filtered to include only IPv4 addresses.

Functions:
    list_network_interfaces: Retrieves all network interfaces and their IPv4 addresses.
    list_ifs: Thread-safe function to append network interface information to a given list.
    main: The main entry point of the script that calls the function to list network interfaces 
          and prints the results.

Usage:
    This module can be executed as a standalone script to print out the network interfaces of the 
    host machine, or it can be imported into other scripts where network interface information 
    is required.
    It's designed to be used by the FunctionManager class in client_shell
"""

import socket
import threading
from typing import List, Dict
import psutil

def list_network_interfaces() -> List[Dict[str, str]]:
    """
    List all network interfaces available on the host, including their IP addresses.
    
    Args:
        None
    
    Returns:
        List[Dict[str, str]]: A list of dict containing interface names and their IP addresses.
    """
    interfaces_info = []
    try:
        interfaces = psutil.net_if_addrs()

        for interface_name, addresses in interfaces.items():
            for address in addresses:
                # Filter for IPv4 addresses; use socket.AF_INET6 for IPv6 if needed
                if address.family == socket.AF_INET:
                    interfaces_info.append(f"{interface_name} : {address.address}")

        return interfaces_info
    except psutil.Error as e:
        return [f"Error listing interfaces {e}",]

def list_ifs(reply_list: List[str], reply_lock: threading.Lock) -> None:
    """
    Returns all network interfaces to reply_list in a thread-safe manner.
    
    Args:
        reply_list (List[str]): The list to append interface information.
        reply_lock (threading.Lock): A lock to ensure thread-safe access to reply_list.
    
    Returns:
        None
    """
    with reply_lock:
        reply_list.extend(list_network_interfaces())

def main() -> None:
    """
    Main function to initialize and call the network interface listing process.
    
    Args:
        None
    
    Returns:
        None
    """
    response_list = []
    response_lock = threading.Lock()
    list_ifs(response_list, response_lock)

    for response in response_list:
        print(response)

if __name__ == "__main__":
    main()
