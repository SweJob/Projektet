"""
A simple module for sniffing arp hosts on the provided interface
Use as a command line tool or use the functions from other modules
"""
import time
import sys
import os
import threading
import argparse
import signal
from typing import List
import scapy.all as scapy
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from utils.ip_addr_chk.ip_addr_chk import ip_type

def get_interface_by_ip(ip_address: str) -> str | None:
    """
    Returns the network interface name for a given IP address.

    Args:
        ip_address (str): The IP address to search for in the network interfaces.

    Returns:
        str | None: The network interface name if a match is found, 
                    or None if no matching interface is found.
    """
    for iface in scapy.conf.ifaces:
        if scapy.conf.ifaces[iface].ip == ip_address:
            return iface
    # Return None if no matching interface is found
    return None

def arp_sniffer(
    stop_event,
    reply_list: List[str],
    reply_lock,
    host_list,
    bind_address: str,
    interval: int = 5,
    duration = None
) -> None:
    """
    Sniffs for ARP packets on the network, storing MAC, IP, and hostname details.

    Args:
        stop_event (Event): Event to signal stopping the sniffer.
        reply_list (list[str]): The list to append sniffing results to.
        reply_lock (Lock): A threading lock to ensure thread-safe access to reply_list.
        host_list (dict): A dictionary storing host details, with MAC as the key.
        bind_address (str): The IP address to bind the sniffer to.
        interval (int, optional): Interval between sniffing iterations in seconds. Default is 5.
        duration (int, optional): Duration to sniff in seconds. If None, sniffs indefinitely.

    Returns:
        None
    """
    try:
        interface = get_interface_by_ip(bind_address)
    except TypeError:
        with reply_lock:
            reply_list.append("You need to provide a valid IP address to bind to.")
            stop_event.set()
        return

    if not interface:
        with reply_lock:
            reply_list.append(f"arp_sniffer Error: No interface found for IP: {bind_address}")
            stop_event.set()
        return

    def arp_packet_handler(packet: scapy.packet) -> None:
        """Handles incoming ARP packets for sniffing."""
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 1:  # ARP request
            mac = packet[scapy.ARP].hwsrc
            ip = packet[scapy.ARP].psrc
            hostname = None  # Placeholder for hostname resolution if implemented later

            # Initialize MAC address entry if it doesn't exist
            if mac not in host_list:
                host_list[mac] = {"IPs": []}
            # Add IP address only if it's not already present
            if ip not in host_list[mac]["IPs"]:
                host_list[mac]["IPs"].append(ip)
                # Append message to response_list instead of printing
                with reply_lock:
                    reply_list.append(f"Detected: MAC={mac}, IP={ip}, Hostname={hostname}")

    # Set end time if duration is specified
    end_time = time.time() + (duration if duration else float('inf'))
    while (not stop_event.is_set()) and (time.time() < end_time):
        try:
            scapy.sniff(
                iface=interface,
                prn=arp_packet_handler,
                filter="arp",
                timeout=interval  # Timeout ensures periodic stop_event checks
            )
        except scapy.Scapy_Exception as e:
            with reply_lock:
                reply_list.append(f"Error sniffing on {interface}: {e}")
            time.sleep(0.5)
            stop_event.set()

    with reply_lock:
        reply_list.append("Stopping arp_sniffer")
    time.sleep(0.5)
    stop_event.set()


def parse_arguments():
    """
    Parses command-line arguments and returns them as a Namespace object.
    
    Args:
        None
        
    Returns:
        Namespace: Parsed arguments, including 'ip_address', 'duration', and 'interval'.
    """
    parser = argparse.ArgumentParser(description='ARPSniffer command-line tool.')

    parser.add_argument(
        'ip_address',
        type=ip_type,        
        help='The IP address to bind the sniffer to.'
    )

    parser.add_argument(
        '-d', '--duration',
        type=int,
        help='Duration to sniff in seconds.'
    )

    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Interval between sniffing iterations in seconds.'
    )

    return parser.parse_args()

def print_output(
    reply_list: List[str],
    reply_lock,
    stop_event
) -> None:
    """
    Prints the contents of the reply list until the stop_event is set.

    Args:
        reply_list (List[str]): A list containing the messages to be printed.
        reply_lock (Lock): A lock to ensure thread-safe access to the reply list.
        stop_event (Event): A threading event that signals when to stop the printing loop.

    Returns:
        None
    """
    while not stop_event.is_set():
        with reply_lock:
            while reply_list:
                print(reply_list.pop(0))
        time.sleep(0.3)  # Sleep to prevent busy waiting
    print("Stops printing thread")

def signal_handler(
    sig,
    frame,
    stop_event
) -> None:
    """
    Signal handler to stop sniffing when Ctrl+C (SIGINT) is pressed.
    
    Args:
        sig (int): The signal number. Typically SIGINT (Ctrl+C).
        frame (signal.FrameType): The current stack frame when the signal is received.
        stop_event (Event): A threading event used to signal threads to stop.
    
    Returns:
        None
    """
    if sig == signal.SIGINT:
        print("Ctrl+C was detected")
    print("Stopping ARP Sniffer and print thread...")
    stop_event.set()  # Signal all threads to stop

def main() -> None:
    """
    Runs the ARP Sniffer as a Command Line tool.

    This function:
    - Parses command-line arguments
    - Initializes and starts the ARP sniffer and print threads
    - Registers a signal handler to handle SIGINT (Ctrl+C)
    - Waits for threads to finish and prints the discovered hosts.

    Returns:
        None
    """
    # Parse arguments
    args = parse_arguments()

    # External variables for thread-safe access and thread control
    stop_event = threading.Event()
    response_list = []
    response_lock = threading.Lock()
    host_list = {}

    # Start the ARP sniffer
    sniff_thread = threading.Thread(
        target=arp_sniffer,
        args=(
            stop_event,
            response_list,
            response_lock,
            host_list,
            args.ip_address,
            args.interval,
            args.duration
        ),
        daemon=True
    )
    sniff_thread.start()

    # Start the printing thread immediately after the sniffer
    print_thread = threading.Thread(
        target=print_output,
        args=(response_list, response_lock, stop_event),
        daemon=True
    )
    print_thread.start()

    # Register the signal handler
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, stop_event))

    # Main loop waits for the stop_event to be set
    while not stop_event.is_set():
        time.sleep(0.1)

    # Join threads before exiting
    sniff_thread.join()
    print_thread.join()

    # Printing a formatted list of discovered hosts
    print("\nDiscovered ARP hosts:")
    for mac, data in host_list.items():
        print(f"MAC: {mac}")
        print("  IPs:")
        for ip in data["IPs"]:
            print(f"       {ip}")
        print("-" * 22)
    print("\nExiting ARP Sniffer...")


if __name__ == '__main__':
    main()
