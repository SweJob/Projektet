"""
DHCP Server implementation for network security testing framework.
Provides capabilities for DHCP request interception, filtering, and response modification.
"""

import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from typing import Dict, Set, Optional, List, Tuple
import threading
import time
from dataclasses import dataclass
from .network_service import NetworkService, CommandResponse

@dataclass
class DhcpLease:
    """Represents a DHCP lease allocation."""
    mac_address: str
    ip_address: str
    lease_time: int
    subnet_mask: str
    gateway: str
    dns_servers: List[str]
    timestamp: float

class DhcpConfig:
    """Configuration for DHCP server operation."""
    def __init__(self) -> None:
        self.allowed_macs: Set[str] = set()
        self.interface: str = "eth0"
        self.server_ip: str = "192.168.1.1"
        self.subnet_mask: str = "255.255.255.0"
        self.gateway: str = "192.168.1.1"
        self.dns_servers: List[str] = ["8.8.8.8", "8.8.4.4"]
        self.lease_time: int = 3600  # 1 hour
        self.legitimate_server: Optional[str] = None

class DhcpServer(NetworkService):
    """
    DHCP Server implementation with MAC filtering and legitimate server passthrough.
    
    Features:
    - MAC address filtering for DHCP responses
    - Legitimate server query capability
    - Response manipulation
    - Lease tracking
    """
    
    def __init__(self) -> None:
        """Initialize DHCP server with default configuration."""
        super().__init__()
        self.config = DhcpConfig()
        self.leases: Dict[str, DhcpLease] = {}
        self._socket: Optional[scapy.SuperSocket] = None
        self._lease_lock = threading.Lock()
        
    def _setup_socket(self) -> None:
        """Set up the raw socket for DHCP traffic."""
        try:
            self._socket = scapy.conf.L2socket(iface=self.config.interface)
        except Exception as e:
            raise RuntimeError(f"Failed to create DHCP socket: {e}")

    def _run(self) -> None:
        """Main service loop - listen for and handle DHCP packets."""
        self._setup_socket()
        if not self._socket:
            return

        while self._running:
            try:
                packet = self._socket.sniff(count=1, filter="udp and (port 67 or port 68)")[0]
                if DHCP in packet:
                    self._handle_dhcp_packet(packet)
            except Exception as e:
                print(f"Error processing DHCP packet: {e}")

    def _handle_dhcp_packet(self, packet: scapy.Packet) -> None:
        """
        Process incoming DHCP packets.
        
        Args:
            packet: Received DHCP packet
        """
        if not DHCP in packet:
            return

        dhcp_types = {
            1: "DISCOVER",
            2: "OFFER",
            3: "REQUEST",
            4: "DECLINE",
            5: "ACK",
            6: "NAK",
            7: "RELEASE",
            8: "INFORM"
        }
        
        mac_address = packet[Ether].src
        message_type = packet[DHCP].options[0][1]
        
        # Check if we should handle this MAC address
        if mac_address not in self.config.allowed_macs:
            if self.config.legitimate_server:
                self._forward_to_legitimate_server(packet)
            return
            
        if message_type == 1:  # DISCOVER
            self._handle_discover(packet)
        elif message_type == 3:  # REQUEST
            self._handle_request(packet)

    def _handle_discover(self, packet: scapy.Packet) -> None:
        """Handle DHCP DISCOVER messages."""
        mac_address = packet[Ether].src
        
        # Generate response
        offer = (
            Ether(dst=mac_address)/
            IP(src=self.config.server_ip, dst="255.255.255.255")/
            UDP(sport=67, dport=68)/
            BOOTP(
                op=2,
                yiaddr=self._get_available_ip(),
                siaddr=self.config.server_ip,
                chaddr=bytes.fromhex(mac_address.replace(':', '')),
                xid=packet[BOOTP].xid
            )/
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", self.config.server_ip),
                ("lease_time", self.config.lease_time),
                ("subnet_mask", self.config.subnet_mask),
                ("router", self.config.gateway),
                ("name_server", self.config.dns_servers),
                "end"
            ])
        )
        
        if self._socket:
            self._socket.send(offer)

    def _handle_request(self, packet: scapy.Packet) -> None:
        """Handle DHCP REQUEST messages."""
        mac_address = packet[Ether].src
        requested_ip = None
        
        # Extract requested IP
        for option in packet[DHCP].options:
            if option[0] == "requested_addr":
                requested_ip = option[1]
                break
        
        if not requested_ip:
            return
            
        # Create and send ACK
        ack = (
            Ether(dst=mac_address)/
            IP(src=self.config.server_ip, dst="255.255.255.255")/
            UDP(sport=67, dport=68)/
            BOOTP(
                op=2,
                yiaddr=requested_ip,
                siaddr=self.config.server_ip,
                chaddr=bytes.fromhex(mac_address.replace(':', '')),
                xid=packet[BOOTP].xid
            )/
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", self.config.server_ip),
                ("lease_time", self.config.lease_time),
                ("subnet_mask", self.config.subnet_mask),
                ("router", self.config.gateway),
                ("name_server", self.config.dns_servers),
                "end"
            ])
        )
        
        if self._socket:
            self._socket.send(ack)
            
        # Record lease
        with self._lease_lock:
            self.leases[mac_address] = DhcpLease(
                mac_address=mac_address,
                ip_address=requested_ip,
                lease_time=self.config.lease_time,
                subnet_mask=self.config.subnet_mask,
                gateway=self.config.gateway,
                dns_servers=self.config.dns_servers.copy(),
                timestamp=time.time()
            )

    def _forward_to_legitimate_server(self, packet: scapy.Packet) -> None:
        """Forward DHCP packet to legitimate server if configured."""
        if not self.config.legitimate_server or not self._socket:
            return
            
        # Modify packet for forwarding
        packet[IP].src = self.config.server_ip
        packet[IP].dst = self.config.legitimate_server
        
        self._socket.send(packet)

    def _get_available_ip(self) -> str:
        """Get next available IP address from pool."""
        # Simple implementation - should be enhanced for production
        used_ips = {lease.ip_address for lease in self.leases.values()}
        base_ip = "192.168.1."
        
        for i in range(100, 200):  # Use 192.168.1.100-199 as DHCP pool
            ip = base_ip + str(i)
            if ip not in used_ips:
                return ip
                
        raise RuntimeError("No available IP addresses in pool")

    def handle_command(self, command: str, args: Dict[str, str]) -> CommandResponse:
        """
        Handle commands from the control server.
        
        Supported commands:
        - add_allowed_mac: Add MAC to allowed list
        - remove_allowed_mac: Remove MAC from allowed list
        - get_leases: Get current DHCP leases
        - set_legitimate_server: Set legitimate server IP
        """
        if command == "add_allowed_mac":
            if "mac" in args:
                self.config.allowed_macs.add(args["mac"])
                return {
                    "status": "success",
                    "message": None,
                    "data": {"allowed_macs": list(self.config.allowed_macs)}
                }
                
        elif command == "remove_allowed_mac":
            if "mac" in args:
                self.config.allowed_macs.discard(args["mac"])
                return {
                    "status": "success",
                    "message": None,
                    "data": {"allowed_macs": list(self.config.allowed_macs)}
                }
                
        elif command == "get_leases":
            return {
                "status": "success",
                "message": None,
                "data": {
                    "leases": [
                        {
                            "mac": lease.mac_address,
                            "ip": lease.ip_address,
                            "expires": lease.timestamp + lease.lease_time
                        } for lease in self.leases.values()
                    ]
                }
            }
                
        elif command == "set_legitimate_server":
            if "server_ip" in args:
                self.config.legitimate_server = args["server_ip"]
                return {
                    "status": "success",
                    "message": None,
                    "data": {"legitimate_server": self.config.legitimate_server}
                }

        return {
            "status": "error",
            "message": f"Unknown command: {command}",
            "data": None
        }