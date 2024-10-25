"""
Network Services Framework for Security Testing and Network Analysis

This module provides a framework for creating and managing network services
that can be used for security testing and network analysis. It includes
base classes for service management and implementations for specific
network protocols (ARP, DHCP, DNS).

Each service can run independently in its own thread and can be controlled
through a unified command interface. The framework is designed to be
extensible and maintainable, with clear separation of concerns.

Note: This framework is intended for educational purposes and authorized
security testing only.
"""

import threading
import scapy.all as scapy
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any, TypedDict, Union
import json
import socket
import ssl
import time
from abc import ABC, abstractmethod

class DeviceDict(TypedDict):
    """Type definition for device dictionary representation."""
    mac: str
    ip: str
    last_seen: float

class CommandResponse(TypedDict):
    """Type definition for command response dictionary."""
    status: str
    message: Optional[str]
    data: Optional[Dict[str, Any]]

@dataclass
class NetworkDevice:
    """
    Represents a device discovered on the network.
    
    Attributes:
        mac_address: The device's MAC address
        ip_address: The device's IP address
        last_seen: Timestamp of last detection (Unix timestamp)
    """
    mac_address: str
    ip_address: str
    last_seen: float

class NetworkService(ABC):
    """
    Abstract base class for all network services.
    
    This class provides the basic threading and lifecycle management that all
    network services should implement. Services inheriting from this class
    will be able to run in their own thread and respond to commands.
    """
    
    def __init__(self) -> None:
        """Initialize the network service with default state."""
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        
    def start(self) -> None:
        """
        Start the service in a new thread if it's not already running.
        
        The service runs as a daemon thread, meaning it will be terminated
        when the main program exits.
        """
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._run)
            self._thread.daemon = True
            self._thread.start()
            
    def stop(self) -> None:
        """
        Stop the service and wait for its thread to terminate.
        
        This method ensures clean shutdown of the service by waiting for
        the thread to complete its current operation.
        """
        self._running = False
        if self._thread:
            self._thread.join()
            
    @abstractmethod
    def _run(self) -> None:
        """
        Main service loop to be implemented by concrete services.
        
        This method should contain the main logic of the service and
        should periodically check self._running to determine if it
        should continue operation.
        """
        pass
    
    @abstractmethod
    def handle_command(self, command: str, args: Dict[str, Any]) -> CommandResponse:
        """
        Process a command received from the control server.
        
        Args:
            command: The command to execute
            args: Dictionary of arguments for the command
            
        Returns:
            CommandResponse: A dictionary containing the command's result
        """
        pass

class ArpScanner(NetworkService):
    """
    Service for performing ARP scans of the local network.
    
    This service periodically sends ARP requests to discover active hosts
    on the network and maintains a list of discovered devices with their
    MAC and IP addresses.
    """
    
    def __init__(self, network: str = "192.168.1.0/24") -> None:
        """
        Initialize the ARP scanner.
        
        Args:
            network: Network range to scan in CIDR notation
        """
        super().__init__()
        self.devices: Dict[str, NetworkDevice] = {}
        self._scan_interval: int = 60
        self._network: str = network
        
    def _run(self) -> None:
        """
        Main scanning loop that performs periodic ARP scans.
        
        The scan interval can be modified at runtime through the
        set_scan_interval command.
        """
        while self._running:
            self._scan_network()
            time.sleep(self._scan_interval)
    
    def _scan_network(self) -> None:
        """
        Perform a single ARP scan of the network.
        
        Sends ARP requests to all addresses in the configured network range
        and updates the devices dictionary with any responses received.
        """
        arp = scapy.ARP(pdst=self._network)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            
            current_time = time.time()
            for sent, received in result:
                device = NetworkDevice(
                    mac_address=received.hwsrc,
                    ip_address=received.psrc,
                    last_seen=current_time
                )
                self.devices[received.hwsrc] = device
                
        except Exception as e:
            print(f"Error during ARP scan: {e}")
    
    def handle_command(self, command: str, args: Dict[str, Any]) -> CommandResponse:
        """
        Process commands for the ARP scanner.
        
        Supported commands:
            - get_devices: Returns list of all discovered devices
            - set_scan_interval: Changes the scanning interval
            
        Args:
            command: Command to execute
            args: Arguments for the command
            
        Returns:
            CommandResponse containing the result of the command
        """
        if command == "get_devices":
            return {
                "status": "success",
                "message": None,
                "data": {
                    "devices": [
                        {
                            "mac": dev.mac_address,
                            "ip": dev.ip_address,
                            "last_seen": dev.last_seen
                        } for dev in self.devices.values()
                    ]
                }
            }
        elif command == "set_scan_interval":
            if "interval" in args:
                self._scan_interval = args["interval"]
                return {
                    "status": "success",
                    "message": None,
                    "data": {"new_interval": self._scan_interval}
                }
        return {
            "status": "error",
            "message": f"Unknown command: {command}",
            "data": None
        }

class ServiceController:
    """
    Central manager for all network services.
    
    This class maintains a registry of all active services and provides
    a unified interface for starting, stopping, and sending commands to
    individual services.
    """
    
    def __init__(self) -> None:
        """Initialize the service controller with an empty service registry."""
        self.services: Dict[str, NetworkService] = {}
        
    def register_service(self, name: str, service: NetworkService) -> None:
        """
        Register a new service with the controller.
        
        Args:
            name: Unique identifier for the service
            service: Instance of NetworkService to register
        """
        self.services[name] = service
        
    def start_all(self) -> None:
        """Start all registered services."""
        for service in self.services.values():
            service.start()
            
    def stop_all(self) -> None:
        """Stop all registered services."""
        for service in self.services.values():
            service.stop()
            
    def handle_command(self, service_name: str, command: str, args: Dict[str, Any]) -> CommandResponse:
        """
        Route a command to the appropriate service.
        
        Args:
            service_name: Name of the service to receive the command
            command: Command to execute
            args: Arguments for the command
            
        Returns:
            CommandResponse containing the result of the command
        """
        if service_name in self.services:
            return self.services[service_name].handle_command(command, args)
        return {
            "status": "error",
            "message": f"Unknown service: {service_name}",
            "data": None
        }