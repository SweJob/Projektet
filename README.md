# Network Security Testing Framework

## Project Overview
An educational network security testing framework implemented in Python, designed for learning about network protocols and security concepts. This framework provides a modular system for running and controlling various network services (ARP, DHCP, DNS) through a centralized control interface.

## Educational Purpose
This project is designed for learning about:
- Network protocol implementations
- Threading and concurrent programming
- Command and control architectures
- Network security concepts

## Current Implementation

### Core Framework
- `NetworkService`: Abstract base class providing threading and lifecycle management
- `ServiceController`: Central manager for all network services
- Type-safe command interface with standardized responses
- Thread-safe service management

### Implemented Services
#### ARP Scanner
- Periodic network scanning capability
- Device tracking with MAC and IP addresses
- Configurable scan intervals
- Command interface for retrieving device information

## Planned Features

### DHCP Server
- Selective response based on MAC address filtering
- Configuration via control server
- Ability to:
  - Answer specific DHCP requests
  - Forward other requests to legitimate server
  - Monitor DHCP traffic

### DNS Server
- Pass-through functionality for normal operation
- Selective response modification capability
- Configuration for target domains
- Response monitoring and logging

### Control Server
- Encrypted communication channel
- Command interface for:
  - Running functions with arguments
  - Getting/setting service properties
  - Managing service lifecycle
- Activity logging

## Architecture

### Service Structure
```
NetworkService (Abstract Base)
├── ArpScanner
├── DhcpServer (Planned)
└── DnsServer (Planned)
```

### Type Definitions
```python
CommandResponse = {
    "status": str,
    "message": Optional[str],
    "data": Optional[Dict[str, Any]]
}

DeviceDict = {
    "mac": str,
    "ip": str,
    "last_seen": float
}
```

## Usage Examples

### Starting the ARP Scanner
```python
from network_services import ServiceController, ArpScanner

# Initialize controller
controller = ServiceController()

# Register and start ARP scanner
scanner = ArpScanner(network="192.168.1.0/24")
controller.register_service("arp_scanner", scanner)
controller.start_all()

# Get discovered devices
response = controller.handle_command(
    "arp_scanner", 
    "get_devices",
    {}
)
```

## Development Status
- [x] Core framework implementation
- [x] ARP Scanner service
- [ ] DHCP Server implementation
- [ ] DNS Server implementation
- [ ] Control Server implementation
- [ ] Encryption layer
- [ ] Full documentation
- [ ] Testing suite

## Security Considerations
This framework is designed for educational purposes and authorized testing only. Features include:
- Logging of all activities
- Configurable service restrictions
- Safe defaults for all services
- Documentation of security implications

## Next Steps
1. Implement DHCP server component
2. Add encryption for control server communication
3. Implement DNS service
4. Add comprehensive testing
5. Enhance documentation with usage examples

## Project Requirements
To run this project, you need:
- Python 3.9+
- Scapy library
- (Additional requirements to be added as services are implemented)

## Note
This framework is intended for educational purposes and authorized security testing only. Always ensure you have proper authorization before conducting any network testing or scanning activities.
