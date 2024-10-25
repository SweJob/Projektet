# Technical Specification

## Architecture Overview

### Core Components

#### 1. Service Layer
##### NetworkService Base Class
- **Purpose**: Provides thread management and lifecycle control
- **Key Features**:
  - Thread-safe operation
  - Graceful shutdown capability
  - Standardized command interface
  - Abstract methods requiring implementation:
    - `_run()`: Main service loop
    - `handle_command()`: Command processor

##### Type System
```python
CommandResponse = TypedDict('CommandResponse', {
    'status': str,          # 'success' or 'error'
    'message': Optional[str],  # Error message or None
    'data': Optional[Dict[str, Any]]  # Response payload
})

DeviceDict = TypedDict('DeviceDict', {
    'mac': str,
    'ip': str,
    'last_seen': float
})
```

#### 2. Service Controller
- **Thread Management**:
  - Each service runs in its own daemon thread
  - Controlled shutdown sequence
  - Resource cleanup handling

#### 3. Network Services

##### ARP Scanner
- **Scanning Method**: Active ARP requests using Scapy
- **Device Tracking**:
  - MAC address as primary key
  - Last seen timestamp for device aging
  - IP address tracking
- **Thread Safety**: Thread-safe device dictionary updates
- **Commands**:
  ```python
  # Get Devices
  Input: {"command": "get_devices", "args": {}}
  Output: {
      "status": "success",
      "data": {
          "devices": List[DeviceDict]
      }
  }
  
  # Set Scan Interval
  Input: {
      "command": "set_scan_interval",
      "args": {"interval": int}
  }
  Output: {
      "status": "success",
      "data": {"new_interval": int}
  }
  ```

##### DHCP Server (Planned)
- **Operational Modes**:
  1. Selective Response
  2. Pass-through
  3. Hybrid
- **MAC Filtering**:
  - Allow/deny lists
  - Pattern matching
  - Temporary exceptions

##### DNS Server (Planned)
- **Response Modes**:
  1. Pass-through
  2. Modified response
  3. Blocking
- **Record Types**: A, AAAA, MX, CNAME, TXT
- **Caching**: Local cache with TTL

## Threading Model

### Thread Isolation
```
ServiceController (Main Thread)
├── ARP Scanner Thread
├── DHCP Server Thread
└── DNS Server Thread
```

### Resource Sharing
- **Shared State**: Minimized through service isolation
- **Inter-Service Communication**: Via ServiceController
- **Lock Usage**: Fine-grained locking for shared resources

## Security Considerations

### Network Access
- **Privilege Requirements**: CAP_NET_RAW for ARP
- **Interface Binding**: Configurable network interface
- **Rate Limiting**: Configurable scan/response rates

### Data Safety
- **Input Validation**: All command arguments validated
- **Resource Limits**: Configurable memory/thread limits
- **Error Handling**: Graceful degradation

## Future Technical Considerations

### Encryption Layer (Planned)
- **Transport**: TLS 1.3
- **Payload**: AES-256-GCM
- **Key Management**: PKI with rotation

### Performance Optimizations
- **Scan Optimization**: ARP cache utilization
- **Response Caching**: DNS/DHCP response cache
- **Thread Pool**: Dynamic thread allocation

## Development Guidelines

### Code Style
- Type hints required
- Comprehensive docstrings
- PEP 8 compliance

### Testing Requirements
- Unit tests for all services
- Integration tests for service interaction
- Network mock framework for testing

### Error Handling
```python
class ServiceError(Exception):
    """Base class for service exceptions."""
    pass

class CommandError(ServiceError):
    """Invalid command or arguments."""
    pass

class NetworkError(ServiceError):
    """Network operation failure."""
    pass
```

## Monitoring and Logging (Planned)

### Metrics
- Active connections
- Response times
- Resource usage
- Error rates

### Logging
- Structured JSON logging
- Severity levels
- Audit trail
