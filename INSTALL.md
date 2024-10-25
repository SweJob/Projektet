# Installation Guide

## Prerequisites

### System Requirements
- Python 3.9 or higher
- Linux/Unix environment (recommended)
- Root/Administrator privileges for network operations
- Git (for version control)

### Required System Packages
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install python3-dev python3-pip libpcap-dev

# RHEL/CentOS
sudo dnf install python3-devel python3-pip libpcap-devel

# macOS
brew install libpcap
```

## Installation Steps

### 1. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate
```

### 2. Install Python Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install scapy==2.5.0
pip install typing-extensions>=4.5.0
```

### 3. Verify Installation
```python
python3 -c "import scapy; print(scapy.__version__)"
```

### 4. Configure Permissions
```bash
# Linux: Allow non-root users to capture packets (optional)
sudo setcap cap_net_raw+ep $(which python3)

# Or run with sudo when needed
sudo python3 your_script.py
```

## Development Setup

### 1. Clone Repository
```bash
git clone <repository-url>
cd network-security-framework
```

### 2. Install Development Dependencies
```bash
pip install -r requirements-dev.txt
```

### 3. Configure Pre-commit Hooks
```bash
pre-commit install
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Error: Permission denied (raw socket access)
# Solution: Run with sudo or configure capabilities
sudo setcap cap_net_raw+ep $(which python3)
```

#### Scapy Import Error
```bash
# Error: ImportError: No module named scapy
# Solution: Install scapy in your virtual environment
pip install scapy
```

#### libpcap Not Found
```bash
# Error: Unable to find libpcap
# Solution: Install libpcap development package
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo dnf install libpcap-devel    # RHEL/CentOS
```

## Usage Verification

### Quick Test
```python
from network_services import ServiceController, ArpScanner

# Initialize controller
controller = ServiceController()

# Register ARP scanner
scanner = ArpScanner(network="192.168.1.0/24")
controller.register_service("arp_scanner", scanner)

# Start services
controller.start_all()

# Test command
response = controller.handle_command("arp_scanner", "get_devices", {})
print(response)
```

## Next Steps
1. Review the README.md for usage examples
2. Check the technical documentation for implementation details
3. Join the development discussion in Issues/Discord

## Support
- GitHub Issues: [Link to issues]
- Documentation: [Link to docs]
- Security Reports: security@yourdomain.com
