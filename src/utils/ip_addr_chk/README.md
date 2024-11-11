# ip_addr_chk.py - by Jonas "SweJob" Bergstedt
The ip_addr_chktools is a tool to check if an IP address is valid.
It supports command-line interface usage and can also be imported as a module
It defines an ip_type that can be used in argparse.

[Command line](#command-line)

## General overview
### Program structure
is_valid_ip - accepts a string, returns true if it's a valid ip address, and false if not
ip_type - accepts a string, returns string if valid IP address or raise an `argparse.ArgumentTypeError` if not validon. This is to be used as a type for argparse arguments.

### Usage
#### Command Line
To run the ip_addr_chk it needs the following information:
ip_address : a string that represents the IP adress to be checked

No default values for arguments.

##### Command line example

`python ip_addr_chk.py 192.168.0.1`  
Will return:  
`192.168.0.1 is a valid IP address`

`python ip_addr_chk.py 297.164.259.13`  
Will return:  
`usage: ip_addr_chk.py [-h] ip_address`  
`ip_addr_chk.py: error: argument ip_address: Invalid IP address: '297.164.259.13'`

#### Using Functions
Use is_valid_ip(string) to check if string is a valid IP Address. Returns True if valid, False if not.  
Use ip_type as type in argparse. Example:
``` python
parser.add_argument(
        'ip_address',
        type=ip_type,
        help="This is an ip address"
    )
```
