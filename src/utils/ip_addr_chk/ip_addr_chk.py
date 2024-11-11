import ipaddress
import argparse

def is_valid_ip(ip_str):
    try:
        # Try creating an IP address object. This will raise a ValueError if invalid.
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False    

def ip_type(ip_str):
    if is_valid_ip(ip_str):
        return ip_str
    else:
        raise argparse.ArgumentTypeError(f"Invalid IP address: '{ip_str}'")

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for configuring the client connection.

    Returns:
        argparse.Namespace: An object containing the parsed arguments:
            address : an adress to check
    """
    parser = argparse.ArgumentParser(description="Client for connecting to the server.")

    parser.add_argument(
        'ip_address',
        type=ip_type,
        default='127.0.0.1',
        help='The server IP address. Default is 127.0.0.1.'
    )
    args = parser.parse_args()
    return args

def main():
    try:
        args = parse_arguments()
    except argparse.ArgumentTypeError as e:
        print("{e}")
        exit(1)
    if is_valid_ip(args.ip_address):
        print(f"{args.ip_address} is a valid IP address")
        
if __name__ == "__main__":
    main()