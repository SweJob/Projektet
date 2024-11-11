# C2 Server - by Jonas "SweJob" Bergstedt

The C2 server (c2_server.py) is a server to recieve incomming connection from the `../client/client_shell.py` and then be able to send commands **_to_** the client_shell and get information **_from_** the client.

[Command Line](#command_line)  
[Server commands](#server-commands)



## General overview
### Program structure
This is a multi-thread server with the aim to let different threads handle different areas of the server. The threads are defined in separet classes.
Threads will be listed in the order they start, as they, to some extent, are dependant on previous threads to work as intended. 

#### ServerUI
This Class and Thread are handling the ServerUI.

The user interface consists of three parts:  
1. The Output window  
   This window will recieve output from commandhandler, from functions and from client.
   It echoes the input commands with the prefix "Command: "  and replies from client are marked with < 
   As the UI "occupies" the screen, some errorcodes are displayed here as well, as a regular print would  disrupt the UI.

2. The Status window  
   This window will display the status of "continous" client functions (see documentation of client_shell for a more detailed explanation of different types of functions)  
   It will also display the status of the servers threads and sockets.

3. The Command prompt  
   A single line to input commands from the server. 
   A feature handled by the InputWithHistory class makes it possible to use up/down arrow keys to go back to an previous command and (edit it and then) run it again

#### OutputManager
This class and thread is handling output to the Output window
It pops the first (=oldest) string in the global output_list and sends it to the Output window and makes sure the window scrolls down as it gets new lines.

#### StatusManager
This class and thread get the status form the client (in the client_status_queue) and transform it into an csm (client status message)
It also read the global variable ssm (server status message)
Those 2 sets of data is combined to a text that is sent to the Status window at regular intervals

#### ServerConnectionManager
This class and thread Manages the 2 sockets that the server listens to and connections made from the client. This i have to admit is the most vital but also the messiest part of the code.
1. status_socket  
   Creates a blocking socket that listens for data from the client.
   Recieved data is decrypted with passwordbased encryption from crypto_tool.py (in utils folder) and then placed in the client_status_queue
   It resets if the client goes dwon and needs to reconnect.

2. command_socket
   Creates a Non-blocking socket that sends data to client and recives data from client
   All communciation is encrypted (with the same encryption as status_socket) 
   Tha data recieved from the client is preceeded with a length-word of 4 bytes to be sure that it gets the full message before trying to decrypt it.
   Then it's placed in the output_list with a prefix - "> "
   The data in the send_to_client_queue is encrypted before it's sent. Length is not calculated in this direction

#### CommandHandler
This class and thread is responsible for understanding the input recieved from command prompt
It checks if the command prefix:  
"s" or "server" [command] - pass command on to handle_server_command 
"c" or "client" [command] - pass command on to handle_client_command

handle_server_command handles locally run commands. See commands further down to se the complete list and their explention.
handle_client_command just passes the command on to the send_to_client_queue which is parsed by the command socket above and sent to the client.

### Usage
#### Command Line
To start the server with proper settings it needs this information:  
bind: an IP-address to bind the sockets to.  
s_port: a TCP port to listen for status_updates from client  
c_port: a TCP port to send commands to client and listen for replies from client
pw: a text that is the base for creating the encryption-key.

The default values are:
bind: 127.0.0.1  
s_port: 8001  
c_port: 8000
pw: a1B2c3D4e5F6g7H8!

command line:
`python c2_server.py [--bind 192.168.1.10] [--s_port 8001] [--c_port 8000][--pw MyPassword!]`  
to start sockets bound to the interface with ip 192.168.1.10 and en-/decrypting using MyPasssword! as base for encryption-key

* Tip: To find the interfaces on your device along with their associated IP addresses, you can run `python if_lister.py` located in `../client`

#### Server commands
Server commands are intiated with the keyword "server" or just "s" at the command prompt

| command     | arguments | help                                                             |
|-------------|-----------|------------------------------------------------------------------|
| help        | [command] | Displays the list of commands, or helt text of optional [command]|
| save_output | filename  | Append output (not history) to file                              |
| exit        |           | Shuts down the server in an orderly manner                       |

#### Client commands
Client commands are not defined in the server, but if noone messes to much with the client code, `c help` or `client help` woudl display a list of all the comamnds that the client are setup to run.  
For a command to be sent to the client entry starts with c or client. 

For more details look at the client_documentation

## Known issues
Sometimes when the client disconnects the connection does not reconnect until sending a command to client, for instance `c help` and after the error message received sending the command again. But most of the times it reconnects after a timeout of about 10 seconds.

During disconnection the server status message might be a bit unreliable. Have not pinpointed the exact situation when it happens.

I have tried to avoid threads running crazy and making sure there at least is some "wait" code in all paths inside all loops, but I might have missed some rare case.

If the UI looks strange, it usually redraws if you resize the terminal window in which it runs. This is usefull if an unhandled exception provides output that clutters the screen.
Usually the code will allow you to do a server exit even after such an event. Just resize, and type `server exit` [enter] in the command prompt line.

If code crashes (at least in windows) to shell the mouse will during some circumstances create escape-codes in the terminal. So far the only solution I have found is to either restart the c2_server and exit it properly (`s exit`) or restart the terminal.