# Client Shell - by Jonas "SweJob" Bergstedt

The Client shell (client_shell.py) is a client software that is set up to run in the background and connect to the c2_server `../server/c2_server.py`. It will periodically send status updates to the server and continuously listen for commands **_from_** the server, run the command locally and pass responses back **_to_** the server.  
[Command line](#command-line)  
[List of functions](#client-commands)


## General overview
### Program structure
This is a multi-thread code that I have tried to make modular, to make it fairly easy to add new functionality. A concept that I have tried to incorporate in all the code is the idea to avoid producing any output on the local screen, to make it as "stealthy" as possible. All output is sent to the server (in an encrypted form)

There are 2 main classes in the code:

#### FunctionManager
This class contains:  
a dictionary of the functions to be run by commands from the server,   
functions to start and stop other client functions  
functions and an internal function to get the status of the functions.  
It also contain a basic set of functions to be run from server.  

##### Dictionary
This is is a dictionary of all the functions and code to run them, and in the case of being a "continous" function, set a stop event to make it exit any loops.   
The idea is that it can be extended with new functions.
The dictionary looks like this (a part of it):
```python
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
    'fnargs': (arp_hosts,),
    'stop_event': threading.Event(),
    'help': "Sniffs ARP packets continuously until stopped. \n" + " "*27 + 
            "Args: [req] bind_address:str [opt] interval:float, duration:float"
},
'get_hosts': {
    'type': 'one-time',
    'start_func': self.get_arp_hosts,
    'fnargs': (arp_hosts,),
    'help': "Returns the discovered hosts"
},
```
The keys ("help", "set_update_interval", "arp_sniffer") is the internal names of the functions. These are what you send to the client to run a specific function.

* type:
  * "one-time":
    * Typically a function with a straightforward approach. 
    * It runs with no long or infinite loops, does what it should and then stops.
    * These functions do not have a status value, does not keep a thread value, and do not have a stop event.
  * "continuous":
    * A function that needs the ability to be stopped from the outside.
    * It runs either for a defined time (possibly set by a timeout argument or so) or in an indefinate loop
    * It has a status
* status:
  * Only used by continuous functions
  * Is set to "Running" when the function is started and to "Stopped" when the function stops.
* thread:
  * Only used by continuous functions
  * When the thread is created it is saved here for reference
* start_func:
  * The actual function that is run. 
  * This does not have to be the same name as the key for this dictionary entry. 
  * Defined as:
    * somewhere in the class (self.function_name) 
    * somewhere in the rest of the code ([object].function_name)
    * in an imported module (module.function_name)
* fnargs:
  * External variables that the function stores information in, shared with other functions
  * Example: The `arp_sniffer` scans for arp hosts. The found hosts are sent to the `response_list` that is passed to the server for output. But it is also passed to the host_list. The `get_hosts` function reads this list and sends the contents in a formatted manner to the server for output. In this way you see the results on the server as they are found, but they are also stored for later reference.
* stop_event:
  * only used by continuous functions
  * a `threading.Event` that is set by the `stop_function`
  * this is passed as the first argument to the continuous functions. It should be handled by the function to stop any long or eternal loops and exit the function
* help:
  * Should be included for all functions, even if just an empty string
  * Help text to guide the user on how to use the function

##### start_function
This function is called from the handle_command, that parses the command that is recieved from the server.
arguments passed to this function is the command and the arguments that is sent from the server. (read more below about how the handle_command parses the input)  
All functions that is to be used at least need to accept the response_list and the response_lock (`threading.Lock`). "Continuous" functions also need accept the stop_event (`threading.Event`) as their first argument.  
examples of the two types:  
* one-time:  
    minimal example:
    `def get_os(self, reply_list, reply_lock)`  
    `self` - it's a part of the FunctionManager class  
    `reply_list` - externally defined `list` that the function stores it output and error messages in.  
    `reply_lock` - externally defined `threading.Lock` used in function to make writing to reply_list threadsafe.
* continous:
  slightly complex example:  
    `def arp_sniffer(
    stop_event: threading.Event,
    reply_list: List[str],
    reply_lock: threading.Lock,
    host_list: dict,
    bind_address: str,
    interval: int = 5,
    duration: int = None)`  
    `stop_event` - threading.Event - externally defined threading.Lock. Used to signal stop to the thread from running. First required argument in all continuous functions.  
    `reply_list` - externally defined list that the function stores it output and error messages in. Second required argument in all continuous functions.  
    `reply_lock` - externally defined threading. Lock used in function to make writing to reply_list threadsafe. Third required argument in all continuous functions.  
    `host_list` - in this case a fnarg. The host_list is defined in the client_shell.py and is used to store a list of hosts that the sniffer finds. If any fnargs, they should come as fourth (and onwards) argument(s).  
    `bind_address` - argument that needs to be passed at command prompt in server  
    `interval` - optional argument that can be passed from server  
    `duration` - optional argument that can be passed from server  
    All arguments that is passed from the server should come last.

All functions run in their own thread
Threads are started in a wrapper to handle exceptions, making them locally stealth and passing output to the response_list 

##### stop_function
The `stop_function` is a one-time function by it self.
It uses teh external `reply_list` and `reply_lock` as arguments to handle any output.
From command you provide the name of the function to stop.
The function changes the status value in the dictionary and  sets the stop_event flag for that function

#### ControlClient
This class contains the base treads that starts everything else:  
`status_thread` and `command_thread`

##### command_thread
Listens for data from the server and passes them on to the handle_command. 
Sends the contents if response_list to the server.
All communciation is encrypted/decrypted with the provided password.

##### status_thread
Monitors the status of the running functions and sends it to the server. Encrypted with the password.

##### handle_command
parses received commmands into a command and [optionally] args.
This is then passed as arguments to `start_function`

### Usage
#### Command Line
To start `client_shell` with the proper settings, it requires the following information:  
server: IP address to connect to
s_port: TCP port to send status_updates to the server
c_port: TCP port to listen for commands from server and send replies to server
pw: a text that is the base for creating the encryption-key

The default values are:  
server: 127.0.0.1  
s_port: 8001  
c_port: 8000
pw: a1B2c3D4e5F6g7H8!

command line example:  
`python client_shell.py [--server 192.168.1.10] [--s_port 8001] [--c_port 8000] [-pw MyPassword!]`  
This connects to server with ip 192.168.1.10 and en-/decrypting using MyPasssword! as base for encryption-key

#### Client commands
Client commands are defined by the `FunctionManager.functions` dictionary.
Functions could relatively easily be added and removed.
This functions are run by the startfunction when handle_command calls it with function name and (if any) needed arguments

| function            | arguments | help |
|---------------------|-----------|------------------------------------------------|
| help                |           | list of valid commands to run on the client |
| set_update_interval | time      | interval for sending status updates in seconds |
| arp_sniffer         |bind_address,  [interval=5][duration=None] | Sniffs for MAC-adresses from interface with bind_address. <br> interval is pause between sniffs. <br> duration is time to keep sniffing.<br>(If None it sniffs until interrupted).<br>Replies are sent to Output window.<br>Status of function is seen in Status window |
| get_hosts           |           | formatted list of discovered MAC-addresses and their IP's in Output window |
| if_list             |           | list of the clients interfaces and their IP's in Output window |
| get_os              |           | display what os the client runs on in the Output window |
| run_os              | command<br> [args] | runs command wiht optional args.<br>Output from command is displayed in  Output window |
| stop                | function  | stops function if it's continuous and is running |

## Known issues
There were some issues around the output from run os, that stemmed from  which codepage the stdout in os was using.
It messed up the frames around the output window a little bit. It was still readable, but a bit "dodgy".  
For understandable reasons all codepages and encoding combinations has not been tested which means that this will depend on the actual OS settings and similar errors might show again.