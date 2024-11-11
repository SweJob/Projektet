# The project 
by Jonas "SweJob" Bergstedt

This is the overall README for the whole project.  
List of contents:  
[Requirements](#requirements-for-project)  
[Table of Tools](#table-of-tools-and-requirements)  
[Directory structure](#file--and-directory-structure-of-project)  
[Idea behind project](#main-idea-of-my-project)  
[Usage](#usage-for-the-overall-project)
[Examples](#example-of-how-to-use-some-functions)

### Requirements for project  

#### Toolbox
Build at toolbox with server Python-script that can be used for pentesting or otherwise in the IT-security field.  
Use techniques and packages that we have lookad at during the course or knowledge you had prior to the course.

#### Requirements for all tools:
- The tool should use atleast one externa Python-library (f.ex. requests, shodan, crypthography, scapy, nmap a.s.o)  
- The tool should use argparse and be able to be executed with arguments from the terminal (except if the toool does not need any user input)  
- The tool should have a README-file with instructions on how to use it, example runs and known limitations

#### Requirement for "Godkänt" (approved):
- At least three tools from different categories (note: You are allowed to use the tools form the previous Laborations. But make sure the adhere to the requirements for the assignment)  
- The tools should have clear usage instructions  
- The code should have basic error-handling (f.ex. try-except), input validation and be structured into functions


#### Requiremnts for "Väl godkänt"(well approved):
- Include additional/more advanced functions, as logging, report generation, a mainscript that imports the other scripts and let the user interacctively run them  
- Implement more than tree tools to show knowledge of other python-packages  
- The tools should be well documented  

#### Submission of project:
- Put everything in a Github repo. Either create a readme-file for each tool (separeate them into folders) or one readme with all tools listed.
- Make sure the repo is public (or invite teacher if you want to keep it private) and post link as submission

#### Table of tools and requirements: 
(link to their README.md respectively in the Tool name)
|Tool                                                   |Ext.lib.|Argp.|Readme|Instr.|Error<br>handl.|Input<br>valid.|Func.| Adv. func.|
|-------------------------------------------------------|--------|-----|------|------|---------------|---------------|-----|-----------|
|[c2_server](./src/server/README.md)                    | urwid  | yes | yes  | yes  | yes           | yes           | yes |Multi-threading,<br> non-blocking sockets,<br>classes|
|[client_shell](./src/client/README.md)                 | none   | yes | yes  | yes  | yes           | yes           | yes |Multi-threading,<br> classes,<br>importing other scripts|
|[arp_sniffer](./src/client/arp_sniffer/README.md)      | scapy  | yes | yes  | yes  | yes           | yes           | yes |           |
|[if_lister](./src/client/if_lister/README.md)          | psutil | N/A | yes  | yes  | yes           | N/A           | yes |           |
|[run_os_command](./src/client/run_os_command/README.md)| none   | N/A | yes  | yes  | yes           | by OS*        | yes |           |
|[crypto_tool](./src/utils/crypto_tool/README.md)|cryptography,<br> pycryptodome|yes|yes|yes|yes     | N/A           | yes |           |
|[ip_addr_chk](./src/utils/ip_addr_chk/README.md)       | none   | yes | yes  | yes  | yes           | yes           | yes |Created own exception|     

#### Other requirements
At least three tools : Yes  
Clear usage instructions : Yes (kind of "eye of the beholder"-judgement on this one. Suggestions for improvments are appreciated)  
Basic error handling: Yes (sometimes I feel it was more than basic :) )  
Additional functions :   
1. Logging : Not *activated* in client_shell and c2_server, **but** import and the code in the main-function is still there, allthough commented out.<br> Logging was used extensivley during testing and debugging
2. Mainscript that imports other scripts : FunctionManager class in client_shell is kind of built on this concept.
3. More advanced functions : Multithreading, keeping track of non-blocking sockets and their state, reconnecting logic in both server and client.
4. More than three tools : depending on how you count and what you count.
5. Well documented : There is probaly room for improvements (feedback is welcome)

Github :  
1. Everything in a repo : https://github.com/SweJob/Projektet
2. Repo made public :
README for each tool: Yes (plus this README as an overall README for the project)

### File- and directory-structure of project
In the [structure.txt](./structure.txt) you see what the directory structure looks like and where to find different files

### Main idea of my project
#### Server:  
- A c2 server running locally. 
- The server provides an user interface where you can communcicate with the client.
- The server can log the input/output for later reference  

#### Client:  
- The client runs on a host we want to silently control. 
- The client should connect to the server and then accept commands from the server.
- The client sends any output to the server and do not print anything on the local screen, to keep it stealth
- The client is built in a way so that it easily can import new functions and add them to the framework, without altering existing code (except for import-statement and adding the function to the ditionary that lists all the functions and their necessary properties)

#### Communication:
- Communciation between client and server is initiated from client to remsemble a reverse shell.
- Communciation is encrypted with symmetric encryption where the key is generated from a password entered as an argument at startup of server and client (or using the default password)
- One socket is used for the client to send statuses at a regular interval
- One socket is used for sending commands from the server to the client and recive output from the client to the server
- Any output from client is put in a response-list. This list is continously monitored and sent to the server, when there is a connection. The server prints this in the output window. If the connection breaks while the client is running, the list will keep getting entries that will be sent as soon as the connection is back up again.
- Both client and server will try to reestablish a connection if it's lost. 

### Usage for the overall project  
For more details, look in each separete tools README.md. [List of tools are here](#table-of-tools-and-requirements)
1. Start the server, binding it to a network interface that is able to communicate with the client
2. Start the client, telling it the IP address of the server
3. **User interaction**
   1. Enter commands at the command prompt in the server
   2. **Server commands**  
        These are called by writing `s` or `server` as the first work in the command prompt and then followed by the command an optionaly any arguments. Ex. `s help` 
        1. `help` - displays a list of all the commands
        2. `save_output [filename]` - saves everything sent to output to filename.
        3. `exit` - terminate teh server orderly
   3.   **Client commands**  
        These are called by writing `c` or `client` as the first work in the command prompt and then followed by the command an optionaly any arguments. Ex. `c help`
        At the moment these commands are included in the client, but the concept is that it should be realtively easy to add new functions, sticking to the guidlines of the framework.
        1. `help` - displays a list of valid commands
        2. `set_updte_interval [interval]` - Set the interval for sending status to server in seconds
        3. `arp_sniffer [bind_address] [interval] [duration]` - sniffs the network connected to the bind_address for MAC addresses. Send result to response-list. Results is also stored in client to be displyed by get_hosts-command. <br>`interval` is the time between the listens. Defult value:5 <br>`duration` is for how many seconds the thread will run. Default value: None (= eternal)
        4. `get_hosts` - displays a list of hosts retrieved so far by arp_sniffer
        5. `if_list` - displays a list of interfaces on the client and their IP addresses
        6. `get_os` - displys which OS the client runs
        7. `run_os [command] [args]` - run a command from shell (cmd or sh) with possibility to add arguments. StdErr and StdOut  is returned to the response-list
        8. `stop [function]`- stops continuous function (at this time only arp_sniffer is continuous)
        9. `stop_client` - stops all continuous fucntions and then terminates the client.

#### Example of how to use some functions
##### run_os
After the connection between server and client is established, enter `c run_os dir`  
This will show the directory on the client.
As the command is run and then stops, all `c run_os [command]` will start in this directory.  
As we can just run one command we need to use those commands to step by step create a script.  
`c run_os echo cd .. > script.bat`
`c run_os echo dir  >> script.bat`
`c run_os echo type *.txt >> script.bat`
`c run_os script.bat`

This sequence will create a script called script.bat that looks like this:  
``` cmd
cd ..  
dir
type *.txt
```
The last line will run this script and display output in the output window.

##### arp_sniffer
To find out MAC-adreses on the network of the client you could do something like this.  
1. `c if_list` - this will provide a list of interfaces, similar to this:  
```
> Ethernet : 192.168.1.137
> VMware Network Adapter VMnet8 : 192.168.232.1
> Bluetooth-nätverksanslutning : 169.254.141.130
> Tailscale : 100.112.50.61
> Loopback Pseudo-Interface 1 : 127.0.0.1
```
2. `c arp_sniffer 192.168.1.137` - this will start the arp_sniffer listening on the interface connected to 192.168.1.137  
After a while your Output window could show something like this:
``` 
> Detected: MAC=aa:bb:cc:dd:ee:ff, IP=192.168.1.1, Hostname=None
> Detected: MAC=bb:cc:dd:ee:ff:aa, IP=192.168.1.179, Hostname=None
> Detected: MAC=cc:dd:ee:ff:aa:bb, IP=192.168.1.214, Hostname=None
> Detected: MAC=dd:ee:ff:aa:bb:cc, IP=192.168.1.137, Hostname=None
> Detected: MAC=cc:dd:ee:ff:aa:bb, IP=0.0.0.0, Hostname=None
```
     As long as the arp_sniffer is running it will keep looking for new adresses and send them to be   displayed by the server.
3. `c get_hosts' - displays a formated list of hosts detected so far, grouped on MAC addresses with all connected IP addresses
```
> Discovered ARP hosts:
> MAC: aa:bb:cc:dd:ee:ff
>   IPs:
>        192.168.1.1
> ----------------------
> MAC: bb:cc:dd:ee:ff:aa
>   IPs:
>        192.168.1.179
> ----------------------
> MAC: cc:dd:ee:ff:aa:bb
>   IPs:
>        192.168.1.214
>        0.0.0.0
> ----------------------
> MAC: dd:ee:ff:aa:bb:cc
>   IPs:
>        192.168.1.137
> ----------------------
```  
4. `c stop arp_sniffer` - this will stop the sniffer (usually take a few seconds, as the present sniff needs to timeout)  
```
> Stopping arp_sniffer
> Function is stopped: arp_sniffer
```

### Known limitations
When a continuous functions stops by an error or by a timeout, the Status value that is parsed, sent and shown in the Status window in the server is not set to "Stopped", but in the output window you will see a text saying that the function has stopped. To update the status, you can run `c stop [function]` to update the status. Note: If the function still is running when you run the stop command, it will stop.
