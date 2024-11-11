# arp_sniffer - by Jonas "SweJob" Bergstedt

The arp_sniffer is a tool to sniff for MAC adresses. It's listens for arp packets and returns them.
When run as a command tool it loops (indefinately or for a set time) and prints found arphosts to terminal.
When timing out or interrupted by Ctrl+c a list of all the found hosts are printed
[Command line](#command-line)  

## General overview
### Program structure
This is a function that runs in a thread.
The main function - arp_sniffer -  is designed in a way to work with the `client_shell.py` framework.
To make it work as a CLI tool a print thread, an arg parse and an sigint handler is added 

### Usage
#### Command line
To run the arps_sniffer it needs the following information:  
ip_address: The IP address to bind the sniffer to.  
-d, --duration: Duration to sniff in seconds.  
-i, --interval: Interval between sniffing iterations in seconds.  

The default values are:   
duration: None (interpreted as eternal loop)  
interval: 5  

command line example:  
`python arp_sniffer.py 192.168.1.10`
Starts an eternal arp_sniff on the network connected to 192.168.1.10
  
`python arp_sniffer.py 192.168.1.10 -d 30 -i 1`
Starts an eternal arp_sniff on the network connected to 192.168.1.10 for 30 seconds

Can be interrupted with Ctrl+C

#### ClientShell
1. `import arp_sniffer`  
2. Entry in FunctionManager `self.functions`  
```python
'arp_sniffer': {
        'type': 'continuous',
                'status': 'Stopped',
                'thread': None,
                'start_func': arp_sniffer.arp_sniffer,
                'fnargs': (self.arp_hosts,),
                'stop_event': threading.Event(),
                'help': "Sniffs ARP packets continuously until stopped. \n" + " "*27 +
                "Args: [req] bind_address:str [opt] interval:float, duration:float"
            }
```
## Known limitations
Cant sniff Tailscalenetwork ;)
