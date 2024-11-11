# if_lister - by Jonas "SweJob" Bergstedt

The if_lister is a tool to list all the available interfaces and ther IP addresses
[Command line](#command-line)

## General overview
### Program structure
The main function - list_ifs -  is designed in a way to work with the `client_shell.py` framework.
To make it work as a CLI tool a print loop is added to main, to print the found interfaces

### Usage
#### Command Line
##### Command line example:  
`python if_lister.py`
Prints the name of all network interfaces and their IP addresses

#### ClientShell
1. `import if_lister`
2. Entry in FunctionManager `self.functions`  
```python
'if_list': {
    'type': 'one-time',
    'start_func': if_lister.list_ifs,
    'help': "Displays a list of network interfaces."
}
´´´
## Known issues