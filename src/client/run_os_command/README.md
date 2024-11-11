# run_os_command - by Jonas "SweJob" Bergstedt

The run_os_command is a module to be imported by `client_shell.py`
It's a function to run an command in the OS where the client runs. 
All replies from the code is sent back to the server to be displyed there.
There is no Command Line use for this. 
(as you could write the command you want to run in run_os_command directly at the command line)

## General overview
### Program structure
It's designed to work with the `client_shell.py` framework.
It will try to run the provided command with the args in the clients OS
and add any output to the provided reply_list


### Usage

#### ClientShell
1. `import run_os_command`
2. Entry in FunctionManager `self.functions`  
```python
'run_os': {
    'type': 'one-time',
    'start_func': run_os_command.run_os_command,
    'help': "Runs [command] in the client os. Args: [req] command:str [opt] arguments:args"
 }
```
## Known issues
As the functions runs one command in shell and then exits, your starting point for every command is the directory where client_shell was started from every time you call the function.
This means that if you ´start client_shell from `/src/client` and you run `c run_os cd ..` from the `c2_server` it will move to `/src`, **BUT** then the shell that the code exits. Next time you run `c run_os something` you are back at `/src/client`

How do you get past this?
You build a script in your starting directory.  
If client runs on windows if could be something like this:
`c run_os echo cd .. > script.bat` - create the script.bat and start it with cd ..  
`c run_os echo dir >> script.bat` - append dir to script.bat
`c run_os script.bat` - run the script and you will get directory listing of the parent folder
The above example could be run as `c run_os dir ..` instead of creating it as a script, but I think it shows the general idea on how to work around the "starting from scratch".