"""
This module provides functionality to execute OS commands in a shell and
capture their output or errors. The output (or error messages) is 
appended to a response list that can be shared across threads.

Functions:
    run_os_command: Executes a shell command,
                    captures the output 
                    appends output to a provided response list.
"""
import subprocess

def run_os_command(response_list, response_lock, command: str, *args) -> None:
    """
    Run an OS command and append the output to the response_list.

    Args:
        response_list (list): The list to append the command output or errors to.
        response_lock (Lock): A threading lock to ensure thread-safe access to the response_list.
        command (str): The OS command to run.
        *args (str): Additional arguments to append to the command.

    Returns:
        None: This function does not return anything; it modifies the response_list.

    Raises:
        subprocess.CalledProcessError: If the command fails to execute, the error is captured
                                        and appended to the response_list.
    """
    try:
        # Run the command and capture output
        command_string = (command + " " + ' '.join(args)).strip()

        result = subprocess.run(
            command_string,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            encoding="cp850"
            )
        output = result.stdout
        errors = result.stderr

        if result:
            with response_lock:
                error_list = errors.strip("\r").split("\n")
                for response in error_list:
                    response_list.append(response)

                output_list = output.strip("\r").split("\n")
                for response in output_list:
                    response_list.append(response)

    except subprocess.CalledProcessError as e:
        # Handle any errors during command execution
        with response_lock:
            response_list.append(f"Error occurred: {e}")
