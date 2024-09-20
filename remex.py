#!/usr/bin/env python3

"""
This script connects to a remote host via SSH and executes commands.

It uses the paramiko library for SSH communication and argparse for
parsing command-line arguments.

The script supports both password and public key authentication.
Public key authentication is the default method.

Instructions:

1. Install the required libraries:
   - pip install paramiko

2. Save the script to a file, for example, ssh_exec.py.

3. Make the script executable:
   - chmod +x ssh_exec.py

4. Run the script with the required arguments:
   - ./ssh_exec.py -h <hostname> -u <username> -c "<command>"

Examples:

- Connect to host '192.168.1.100' as user 'john' and execute 'ls -l':
  ./ssh_exec.py -h 192.168.1.100 -u john -c "ls -l"

- Connect to host '192.168.1.100' as user 'john' using password 'secret'
  and execute 'uptime':
  ./ssh_exec.py -h 192.168.1.100 -u john -p secret -c "uptime"

- Connect to host '192.168.1.100' as user 'john' using public key
  at '/home/john/.ssh/id_rsa' and execute 'df -h':
  ./ssh_exec.py -h 192.168.1.100 -u john -k /home/john/.ssh/id_rsa -c "df -h"
"""

import argparse
import paramiko


def execute_commands(hostname, username, commands, password=None, key_file=None):
    """
    Connects to a remote host via SSH and executes commands.

    Args:
        hostname (str): The hostname or IP address of the remote host.
        username (str): The username to use for authentication.
        commands (list): A list of commands to execute on the remote host.
        password (str, optional): The password to use for authentication.
        key_file (str, optional): The path to the private key file for
                                   public key authentication.

    Returns:
        None
    """

    # Create an SSH client
    client = paramiko.SSHClient()

    # Automatically add the remote host's key to the known_hosts file
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the remote host
    try:
        if key_file:
            # Use public key authentication
            client.connect(hostname, username=username, key_filename=key_file)
        elif password:
            # Use password authentication
            client.connect(hostname, username=username, password=password)
        else:
            print("Error: Please provide either a password or a key file.")
            return

        # Execute each command
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode("utf-8")
            errors = stderr.read().decode("utf-8")

            # Print the output and errors
            if output:
                print(f"Output:\n{output}")
            if errors:
                print(f"Errors:\n{errors}")

    except paramiko.AuthenticationException:
        print("Error: Authentication failed.")
    except paramiko.SSHException as e:
        print(f"Error: SSH connection failed: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the SSH connection
        client.close()


if __name__ == "__main__":
    # Create an argument parser
    parser = argparse.ArgumentParser(
        description="Execute commands on a remote host via SSH."
    )

    # Add arguments
    parser.add_argument(
        "-h", "--hostname", required=True, help="Hostname or IP address"
    )
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument(
        "-c", "--commands", required=True, nargs="+", help="Commands to execute"
    )
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-k", "--key_file", help="Path to private key file")

    # Parse the arguments
    args = parser.parse_args()

    # Execute the commands
    execute_commands(
        args.hostname,
        args.username,
        args.commands,
        password=args.password,
        key_file=args.key_file,
    )
