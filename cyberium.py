"""
Log Analyzer Project
Student Name: Byukusenge Andre
Class Code: S14
Lecturer's Name: Celestin Nzeyimana

This script analyzes the auth.log file for Linux and Windows Event Viewer logs to extract command usage
and monitor user authentication changes. It identifies the operating system and provides system details,
network data, disk statistics, and real-time CPU usage monitoring.

Credits:
- psutil library for system and process utilities: https://pypi.org/project/psutil/
- Stack Overflow for examples on parsing logs and retrieving system information: https://stackoverflow.com/
- Windows PowerShell for accessing Event Viewer logs.

"""
import os
import platform
import psutil
import re
import subprocess
import time
from win32 import win32evtlog



def get_system_info():
    """Identifies the operating system and retrieves corresponding system details."""
    os_info = platform.system()
    version_info = platform.version()
    release_info = platform.release()

    print(f"Operating System: {os_info}")
    print(f"Version: {version_info}")
    print(f"Release: {release_info}")

def get_network_info():
    """network information including private and public IP addresses, and default gateway."""
    try:
        interfaces = psutil.net_if_addrs()
        private_ip = interfaces[list(interfaces.keys())[0]][0].address
        public_ip = subprocess.getoutput('curl -s ifconfig.me')
        gateway = psutil.net_if_addrs()[list(psutil.net_if_addrs().keys())[0]][1].address
        
        print(f"MAC Address: {private_ip}")
        print(f"Public IP: {public_ip}")
        print(f"Default Gateway: {gateway}")
    except Exception as e:
        print(f"Error retrieving network info: {e}")

def get_disk_info():
    """Retrieves disk statistics including total size, used space, and free space."""
    disk_usage = psutil.disk_usage('/')
    print(f"Total Disk Size: {disk_usage.total / (1024**3):.2f} GB")
    print(f"Used Disk Space: {disk_usage.used / (1024**3):.2f} GB")
    print(f"Free Disk Space: {disk_usage.free / (1024**3):.2f} GB")

def get_largest_files_windows(root_dir='D:\\'):
    """Lists the five largest files in a specified directory on Windows."""
    file_sizes = []

    def scan_directory(path):
        """Recursively scans directories to find file sizes."""
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        if entry.is_file():
                            file_sizes.append((entry.path, entry.stat().st_size))
                        elif entry.is_dir():
                            scan_directory(entry.path)
                    except (PermissionError, FileNotFoundError):
                        continue
        except PermissionError:
            return

    scan_directory(root_dir)
    largest_files = sorted(file_sizes, key=lambda x: x[1], reverse=True)[:5]

    print("Five Largest Files:")
    for filepath, size in largest_files:
        print(f"{filepath}: {size / (1024**3):.2f} GB")
        #leave some space
        print(" ")

def get_largest_files_linux(root_dir='/'):
    """Lists the five largest files in a specified directory on Linux."""
    file_sizes = []

    def scan_directory(path):
        """Recursively scans directories to find file sizes."""
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        if entry.is_file():
                            file_sizes.append((entry.path, entry.stat().st_size))
                        elif entry.is_dir():
                            scan_directory(entry.path)
                    except (PermissionError, FileNotFoundError):
                        continue
        except PermissionError:
            return

    scan_directory(root_dir)
    largest_files = sorted(file_sizes, key=lambda x: x[1], reverse=True)[:5]

    print("Five Largest Files:")
    for filepath, size in largest_files:
        print(f"{filepath}: {size / (1024**3):.2f} GB")

def monitor_cpu_usage():
    """Monitors CPU usage, refreshing every ten seconds for real-time statistics."""
    print("Monitoring CPU usage every 10 seconds. Press Ctrl+C to stop.")
    try:
        while True:
            cpu_usage = psutil.cpu_percent(interval=1)
            print(f"Current CPU Usage: {cpu_usage}%")
            time.sleep(9)  # Sleep for 9 seconds for a 10-second refresh rate
    except KeyboardInterrupt:
        print("Stopped monitoring CPU usage.")

def parse_auth_log(log_file):
    """Parses the auth.log file to extract command usage details for Linux."""
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found. Skipping command usage parsing.")
        return

    try:
        with open(log_file, 'r') as file:
            for line in file:
                # Extract timestamp, user, and command from the log line
                timestamp = re.search(r'\w+ \d+ \d+:\d+:\d+', line)
                user = re.search(r'user (\w+)', line)
                command = re.search(r'COMMAND=(.*)', line)

                # If all elements are found, print the details
                if timestamp and user and command:
                    print(f"Timestamp: {timestamp.group()}")
                    print(f"User: {user.group(1)}")
                    print(f"Command: {command.group(1)}\n")

    except FileNotFoundError:
        print(f"Log file {log_file} not found.")
    except Exception as e:
        print(f"Error reading log file: {e}")

def monitor_user_authentication_changes():
    # """Monitor user authentication changes on Windows."""
    # #monitoring user authentication changes
    # ps_command = '''
    # $ErrorActionPreference = "Stop"
    # if (-NOT [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent().IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    #     $args = [System.Collections.ArrayList]@("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& {Start-Process PowerShell -ArgumentList $args -Verb RunAs}")
    #     Start-Process PowerShell -ArgumentList $args -Verb RunAs
    #     exit
    # }
    # Get-WinEvent -LogName Security | Where-Object {
    #     $_.Id -eq 4624 -or  # Successful logon
    #     $_.Id -eq 4625 -or  # Failed logon
    #     $_.Id -eq 4720 -or  # User account created
    #     $_.Id -eq 4726 -or  # User account deleted
    #     $_.Id -eq 4723      # Password changed
    # } | Select-Object TimeCreated, Id, Message
    # '''

    # #script file
    # script_path = 'temp_script.ps1'
    # with open(script_path, 'w') as script_file:
    #     script_file.write(ps_command)

    # # Run the PowerShell script
    # command = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
    
    # try:
    #     result = subprocess.run(command, capture_output=True, text=True, check=True)
    #     print(result.stdout)
    # except subprocess.CalledProcessError as e:
    #     print(f"Error retrieving user changes: {e}")
    # finally:
    #     # Clean up temporary script file
    #     if os.path.exists(script_path):
    #         os.remove(script_path)
    server = "localhost"
    logtype = "Security"
    flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    failures = {}

    def checkEvents():
        
            h = win32evtlog.OpenEventLog(server, logtype)
            while True:
                events = win32evtlog.ReadEventLog(h, flags)
                if events:
                    for event in events:
                        if event.EventID == 4625:
                            if event.stringInserts[0].startswith("S-1-5-21"):
                                account = event.stringInserts[1]
                                if account in failures:
                                    failures[account] += 1
                                else:
                                    failures[account] = 1


                        else:
                            break
        

    checkEvents()

    for account in failures:
        print("%s: %s failed logins" % (account, failures[account]))

        




def monitor_user_changes_linux(log_file):
    """Monitors user authentication changes in the auth.log file for Linux."""
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found. Skipping user authentication monitoring.")
        return

    try:
      with open(log_file, 'r') as file:
        for line in file:
                # Extract timestamp from the log line
            timestamp = re.search(r'\w+ \d+ \d+:\d+:\d+', line)

                # Check for specific user change events and print details
            if timestamp:
                if 'new user' in line:
                        print(f"New User Added at {timestamp.group()}")
                elif 'deleted user' in line:
                        print(f"User Deleted at {timestamp.group()}")
                elif 'changed password' in line:
                        print(f"Password Changed at {timestamp.group()}")
                elif 'su ' in line:
                        print(f"su Command Used at {timestamp.group()}")
                elif 'sudo ' in line:
                    if 'authentication failure' in line:
                            print(f"ALERT! Failed sudo at {timestamp.group()} - Command: {line}")
                    else:
                            print(f"sudo Command Used at {timestamp.group()} - Command: {line}")

    except FileNotFoundError:
        print(f"Log file {log_file} not found.")
    except Exception as e:
        print(f"Error reading log file: {e}")

def main():
    # Specify the path to the auth.log file for Linux and a log file for Windows
    log_file_path_linux = '/var/log/auth.log'
    log_file_path_windows = 'C:\\Path\\To\\Your\\Windows\\LogFile.log'  # Update this path

    os_info = platform.system()

    while True:
        print("\nLog Analyzer Menu")
        print("1. Get System Information")
        print("2. Get Network Information")
        print("3. Get Disk Information")
        if os_info == "Windows":
            print("4. List Largest Files (Windows)")
            print("5. Monitor User Authentication Changes (Windows)")
        else:
            print("4. List Largest Files (Linux)")
            print("5. Parse auth.log for Command Usage (Linux)")
            print("6. Monitor User Authentication Changes (Linux)")
        print("7. Monitor CPU Usage")
        print("8. Exit")
        
        choice = input("Please choose an option: ")

        if choice == '1':
            get_system_info()
        elif choice == '2':
            get_network_info()
        elif choice == '3':
            get_disk_info()
        elif choice == '4':
            if os_info == "Windows":
                get_largest_files_windows()
            else:
                get_largest_files_linux()
        elif choice == '5':
            if os_info == "Windows":
                monitor_user_authentication_changes()
            else:
                parse_auth_log(log_file_path_linux)
        elif choice == '6' and os_info != "Windows":
            monitor_user_changes_linux(log_file_path_linux)
        elif choice == '7':
            monitor_cpu_usage()
        elif choice == '8':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
