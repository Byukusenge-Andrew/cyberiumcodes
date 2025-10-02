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

def get_largest_files_linux(root_dir='/home'):
    """Lists the five largest files in a specified directory on Linux."""
    file_sizes = []
    path = root_dir

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
            cpu_usage = psutil.cpu_percent(interval=10)
            print(f"Current CPU Usage: {cpu_usage}%")
            time.sleep(9) 
    except KeyboardInterrupt:
        print("Stopped monitoring CPU usage.")


def grep_sudo_commands(log_file_path):
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if 'sudo' in line and 'COMMAND=' in line:
                    command_start = line.find('COMMAND=') + len('COMMAND=')
                    sudo_command = line[command_start:].strip()
                    print(sudo_command)

    except FileNotFoundError:
        print(f"The file {log_file_path} was not found.")


def monitor_user_authentication_changes():
    
    def get_failed_login_attempts():
    # Open the security event log
        server = 'localhost'  # Local machine
        log_type = 'Security'  # Type of event log
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        event_log = win32evtlog.OpenEventLog(server, log_type)

        failed_logins = []
        total = 0


        while total < 5:
 
            records = win32evtlog.ReadEventLog(event_log, flags, 0)
            if not records:
                break

            for record in records:
          
                if record.EventID <= 4625:
                    failed_logins.append(record)
                    total += 1
                    if total >= 5:
                        break

        win32evtlog.CloseEventLog(event_log)

        for event in failed_logins:
            print(f"Event ID: {event.EventID}, Time: {event.TimeGenerated}, Source: {event.SourceName}")
            print(f"User: {event.StringInserts[5]}, Failure Reason: {event.StringInserts[8]}")
            print("-------")

    get_failed_login_attempts()

        




def monitor_user_changes_linux(log_file_path_linux,log_lines):
    """Monitors user authentication changes in the auth.log file for Linux."""
    user_added_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*useradd.*(?:for user|new user):\s+(\S+)')
    user_deleted_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*userdel.*(?:for user|deleted user):\s+(\S+)')
    password_change_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*passwd.*(?:for user|password changed for):\s+(\S+)')
    su_command_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*su:\s+session opened for user\s+(\S+)')
    sudo_command_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+).*sudo.*COMMAND=(.+)')
    failed_sudo_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+).*sudo.*authentication failure.*COMMAND=(.+)')
    
    print("\nUser Authentication Changes:")
   
    for line in log_lines:
        
        if user_added_match := user_added_pattern.search(line):
            timestamp, user = user_added_match.groups()
            print(f"New user added: Timestamp: {timestamp}, User: {user}")
        
        if user_deleted_match := user_deleted_pattern.search(line):
            timestamp, user = user_deleted_match.groups()
            print(f"User deleted: Timestamp: {timestamp}, User: {user}")
        
        if password_change_match := password_change_pattern.search(line):
            timestamp, user = password_change_match.groups()
            print(f"Password changed: Timestamp: {timestamp}, User: {user}")
        
        if su_command_match := su_command_pattern.search(line):
            timestamp, user = su_command_match.groups()
            print(f"su command used: Timestamp: {timestamp}, User: {user}")
        
        if sudo_command_match := sudo_command_pattern.search(line):
            timestamp, user, command = sudo_command_match.groups()
            print(f"sudo command used: Timestamp: {timestamp}, User: {user}, Command: {command}")
        
        if failed_sudo_match := failed_sudo_pattern.search(line):
            timestamp, user, command = failed_sudo_match.groups()
            print(f"ALERT! Failed sudo attempt: Timestamp: {timestamp}, User: {user}, Command: {command}")
            
            
def main():
    
    log_file_path_linux = '/var/log/auth.log'
    



    os_info = platform.system()

    if os_info == "linux":
        with open(log_file_path_linux, 'r') as file:
            log_lines = file.readlines()
            monitor_user_changes_linux(log_file_path_linux,log_lines)

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
        
        print("input your choice: "); choice = input('> ')
       

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
                grep_sudo_commands(log_file_path_linux)
        elif choice == '6' and os_info != "Windows":
            monitor_user_changes_linux(log_file_path_linux,log_lines)
        elif choice == '7':
            monitor_cpu_usage()
        elif choice == '8':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
