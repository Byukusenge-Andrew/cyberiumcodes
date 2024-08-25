import re

# Path to the auth.log file on Kali Linux
log_file = '/var/log/auth.log'

# Function to read the log file
def read_auth_log(file_path):
    try:
        with open(file_path, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"Log file not found at {file_path}")
        return []

# Function to extract command usage from the log
def extract_commands(log_lines):
    # Regex pattern for extracting command usage
    command_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+)\s+.*COMMAND=(.+)')
    
    print("Command usage found:")
    for line in log_lines:
        match = command_pattern.search(line)
        if match:
            timestamp, user, command = match.groups()
            print(f"Timestamp: {timestamp}, User: {user}, Command: {command}")

# Function to monitor authentication changes (user addition, deletion, password changes, etc.)
def monitor_auth_changes(log_lines):
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

# Main function to run the log parser
def main():
    log_lines = read_auth_log(log_file)
    
    if log_lines:
        extract_commands(log_lines)
        monitor_auth_changes(log_lines)

if __name__ == "__main__":
    main()
