import paramiko
import hashlib

# Define server and login details
hostname = '18.184.254.218'
username = 's14'  # replace with your actual student code
password = 'Snowd3n'

# Create SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Connect to the server
    client.connect(hostname, username=username, password=password)

    # Navigate to the NoAccess directory and list files
    stdin, stdout, stderr = client.exec_command('cd NoAccess && ls')
    files = stdout.read().decode().splitlines()

    # Target MD5 hash
    target_hash = '9c91802aaa7114783cc6df9c83e91d3f'

    # Check each file
    for file in files:
        stdin, stdout, stderr = client.exec_command(f'cat NoAccess/{file}')
        content = stdout.read()

        # Calculate MD5 hash
        md5_hash = hashlib.md5(content).hexdigest()

        # Check if it matches the target hash
        if md5_hash == target_hash:
            print(f"File with matching MD5 hash: {file}")
            break

finally:
    # Close the connection
    client.close()
