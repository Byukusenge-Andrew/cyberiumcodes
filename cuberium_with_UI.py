import os
import platform
import psutil
import subprocess
import time
import tkinter as tk
from tkinter import messagebox
from threading import Thread

# Importing Windows-specific libraries for event logs if running on Windows
if platform.system() == 'Windows':
    import win32evtlog


# System Information Functions (from your existing code)
def get_system_info():
    os_info = platform.system()
    version_info = platform.version()
    release_info = platform.release()
    return f"Operating System: {os_info}\nVersion: {version_info}\nRelease: {release_info}"


def get_network_info():
    try:
        interfaces = psutil.net_if_addrs()
        private_ip = interfaces[list(interfaces.keys())[0]][0].address
        public_ip = subprocess.getoutput('curl -s ifconfig.me')
        gateway = psutil.net_if_addrs()[list(psutil.net_if_addrs().keys())[0]][1].address
        return f"MAC Address: {private_ip}\nPublic IP: {public_ip}\nDefault Gateway: {gateway}"
    except Exception as e:
        return f"Error retrieving network info: {e}"


def get_disk_info():
    disk_usage = psutil.disk_usage('/')
    return f"Total Disk Size: {disk_usage.total / (1024 ** 3):.2f} GB\nUsed Disk Space: {disk_usage.used / (1024 ** 3):.2f} GB\nFree Disk Space: {disk_usage.free / (1024 ** 3):.2f} GB"


# Authentication Changes for Linux (auth.log)
def extract_authentication_changes_linux():
    log_file_path_linux = '/var/log/auth.log'
    try:
        with open(log_file_path_linux, 'r') as file:
            lines = file.readlines()
            changes = []

            # Example: parsing for user authentication events
            for line in lines:
                if 'useradd' in line or 'userdel' in line or 'passwd' in line:
                    changes.append(line)

            return "\n".join(changes) if changes else "No authentication changes found."
    except FileNotFoundError:
        return f"Log file {log_file_path_linux} not found."


# Tkinter UI Class
class LogAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer UI")
        self.root.geometry("600x500")

        # Title Label
        self.title_label = tk.Label(root, text="Log Analyzer", font=("Helvetica", 18))
        self.title_label.pack(pady=20)

        # Buttons
        self.sys_info_button = tk.Button(root, text="Get System Info", command=self.show_system_info)
        self.sys_info_button.pack(pady=10)

        self.network_info_button = tk.Button(root, text="Get Network Info", command=self.show_network_info)
        self.network_info_button.pack(pady=10)

        self.disk_info_button = tk.Button(root, text="Get Disk Info", command=self.show_disk_info)
        self.disk_info_button.pack(pady=10)

        self.cpu_monitor_button = tk.Button(root, text="Monitor CPU Usage", command=self.monitor_cpu_usage)
        self.cpu_monitor_button.pack(pady=10)

        self.auth_change_button = tk.Button(root, text="Extract User Auth Changes", command=self.extract_auth_changes)
        self.auth_change_button.pack(pady=10)

        self.exit_button = tk.Button(root, text="Exit", command=root.quit)
        self.exit_button.pack(pady=20)

        # Text Box for Output
        self.output_text = tk.Text(root, height=15, width=70)
        self.output_text.pack(pady=10)

    # Functions for buttons
    def show_system_info(self):
        info = get_system_info()
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, info)

    def show_network_info(self):
        info = get_network_info()
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, info)

    def show_disk_info(self):
        info = get_disk_info()
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, info)

    def monitor_cpu_usage(self):
        # CPU Monitoring in a new thread to keep the UI responsive
        thread = Thread(target=self._monitor_cpu_thread)
        thread.start()

    def _monitor_cpu_thread(self):
        messagebox.showinfo("CPU Monitor", "Monitoring CPU usage every 10 seconds. Click OK to start.")
        try:
            while True:
                cpu_usage = psutil.cpu_percent(interval=10)
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, f"Current CPU Usage: {cpu_usage}%")
                time.sleep(9)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error monitoring CPU usage: {e}")

    def extract_auth_changes(self):
        # Run authentication change extraction based on OS
        os_info = platform.system()
        if os_info == 'Linux':
            changes = extract_authentication_changes_linux()
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, changes)
        else:
            messagebox.showinfo("Info", "This function is currently only available for Linux.")

# Running the Tkinter App
if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerUI(root)
    root.mainloop()
