import subprocess

command = 'Get-WinEvent -LogName System | Select-Object -First 10'
result = subprocess.run(['powershell', '-Command', command], capture_output=True, text=True)
print(result.stdout)
