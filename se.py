import ctypes
import sys
from win32 import win32evtlog

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    # Your code that requires elevated privileges
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

     
else:
    print("This script requires administrative privileges.")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
