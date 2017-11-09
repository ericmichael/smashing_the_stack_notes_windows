import subprocess
payload = ""
exploit = "\x90"
exploit += ""
exploit += payload
print exploit
subprocess.call(['C:\\Users\\ericm\\OneDrive\\Documents\\Visual Studio 2017\\Projects\\bufferOverflow\\Debug\\bufferOverflow.exe', exploit])