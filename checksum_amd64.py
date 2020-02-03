#!/usr/bin/env python3 -m peachpy.x86_64 -S -o checksum_amd64.s -mabi=goasm

# These two lines are not needed for PeachPy,
# but will help you get autocompletion in good code editors
from peachpy import *
from peachpy.x86_64 import *

b = Argument(ptr(uint16_t))
n = Argument(const_int64_t)
with Function("sum16b32", (b, n), uint32_t, target=uarch.default + isa.sse4_1) as sum16b32:
    breg = GeneralPurposeRegister64()
    nreg = GeneralPurposeRegister64()
    LOAD.ARGUMENT(breg, b)
    LOAD.ARGUMENT(nreg, n)

    # vector loop
    factor = 4
    l_regs = [XMMRegister() for _ in range(factor)]
    s_regs = [XMMRegister() for _ in range(factor)]
    for s in s_regs:
        PXOR(s, s)

    vector_loop = Loop()
    SUB(nreg, 8 * factor)
    JB(vector_loop.end)
    with vector_loop:
        for i in range(factor):
            PMOVZXWD(l_regs[i], qword[breg + 8 * i])
        for i in range(factor):
            PADDD(s_regs[i], l_regs[i])

        ADD(breg, 8 * factor)
        SUB(nreg, 8 * factor)
        JAE(vector_loop.begin)

    # sum s_regs
    for s in s_regs[1:]:
        PADDD(s_regs[0], s)

    # sum s_regs[0]
    PHADDD(s_regs[0], s_regs[0])
    PHADDD(s_regs[0], s_regs[0])

    # result
    r = GeneralPurposeRegister32()
    MOVD(r, s_regs[0])

    # scalar loop
    scalar_loop = Loop()
    ADD(nreg, 8 * factor)
    with scalar_loop:
        SUB(nreg, 2)
        JB(scalar_loop.end)
        # add uint16
        tmp = GeneralPurposeRegister32()
        MOVZX(tmp, word[breg])
        ADD(r, tmp)
        ADD(breg, 2)
        JMP(scalar_loop.begin)

    # odd byte
    ADD(nreg, 1)
    with Block('odd') as block:
        JNZ(block.end)
        # add uint8
        MOVZX(tmp, byte[breg])
        ADD(r, tmp)

    RETURN(r)
