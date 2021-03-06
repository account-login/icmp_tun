#!/usr/bin/env python3 -m peachpy.x86_64 -S -o splitmix64_lu_amd64.s -mabi=goasm

# These two lines are not needed for PeachPy,
# but will help you get autocompletion in good code editors
from peachpy import *
from peachpy.x86_64 import *


def xorshift(sv, shift_count):
    tmp = GeneralPurposeRegister64()
    MOV(tmp, sv)
    SHR(tmp, shift_count)
    XOR(sv, tmp)


def splitmix64(rval, sv_list):
    for i, sv in enumerate(sv_list):
        # result := uint64(*s)
        # result += 0x9E3779B97f4A7C15
        # ADD(rval, a1)
        # MOV(sv, rval)
        if i == 2:
            # LEA(sv, [rval + a1 * 2])
            # ADD(sv, a1)
            LEA(sv, [rval + a3 * 1])
        else:
            # 1, 2, 4
            LEA(sv, [rval + a1 * (i + 1)])
    LEA(rval, [rval + a1 * len(sv_list)])

    for sv in sv_list:
        # result ^= result >> 30
        xorshift(sv, 30)
    for sv in sv_list:
        # result *= 0xBF58476D1CE4E5B9
        IMUL(sv, c1)
    for sv in sv_list:
        # result ^= result >> 27
        xorshift(sv, 27)
    for sv in sv_list:
        # result *= 0x94D049BB133111EB
        IMUL(sv, c2)
    for sv in sv_list:
        # result ^= (result >> 31)
        xorshift(sv, 31)


s = Argument(uint64_t)
dst = Argument(ptr(uint8_t))
src = Argument(ptr(uint8_t))
n = Argument(int64_t)
with Function("sm64xorLU", (s, dst, src, n), uint64_t, target=uarch.default) as sm64xorLU:
    # arg s, return r
    rval_reg = GeneralPurposeRegister64()
    LOAD.ARGUMENT(rval_reg, s)
    # arg dst, src
    src_reg = GeneralPurposeRegister64()
    LOAD.ARGUMENT(src_reg, src)
    dst_reg = GeneralPurposeRegister64()
    LOAD.ARGUMENT(dst_reg, dst)
    # arg n
    count = GeneralPurposeRegister64()
    LOAD.ARGUMENT(count, n)

    # constants
    a1 = GeneralPurposeRegister64()
    MOV(a1, 0x9E3779B97f4A7C15)
    c1 = GeneralPurposeRegister64()
    MOV(c1, 0xBF58476D1CE4E5B9)
    c2 = GeneralPurposeRegister64()
    MOV(c2, 0x94D049BB133111EB)

    # rng output
    factor = 4
    sv_regs = [GeneralPurposeRegister64() for _ in range(factor)]
    if factor >= 3:
        a3 = GeneralPurposeRegister64()
        MOV(a3, (0x9E3779B97f4A7C15 * 3) & 0xffffffff_ffffffff)

    # negative index
    ADD(src_reg, count)
    ADD(dst_reg, count)
    NEG(count)

    # vector loop
    vector_loop = Loop()
    ADD(count, 8 * factor)
    JG(vector_loop.end)
    with vector_loop:
        """
        func (s *SplitMix64) next() uint64 {
            result := uint64(*s)
            result += 0x9E3779B97f4A7C15
            *s = SplitMix64(result)
            result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9
            result = (result ^ (result >> 27)) * 0x94D049BB133111EB
            return result ^ (result >> 31)
        }
        """
        splitmix64(rval_reg, sv_regs)

        # dst = src ^ result
        src_val = GeneralPurposeRegister64()
        for i in range(factor):
            MOV(src_val, qword[src_reg + count * 1 + (8 * i - 8 * factor)])
            XOR(src_val, sv_regs[i])
            MOV(qword[dst_reg + count * 1 + (8 * i - 8 * factor)], src_val)

        # loop end
        ADD(count, 8 * factor)
        JLE(vector_loop.begin)

    sv0 = sv_regs[0]
    SUB(count, 8 * factor - 8)
    if factor > 1:
        qw_loop = Loop()
        JG(qw_loop.end)
        with qw_loop:
            # count >= 8
            splitmix64(rval_reg, [sv0])
            MOV(src_val, qword[src_reg + count * 1 - 8])
            XOR(src_val, sv0)
            MOV(qword[dst_reg + count * 1 - 8], src_val)

            ADD(count, 8)
            JLE(qw_loop.begin)

    # scalar loop
    scalar_loop = Loop()
    # count != 0
    SUB(count, 8)
    JZ(scalar_loop.end)
    splitmix64(rval_reg, [sv0])
    with scalar_loop:
        MOV(src_val.as_low_byte, byte[src_reg + count * 1])
        XOR(src_val, sv0)
        MOV(byte[dst_reg + count * 1], src_val.as_low_byte)
        SHR(sv0, 8)

        ADD(count, 1)
        JNZ(scalar_loop.begin)

    RETURN(rval_reg)
