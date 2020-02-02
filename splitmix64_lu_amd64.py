#!/usr/bin/env python3 -m peachpy.x86_64 -S -o splitmix64_lu_amd64.s -mabi=goasm

# These two lines are not needed for PeachPy,
# but will help you get autocompletion in good code editors
from peachpy import *
from peachpy.x86_64 import *

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
    sv1, sv2 = GeneralPurposeRegister64(), GeneralPurposeRegister64()

    # vector loop
    vector_loop = Loop()
    with vector_loop:
        """
        func (s *SplitMix64) next() uint64 {
            result := uint64(*s)
            *s = SplitMix64(result + 0x9E3779B97f4A7C15)
            result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9
            result = (result ^ (result >> 27)) * 0x94D049BB133111EB
            return result ^ (result >> 31)
        }
        """

        def xorshift(shift_count):
            tmp1, tmp2 = GeneralPurposeRegister64(), GeneralPurposeRegister64()
            MOV(tmp1, sv1)
            SHR(tmp1, shift_count)
            XOR(sv1, tmp1)
            MOV(tmp2, sv2)
            SHR(tmp2, shift_count)
            XOR(sv2, tmp2)

        # result := uint64(*s)
        # *s = SplitMix64(*s + 0x9E3779B97f4A7C15)
        MOV(sv1, rval_reg)
        ADD(rval_reg, a1)
        MOV(sv2, rval_reg)
        ADD(rval_reg, a1)
        # result ^= result >> 30
        xorshift(30)
        # result *= 0xBF58476D1CE4E5B9
        IMUL(sv1, c1)
        IMUL(sv2, c1)
        # result ^= result >> 27
        xorshift(27)
        # result *= 0x94D049BB133111EB
        IMUL(sv1, c2)
        IMUL(sv2, c2)
        # result ^= (result >> 31)
        xorshift(31)

        # loop cond
        SUB(count, 16)
        JB(vector_loop.end)

        # dst = src ^ result
        src1, src2 = GeneralPurposeRegister64(), GeneralPurposeRegister64()
        MOV(src1, qword[src_reg + 0])
        XOR(src1, sv1)
        MOV(qword[dst_reg + 0], src1)
        MOV(src2, qword[src_reg + 8])
        XOR(src2, sv2)
        MOV(qword[dst_reg + 8], src2)

        ADD(src_reg, 16)
        ADD(dst_reg, 16)
        JMP(vector_loop.begin)

    scalar_loop = Loop()
    ADD(count, 16)
    JZ(scalar_loop.end)
    with Block('b8') as block:
        CMP(count, 8)
        JLE(block.end)

        # count > 8
        MOV(src1, qword[src_reg])
        XOR(src1, sv1)
        MOV(qword[dst_reg], src1)
        # sv1 used
        MOV(sv1, sv2)

        ADD(src_reg, 8)
        ADD(dst_reg, 8)
        SUB(count, 8)

    # scalar loop
    with scalar_loop:
        MOV(src1.as_low_byte, byte[src_reg])
        XOR(src1, sv1)
        MOV(byte[dst_reg], src1.as_low_byte)
        SHR(sv1, 8)

        ADD(src_reg, 1)
        ADD(dst_reg, 1)
        SUB(count, 1)
        JNZ(scalar_loop.begin)

    RETURN(rval_reg)
