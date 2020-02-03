// +build !noasm
// Generated by PeachPy 0.2.0 from splitmix64_lu_amd64.py


// func sm64xorLU(s uint64, dst *uint8, src *uint8, n int64) uint64
TEXT ·sm64xorLU(SB),4,$0-40
	MOVQ s+0(FP), AX
	MOVQ src+16(FP), CX
	MOVQ dst+8(FP), DX
	MOVQ n+24(FP), DI
	MOVQ $11400714819323198485, SI
	MOVQ $13787848793156543929, BP
	MOVQ $10723151780598845931, R8
	SUBQ $16, DI
	JLT vector_loop_end
vector_loop_begin:
		MOVQ AX, R9
		ADDQ SI, AX
		MOVQ AX, R10
		ADDQ SI, AX
		MOVQ R9, BX
		SHRQ $30, BX
		XORQ BX, R9
		MOVQ R10, BX
		SHRQ $30, BX
		XORQ BX, R10
		IMULQ BP, R9
		IMULQ BP, R10
		MOVQ R9, BX
		SHRQ $27, BX
		XORQ BX, R9
		MOVQ R10, BX
		SHRQ $27, BX
		XORQ BX, R10
		IMULQ R8, R9
		IMULQ R8, R10
		MOVQ R9, BX
		SHRQ $31, BX
		XORQ BX, R9
		MOVQ R10, BX
		SHRQ $31, BX
		XORQ BX, R10
		MOVQ 0(CX), BX
		XORQ R9, BX
		MOVQ BX, 0(DX)
		MOVQ 8(CX), BX
		XORQ R10, BX
		MOVQ BX, 8(DX)
		ADDQ $16, CX
		ADDQ $16, DX
		SUBQ $16, DI
		JGE vector_loop_begin
vector_loop_end:
	ADDQ $16, DI
qw_loop_begin:
		CMPQ DI, $8
		JLT qw_loop_end
		MOVQ AX, R9
		ADDQ SI, AX
		MOVQ R9, BX
		SHRQ $30, BX
		XORQ BX, R9
		IMULQ BP, R9
		MOVQ R9, BX
		SHRQ $27, BX
		XORQ BX, R9
		IMULQ R8, R9
		MOVQ R9, BX
		SHRQ $31, BX
		XORQ BX, R9
		MOVQ 0(CX), BX
		XORQ R9, BX
		MOVQ BX, 0(DX)
		ADDQ $8, CX
		ADDQ $8, DX
		SUBQ $8, DI
		JMP qw_loop_begin
qw_loop_end:
	TESTQ DI, DI
	JEQ scalar_loop_end
	MOVQ AX, R9
	ADDQ SI, AX
	MOVQ R9, SI
	SHRQ $30, SI
	XORQ SI, R9
	IMULQ BP, R9
	MOVQ R9, SI
	SHRQ $27, SI
	XORQ SI, R9
	IMULQ R8, R9
	MOVQ R9, SI
	SHRQ $31, SI
	XORQ SI, R9
scalar_loop_begin:
		MOVB 0(CX), BX
		XORQ R9, BX
		MOVB BX, 0(DX)
		SHRQ $8, R9
		ADDQ $1, CX
		ADDQ $1, DX
		SUBQ $1, DI
		JNE scalar_loop_begin
scalar_loop_end:
	MOVQ AX, ret+32(FP)
	RET