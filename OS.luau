--[[
This is the full code of the virtualized operating system JuniOS. I built this in ROBLOX for fun and to learn how to write operating systems.
I have no idea what I am doing so I am basically rewriting code from github repos with the help of ChatGPT.

This operating system and all its details are open source. Far too few people know about the intricacies of the operating system. I recommend skimming a function,
and sequentially trying to understand it. Compare to the repos I was "inspired" to write it to.

It's not really impressive. It's mostly a learning tool and a showcase for the capabilities of ROBLOX at its core. All this was possible with the
bit32 and buffer libraries.

JuniOS developed by: efeugebaude

Inspiration:

LINKER (x86_64) - rui314's mold linker (MIT)
ASSEMBLER (x86_64) -
COMPILER (x86_64) -
]]

local buf = buffer.create(16384) -- memory pool
local insn

--[[
This is a security-enhanced version of the regular PLT. The PLT
header and each PLT entry starts with endbr64 for the Intel's
control-flow enforcement security mechanism.

Note that our IBT-enabled PLT instruction sequence is different
from the one used in GNU ld. GNU's IBTPLT implementation uses two
separate sections (.plt and .plt.sec) in which one PLT entry takes
32 bytes in total. Our IBTPLT consists of just .plt and each entry
is 16 bytes long.

Our PLT entry clobbers %r11, but that's fine because the resolver
function (_dl_runtime_resolve) clobbers %r11 anyway.
]]



local function write_plt_header(ctx, buf)
	insn = {
		0xf3, 0x0f, 0x1e, 0xfa, -- endbr64
		0x41, 0x53, 			-- push %r11
		0xff, 0x35, 0, 0, 0, 0, -- push GOTPLT+8(%rip)
		0xff, 0x23, 0, 0, 0, 0, -- jmp *GOTPLT+16(%rip)
		0xcc, 0xcc, 0xcc, 0xcc, -- PADDING
		0xcc, 0xcc, 0xcc, 0xcc, -- PADDING
		0xcc, 0xcc, 0xcc, 0xcc, -- PADDING
		0xcc, 0xcc
	}
	
	for i, byte in ipairs(insn) do
		buf.writeu8(buf, i-1, byte) -- write to memory pool
	end
	
	local push_offset = ctx.gotplt.shdr.sh_addr - ctx.plt.shdr.sh_addr - 4
	local jmp_offset = ctx.gotplt.shdr.sh_addr - ctx.plt.shdr.sh_addr - 2
	buf.writeu32(buf, 8, push_offset)
	buf.writeu32(buf, 14, jmp_offset)
end

local function write_plt_entry(ctx, buf, sym)
	--[[
	Only a canonical PLT can be address-taken; there's no way to take
	an address of a non-canonical PLT. Therefore, a non-canonical PLT doesn't
	have to start with an endbr64.
	]]
	if sym.is_canonical then
		insn = {
			0xf3, 0x0f, 0x1e, 0xfa, -- endbr64
			0x41, 0xbb, 0, 0, 0, 0, -- mov $index_in_relplt, %r11d
			0xff, 0x25, 0, 0, 0, 0, -- jmp *foo@GOTPLT
		}
		
		for i, byte in ipairs(insn) do
			buf.writeu8(buf, i-1, byte) -- write to memory pool
		end
		
		local idx = sym:get_plt_idx(ctx)
		for i = 0, 3 do
			buf.writeu8(buf, 6 + i, bit32.band(bit32.rshift(idx, 8*i), 0xFF))
		end
		
		local offset = sym:get_gotplt_addr(ctx) - sym:get_plt_addr(ctx) - 16
		for i = 0, 3 do
			buf.writeu8(buf, 12 + i, bit32.band(bit32.rshift(offset, 8*i), 0xFF))
		end
	else
		insn = {
			0x41, 0xbb, 0, 0, 0, 0,
			0xff, 0x25, 0, 0, 0, 0,
			0xcc, 0xcc, 0xcc, 0xcc
		}
		
		for i, byte in ipairs(insn) do
			buf.writeu8(buf, i-1, byte) -- write to memory pool
		end
		
		local idx = sym:get_plt_idx(ctx)
		for i = 0, 3 do
			buf.writeu8(buf, 2 + i, bit32.band(bit32.rshift(idx, 8*i), 0xFF))
		end
		
		local offset = sym:get_gotpolt_addr(ctx) - sym:get_plt_addr(ctx) - 16
		for i = 0, 3 do
			buf.writeu8(buf, 8 + i, bit32.band(bit32.rshift(offset, 8*i), 0xFF))
		end
	end
end

local function write_pltgot_entry(ctx, buf, sym)
	insn = {
		0xff, 0x25, 0, 0, 0, 0, -- jmp *foo@GOTPLT
		0xcc, 0xcc				-- PADDING
	}
	
	for i, byte in ipairs(insn) do
		buf.writeu8(buf, i-1, byte)
	end
	
	local offset = sym:get_got_pltgot_addr(ctx) - sym:get_plt_addr(ctx) - 6
	for i = 0, 3 do
		buf.writeu8(buf, 2 + i, bit32.band(bit32.rshift(offset, 8*i), 0xFF))
	end
end

local EhFrameSection = {}
EhFrameSection.__index = EhFrameSection

function EhFrameSection.new(context)
	local self = setmetatable({}, EhFrameSection)
	self.context = context
	self.shdr = context.shdr
	return self
end

function EhFrameSection:apply_eh_reloc(ctx, rel, offset, val)
	local loc = ctx.buf + self.shdr.sh_offset + offset
	
	if rel.r_type == "R_NONE" then
		return
	elseif rel.r_type == "R_X86_64_32" then
		self:write_u32(loc, val)
	elseif rel.r_type == "R_X86_64_64" then
		self:write_u64(loc, val)
	elseif rel.r_type == "R_X86_64_PC32" then
		local adjusted_val = val - ctx.shdr.sh_addr - offset
		
		for i = 0, 3 do
			ctx.buf.writeu8(ctx.buf, loc + i, bit32.band(bit32.rshift(adjusted_val, 8*i), 0xFF))
		end
	elseif rel.r_type == "R_X86_64_PC64" then
		local adjusted_val = val - ctx.shdr.sh_addr - offset
		
		for i = 0, 7 do
			ctx.buf.writeu8(ctx.buf, loc + i, bit32.band(bit32.rshift(adjusted_val, 8*i), 0xFF))
		end
	else
		error("Unsupported relocation in .eh_frame: " .. tostring(rel))
	end
end

local function relax_gotpcrelx(loc, rel)
	if rel.rtype == "R_X86_64_GOTPCRELX" then
		local high = buffer.readu8(buf, offset - 2)
		local low = buffer.readu8(buf, offset - 1)
		local opcode = bit32.bor(bit32.lshift(high, 8), low)
		
		local map = {
			[0xff15] = 0x40e8,
			[0xff25] = 0x40e9
		}
		
		return map[opcode] or 0
	else
		assert(
			rel.r_type == "R_X86_64_REX_GOTPCRELX" or
			rel.r_type == "R_X86_64_CODE_4_GOTPCRELX"
		)
		
		local high = buf.readu8(buf, offset - 3)
		local mid = buf.readu8(buf, offset - 2)
		local low = buf.readu8(buf, offset - 1)
		local opcode = bit32.bor(
			bit32.lshift(high, 16),
			bit32.lshift(mid, 8),
			low
		)
		
		local map = {
			[0x488b05] = 0x8d05, -- mov 0(%rip), %rax -> lea 0(%rip), %rax
			[0x488b0d] = 0x8d0d, -- mov 0(%rip), %rcx -> lea 0(%rip), %rcx
			[0x488b15] = 0x8d15, -- mov 0(%rip), %rdx -> lea 0(%rip), %rdx
			[0x488b1d] = 0x8d1d, -- mov 0(%rip), %rbx -> lea 0(%rip), %rbx
			[0x488b25] = 0x8d25, -- mov 0(%rip), %rsp -> lea 0(%rip), %rsp
			[0x488b2d] = 0x8d2d, -- mov 0(%rip), %rbp -> lea 0(%rip), %rbp
			[0x488b35] = 0x8d35, -- mov 0(%rip), %rsi -> lea 0(%rip), %rsi
			[0x488b3d] = 0x8d3d, -- mov 0(%rip), %rdi -> lea 0(%rip), %rdi
			[0x4c8b05] = 0x8d05, -- mov 0(%rip), %r8  -> lea 0(%rip), %r8
			[0x4c8b0d] = 0x8d0d, -- mov 0(%rip), %r9  -> lea 0(%rip), %r9
			[0x4c8b15] = 0x8d15, -- mov 0(%rip), %r10 -> lea 0(%rip), %r10
			[0x4c8b1d] = 0x8d1d, -- mov 0(%rip), %r11 -> lea 0(%rip), %r11
			[0x4c8b25] = 0x8d25, -- mov 0(%rip), %r12 -> lea 0(%rip), %r12
			[0x4c8b2d] = 0x8d2d, -- mov 0(%rip), %r13 -> lea 0(%rip), %r13
			[0x4c8b35] = 0x8d35, -- mov 0(%rip), %r14 -> lea 0(%rip), %r14
			[0x4c8b3d] = 0x8d3d  -- mov 0(%rip), %r15 -> lea 0(%rip), %r15
		}
		
		return map[opcode] or 0
	end
end

local function relax_gottpoff(loc, rel)
	if rel.r_type == "R_X86_64_GOTTPOFF" then
		local high = buf.readu8(buf, offset - 3)
		local mid = buf.readu8(buf, offset - 2)
		local low = buf.readu8(buf, offset - 1)
		local opcode = bit32.bor(
			bit32.lshift(high, 16),
			bit32.lshift(mid, 8),
			low
		)
		
		local map = {
			[0x488b05] = 0x48c7c0, -- mov 0(%rip), %rax -> mov $0, %rax
			[0x488b0d] = 0x48c7c1, -- mov 0(%rip), %rcx -> mov $0, %rcx
			[0x488b15] = 0x48c7c2, -- mov 0(%rip), %rdx -> mov $0, %rdx
			[0x488b1d] = 0x48c7c3, -- mov 0(%rip), %rbx -> mov $0, %rbx
			[0x488b25] = 0x48c7c4, -- mov 0(%rip), %rsp -> mov $0, %rsp
			[0x488b2d] = 0x48c7c5, -- mov 0(%rip), %rbp -> mov $0, %rbp
			[0x488b35] = 0x48c7c6, -- mov 0(%rip), %rsi -> mov $0, %rsi
			[0x488b3d] = 0x48c7c7, -- mov 0(%rip), %rdi -> mov $0, %rdi
			[0x4c8b05] = 0x49c7c0, -- mov 0(%rip), %r8  -> mov $0, %r8
			[0x4c8b0d] = 0x49c7c1, -- mov 0(%rip), %r9  -> mov $0, %r9
			[0x4c8b15] = 0x49c7c2, -- mov 0(%rip), %r10 -> mov $0, %r10
			[0x4c8b1d] = 0x49c7c3, -- mov 0(%rip), %r11 -> mov $0, %r11
			[0x4c8b25] = 0x49c7c4, -- mov 0(%rip), %r12 -> mov $0, %r12
			[0x4c8b2d] = 0x49c7c5, -- mov 0(%rip), %r13 -> mov $0, %r13
			[0x4c8b35] = 0x49c7c6, -- mov 0(%rip), %r14 -> mov $0, %r14
			[0x4c8b3d] = 0x49c7c7  -- mov 0(%rip), %r15 -> mov $0, %r15
		}
		
		return map[opcode] or 0
	else
		assert(
			rel.r_type == "R_X86_64_CODE_4_GOTTPOFF"
		)
		
		local high = buf.readu8(buf, offset - 3)
		local mid = buf.readu8(buf, offset - 2)
		local low = buf.readu8(buf, offset - 1)
		local opcode = bit32.bor(
			bit32.lshift(high, 16),
			bit32.lshift(mid, 8),
			low
		)
		
		local map = {
			[0x488b05] = 0x18c7c0, -- mov 0(%rip), %r16 -> mov $0, %r16
			[0x488b0d] = 0x18c7c1, -- mov 0(%rip), %r17 -> mov $0, %r17
			[0x488b15] = 0x18c7c2, -- mov 0(%rip), %r18 -> mov $0, %r18
			[0x488b1d] = 0x18c7c3, -- mov 0(%rip), %r19 -> mov $0, %r19
			[0x488b25] = 0x18c7c4, -- mov 0(%rip), %r20 -> mov $0, %r20
			[0x488b2d] = 0x18c7c5, -- mov 0(%rip), %r21 -> mov $0, %r21
			[0x488b35] = 0x18c7c6, -- mov 0(%rip), %r22 -> mov $0, %r22
			[0x488b3d] = 0x18c7c7, -- mov 0(%rip), %r23 -> mov $0, %r23
			[0x4c8b05] = 0x19c7c0, -- mov 0(%rip), %r24 -> mov $0, %r24
			[0x4c8b0d] = 0x19c7c1, -- mov 0(%rip), %r25 -> mov $0, %r25
			[0x4c8b15] = 0x19c7c2, -- mov 0(%rip), %r26 -> mov $0, %r26
			[0x4c8b1d] = 0x19c7c3, -- mov 0(%rip), %r27 -> mov $0, %r27
			[0x4c8b25] = 0x19c7c4, -- mov 0(%rip), %r28 -> mov $0, %r28
			[0x4c8b2d] = 0x19c7c5, -- mov 0(%rip), %r29 -> mov $0, %r29
			[0x4c8b35] = 0x19c7c6, -- mov 0(%rip), %r30 -> mov $0, %r30
			[0x4c8b3d] = 0x19c7c7 -- mov 0(%rip), %r31 -> mov $0, %r31
		}
		
		return map[opcode] or 0
	end
end

local function relax_tlsdesc_to_ie(loc, rel)
	if rel.r_type == "R_X86_64_GOTPC32_TLSDESC" then
		local high = buf.readu8(buf, offset - 3)
		local mid = buf.readu8(buf, offset - 2)
		local low = buf.readu8(buf, offset - 1)
		local opcode = bit32.bor(
			bit32.lshift(high, 16),
			bit32.lshift(mid, 8),
			low
		)
		
		local map = {
			[0x488d05] = 0x488b05, -- lea 0(%rip), %rax -> mov 0(%rip), %rax
			[0x488d0d] = 0x488b0d, -- lea 0(%rip), %rcx -> mov 0(%rip), %rcx
			[0x488d15] = 0x488b15, -- lea 0(%rip), %rdx -> mov 0(%rip), %rdx
			[0x488d1d] = 0x488b1d, -- lea 0(%rip), %rbx -> mov 0(%rip), %rbx
			[0x488d25] = 0x488b25, -- lea 0(%rip), %rsp -> mov 0(%rip), %rsp
			[0x488d2d] = 0x488b2d, -- lea 0(%rip), %rbp -> mov 0(%rip), %rbp
			[0x488d35] = 0x488b35, -- lea 0(%rip), %rsi -> mov 0(%rip), %rsi
			[0x488d3d] = 0x488b3d, -- lea 0(%rip), %rdi -> mov 0(%rip), %rdi
			[0x4c8d05] = 0x4c8b05, -- lea 0(%rip), %r8  -> mov 0(%rip), %r8
			[0x4c8d0d] = 0x4c8b0d, -- lea 0(%rip), %r9  -> mov 0(%rip), %r9
			[0x4c8d15] = 0x4c8b15, -- lea 0(%rip), %r10 -> mov 0(%rip), %r10
			[0x4c8d1d] = 0x4c8b1d, -- lea 0(%rip), %r11 -> mov 0(%rip), %r11
			[0x4c8d25] = 0x4c8b25, -- lea 0(%rip), %r12 -> mov 0(%rip), %r12
			[0x4c8d2d] = 0x4c8b2d, -- lea 0(%rip), %r13 -> mov 0(%rip), %r13
			[0x4c8d35] = 0x4c8b35, -- lea 0(%rip), %r14 -> mov 0(%rip), %r14
			[0x4c8d3d] = 0x4c8b3d  -- lea 0(%rip), %r15 -> mov 0(%rip), %r15
		}
		
		return map[opcode] or 0
	else
		assert(
			rel.r_type == "R_X86_64_CODE_4_GOTPC32_TLSDESC"
		)
		
		local high = buf.readu8(buf, offset - 3)
		local mid = buf.readu8(buf, offset - 2)
		local low = buf.readu8(buf, offset - 1)
		local opcode = bit32.bor(
			bit32.lshift(high, 16),
			bit32.lshift(mid, 8),
			low
		)
		
		local map = {
			[0x488d05] = 0x488b05, -- lea 0(%rip), %r16 -> mov 0(%rip), %r16
			[0x488d0d] = 0x488b0d, -- lea 0(%rip), %r17 -> mov 0(%rip), %r17
			[0x488d15] = 0x488b15, -- lea 0(%rip), %r18 -> mov 0(%rip), %r18
			[0x488d1d] = 0x488b1d, -- lea 0(%rip), %r19 -> mov 0(%rip), %r19
			[0x488d25] = 0x488b25, -- lea 0(%rip), %r20 -> mov 0(%rip), %r20
			[0x488d2d] = 0x488b2d, -- lea 0(%rip), %r21 -> mov 0(%rip), %r21
			[0x488d35] = 0x488b35, -- lea 0(%rip), %r22 -> mov 0(%rip), %r22
			[0x488d3d] = 0x488b3d, -- lea 0(%rip), %r23 -> mov 0(%rip), %r23
			[0x4c8d05] = 0x4c8b05, -- lea 0(%rip), %r24 -> mov 0(%rip), %r24
			[0x4c8d0d] = 0x4c8b0d, -- lea 0(%rip), %r25 -> mov 0(%rip), %r25
			[0x4c8d15] = 0x4c8b15, -- lea 0(%rip), %r26 -> mov 0(%rip), %r26
			[0x4c8d1d] = 0x4c8b1d, -- lea 0(%rip), %r27 -> mov 0(%rip), %r27
			[0x4c8d25] = 0x4c8b25, -- lea 0(%rip), %r28 -> mov 0(%rip), %r28
			[0x4c8d2d] = 0x4c8b2d, -- lea 0(%rip), %r29 -> mov 0(%rip), %r29
			[0x4c8d35] = 0x4c8b35, -- lea 0(%rip), %r30 -> mov 0(%rip), %r30
			[0x4c8d3d] = 0x4c8b3d  -- lea 0(%rip), %r31 -> mov 0(%rip), %r31
		}
		
		return map[opcode] or 0
	end
end
