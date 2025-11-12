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
