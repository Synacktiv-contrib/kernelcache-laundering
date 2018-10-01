# AArch64 8.3-A Pointer Authentication extension
# Enhanced and Python version of xerub C++ plugin available there: https://github.com/xerub/idastuff/blob/master/arm64/aarch64_pac

# Copyright (c) 2018 Eloi Benoist-Vanderbeken - Synacktiv
# Copyright (c) 2018 xerub

# This program is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License version 
# 2 as published by the Free Software Foundation. 

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idaapi
import ida_hexrays

PAC_NONE = 0
PAC_PACIASP = PAC_NONE + 1
PAC_PACIBSP = PAC_PACIASP + 1
PAC_AUTIASP = PAC_PACIBSP + 1
PAC_AUTIBSP = PAC_AUTIASP + 1
PAC_PACIAZ = PAC_AUTIBSP + 1
PAC_PACIBZ = PAC_PACIAZ + 1
PAC_AUTIAZ = PAC_PACIBZ + 1
PAC_AUTIBZ = PAC_AUTIAZ + 1
PAC_PACIA1716 = PAC_AUTIBZ + 1
PAC_PACIB1716 = PAC_PACIA1716 + 1
PAC_AUTIA1716 = PAC_PACIB1716 + 1
PAC_AUTIB1716 = PAC_AUTIA1716 + 1
PAC_PACIA = PAC_AUTIB1716 + 1
PAC_PACIB = PAC_PACIA + 1
PAC_PACDA = PAC_PACIB + 1
PAC_PACDB = PAC_PACDA + 1
PAC_AUTIA = PAC_PACDB + 1
PAC_AUTIB = PAC_AUTIA + 1
PAC_AUTDA = PAC_AUTIB + 1
PAC_AUTDB = PAC_AUTDA + 1
PAC_PACIZA = PAC_AUTDB + 1
PAC_PACIZB = PAC_PACIZA + 1
PAC_PACDZA = PAC_PACIZB + 1
PAC_PACDZB = PAC_PACDZA + 1
PAC_AUTIZA = PAC_PACDZB + 1
PAC_AUTIZB = PAC_AUTIZA + 1
PAC_AUTDZA = PAC_AUTIZB + 1
PAC_AUTDZB = PAC_AUTDZA + 1
PAC_PACGA = PAC_AUTDZB + 1
PAC_XPACLRI = PAC_PACGA + 1
PAC_XPACI = PAC_XPACLRI + 1
PAC_XPACD = PAC_XPACI + 1
PAC_RETAA = PAC_XPACD + 1
PAC_RETAB = PAC_RETAA + 1
PAC_BRAA = PAC_RETAB + 1
PAC_BRAB = PAC_BRAA + 1
PAC_BRAAZ = PAC_BRAB + 1
PAC_BRABZ = PAC_BRAAZ + 1
PAC_BLRAA = PAC_BRABZ + 1
PAC_BLRAB = PAC_BLRAA + 1
PAC_BLRAAZ = PAC_BLRAB + 1
PAC_BLRABZ = PAC_BLRAAZ + 1
PAC_ERETAA = PAC_BLRABZ + 1
PAC_ERETAB = PAC_ERETAA + 1
PAC_LDRAA = PAC_ERETAB + 1
PAC_LDRAB = PAC_LDRAA + 1

OP_NAMES = {
	PAC_PACIASP: "PACIASP",
	PAC_PACIBSP: "PACIBSP",
	PAC_AUTIASP: "AUTIASP",
	PAC_AUTIBSP: "AUTIBSP",
	PAC_PACIAZ: "PACIAZ",
	PAC_PACIBZ: "PACIBZ",
	PAC_AUTIAZ: "AUTIAZ",
	PAC_AUTIBZ: "AUTIBZ",
	PAC_PACIA1716: "PACIA1716",
	PAC_PACIB1716: "PACIB1716",
	PAC_AUTIA1716: "AUTIA1716",
	PAC_AUTIB1716: "AUTIB1716",
	PAC_PACIA: "PACIA",
	PAC_PACIB: "PACIB",
	PAC_PACDA: "PACDA",
	PAC_PACDB: "PACDB",
	PAC_AUTIA: "AUTIA",
	PAC_AUTIB: "AUTIB",
	PAC_AUTDA: "AUTDA",
	PAC_AUTDB: "AUTDB",
	PAC_PACIZA: "PACIZA",
	PAC_PACIZB: "PACIZB",
	PAC_PACDZA: "PACDZA",
	PAC_PACDZB: "PACDZB",
	PAC_AUTIZA: "AUTIZA",
	PAC_AUTIZB: "AUTIZB",
	PAC_AUTDZA: "AUTDZA",
	PAC_AUTDZB: "AUTDZB",
	PAC_PACGA: "PACGA",
	PAC_XPACLRI: "XPACLRI",
	PAC_XPACI: "XPACI",
	PAC_XPACD: "XPACD",
	PAC_RETAA: "RETAA",
	PAC_RETAB: "RETAB",
	PAC_BRAA: "BRAA",
	PAC_BRAB: "BRAB",
	PAC_BRAAZ: "BRAAZ",
	PAC_BRABZ: "BRABZ",
	PAC_BLRAA: "BLRAA",
	PAC_BLRAB: "BLRAB",
	PAC_BLRAAZ: "BLRAAZ",
	PAC_BLRABZ: "BLRABZ",
	PAC_ERETAA: "ERETAA",
	PAC_ERETAB: "ERETAB",
	PAC_LDRAA: "LDRAA",
	PAC_LDRAB: "LDRAB"
}

def decode_PAC(d, insn):
	if (d & 0xffffc000) == 0xdac10000: 
		m = (d >> 10) & 7
		Z = (d >> 13) & 1
		Xn = (d >> 5) & 0x1F
		Xd = d & 0x1F
		if Z == 0: 
			insn.itype = idaapi.ARM_hlt
			insn.segpref = 14
			insn.Op1.type = idaapi.o_reg
			insn.Op1.reg = Xd + 129
			insn.Op1.dtype = idaapi.dt_qword
			insn.Op3.type = idaapi.o_reg
			insn.Op3.reg = Xd + 129
			insn.Op3.dtype = idaapi.dt_qword
			insn.Op3.flags = 0
			insn.Op2.type = idaapi.o_reg
			insn.Op2.reg = Xn + 129
			insn.Op2.dtype = idaapi.dt_qword
			insn.Op2.flags = idaapi.OF_SHOW
			insn.insnpref = PAC_PACIA + m
			insn.size = 4
			return True
		elif Xn == 31: 
			insn.itype = idaapi.ARM_hlt
			insn.segpref = 14
			insn.Op1.type = idaapi.o_reg
			insn.Op1.reg = Xd + 129
			insn.Op1.dtype = idaapi.dt_qword
			insn.Op3.type = idaapi.o_reg
			insn.Op3.reg = Xd + 129
			insn.Op3.dtype = idaapi.dt_qword
			insn.Op3.flags = 0
			insn.insnpref = PAC_PACIZA + m
			insn.size = 4
			return True
	if (d & 0xfffffd1f) == 0xd503211f: 
		m = (d >> 6) & 3
		CRm = (d >> 9) & 1
		op2 = (d >> 5) & 1
		if CRm == 0: 
			insn.itype = idaapi.ARM_hlt
			insn.segpref = 14
			insn.Op1.type = idaapi.o_void
			insn.insnpref = PAC_PACIA1716 + m
		elif op2: 
			insn.itype = idaapi.ARM_hlt
			insn.segpref = 14
			insn.Op1.type = idaapi.o_void
			insn.insnpref = PAC_PACIASP + m
		else:
			insn.itype = idaapi.ARM_hlt
			insn.segpref = 14
			insn.Op1.type = idaapi.o_void
			insn.insnpref = PAC_PACIAZ + m
		insn.size = 4
		return True
	if (d & 0xffe0fc00) == 0x9ac03000: 
		Xm = (d >> 16) & 0x1F
		Xn = (d >> 5) & 0x1F
		Xd = d & 0x1F
		insn.itype = idaapi.ARM_hlt
		insn.segpref = 14
		insn.Op1.type = idaapi.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = idaapi.dt_qword
		insn.Op2.type = idaapi.o_reg
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = idaapi.dt_qword
		insn.Op3.type = idaapi.o_reg
		insn.Op3.reg = Xm + 129
		insn.Op3.dtype = idaapi.dt_qword
		insn.insnpref = PAC_PACGA
		insn.size = 4
		return True
	if (d & 0xfffffbe0) == 0xdac143e0: 
		D = (d >> 10) & 1
		Xd = d & 0x1F
		insn.itype = idaapi.ARM_hlt
		insn.segpref = 14
		insn.Op1.type = idaapi.o_reg
		insn.Op1.reg = Xd + 129
		insn.Op1.dtype = idaapi.dt_qword
		insn.Op3.type = idaapi.o_reg
		insn.Op3.reg = Xd + 129
		insn.Op3.dtype = idaapi.dt_qword
		insn.Op3.flags = 0
		insn.insnpref = PAC_XPACI + D
		insn.size = 4
		return True
	if d == 0xd50320ff: 
		insn.itype = idaapi.ARM_hlt
		insn.segpref = 14
		insn.Op1.type = idaapi.o_void
		insn.insnpref = PAC_XPACLRI
		insn.size = 4
		return True
	if (d & 0xfffffbff) == 0xd65f0bff: 
		M = (d >> 10) & 1
		insn.insnpref = PAC_RETAA + M
		insn.itype = idaapi.ARM_ret
		insn.segpref = 14
		insn.Op1.type = idaapi.o_reg
		insn.Op1.reg = 30 + 129
		insn.Op1.dtype = idaapi.dt_qword
		insn.Op1.flags = 0
		insn.size = 4
		return True
	if (d & 0xfedff800) == 0xd61f0800: 
		is_blr = (d >> 19) & 4
		Z = (d >> 24) & 1
		M = (d >> 10) & 1
		Xn = (d >> 5) & 0x1F
		Xm = d & 0x1F
		if Z == 0 and Xm == 31: 
			insn.itype =  idaapi.ARM_blr if is_blr else idaapi.ARM_br
			insn.segpref = 14
			insn.Op1.type = idaapi.o_reg
			insn.Op1.reg = Xn + 129
			insn.Op1.dtype = idaapi.dt_qword
			insn.insnpref = PAC_BRAAZ + M + is_blr
			insn.size = 4
			return True
		elif Z: 
			insn.itype = idaapi.ARM_blr if is_blr else idaapi.ARM_br
			insn.segpref = 14
			insn.Op1.type = idaapi.o_reg
			insn.Op1.reg = Xn + 129
			insn.Op1.dtype = idaapi.dt_qword
			insn.Op2.type = idaapi.o_reg
			insn.Op2.reg = Xm + 129
			insn.Op2.dtype = idaapi.dt_qword
			insn.Op2.flags = idaapi.OF_SHOW
			insn.insnpref = PAC_BRAA + M + is_blr
			insn.size = 4
			return True
	if (d & 0xfffffbff) == 0xd69f0bff: 
		M = (d >> 10) & 1
		insn.insnpref = PAC_ERETAA + M
		insn.itype = idaapi.ARM_eret
		insn.segpref = 14
		insn.size = 4
		return True
	if (d & 0xff200400) == 0xf8200400: 
		M = (d >> 23) & 1
		imm10 = ((d & 0x400000) << 9) | ((d & 0x1ff000) << 10)
		offset = imm10 >> 19
		W = (d >> 11) & 1
		Xn = (d >> 5) & 0x1F
		Xt = d & 0x1F
		insn.itype = idaapi.ARM_ldr
		insn.segpref = 14
		insn.Op1.type = idaapi.o_reg
		insn.Op1.reg = Xt + 129
		insn.Op1.dtype = idaapi.dt_qword
		insn.Op2.type = idaapi.o_displ
		insn.Op2.reg = Xn + 129
		insn.Op2.dtype = idaapi.dt_qword
		insn.Op2.addr = offset
		if W != 0: 
			insn.auxpref = 0x20
		insn.insnpref = PAC_LDRAA + M
		insn.size = 4
		return True
	return False

class Aarch64PACHook(idaapi.IDP_Hooks):
	CUSTOM_INSTRUCTIONS = {idaapi.ARM_hlt, idaapi.ARM_ret, idaapi.ARM_blr, idaapi.ARM_br, idaapi.ARM_eret,idaapi.ARM_ldr}
	indent = 16
	def ev_ana_insn(self, outctx):
		return outctx.size if decode_PAC(idaapi.get_dword(outctx.ea), outctx) else 0

	def ev_emu_insn(self, insn):
		if insn.itype != idaapi.ARM_brk:
			return False
		return True

	def ev_out_mnem(self, outctx):
		if outctx.insn.itype in self.CUSTOM_INSTRUCTIONS:
			mnem = OP_NAMES.get(ord(outctx.insn.insnpref), None)
			if mnem is not None:
				if not idaapi.get_inf_structure().is_graph_view():
					self.indent = idaapi.get_inf_structure().indent
				outctx.out_custom_mnem(mnem, self.indent)
				return 1
		return 0

class Aarch64PACPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
	comment = "ARM v8.3-A Pointer Authentication extension"
	wanted_hotkey = ""
	help = "Runs transparently"
	wanted_name = "Aarch64 PAC"
	hook = None
	enabled = 1

	def init(self):
		if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.BADADDR <= 0xFFFFFFFF:
			return idaapi.PLUGIN_SKIP
		print "%s init"%self.comment
		self.hook = Aarch64PACHook()
		self.hook.hook()
		return idaapi.PLUGIN_KEEP

	def run():
		pass

	def term(self):
		if self.hook is not None:
			self.hook.unhook()
		print "%s unloaded"%self.comment

def PLUGIN_ENTRY():
	return Aarch64PACPlugin()
