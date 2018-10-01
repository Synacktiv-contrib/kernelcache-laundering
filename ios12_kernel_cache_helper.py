# Copyright (c) 2018, Eloi Benoist-Vanderbeken - Synacktiv
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Synacktiv nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import idaapi

def fix_relocs(base_address, relocs_address, relocs_size):
	cursor = relocs_address
	end = relocs_address+relocs_size

	multiplier = 4 * (idaapi.get_dword(cursor) & 1) + 4
	cursor += 4
	
	print 'starting to fix relocs...'
	nb_relocs = 0

	delta = idaapi.get_dword(cursor)
	while delta != 0xFFFFFFFF and cursor < end:
		current_reloc = base_address + delta
		while True:
			decorated_addr = idaapi.get_qword(current_reloc)
			if decorated_addr & 0x4000000000000000 == 0:
				if decorated_addr & 0x8000000000000000:
					#tagged ptr
					sign_type = (decorated_addr >> 49) & 3
					real_addr = base_address + (decorated_addr & 0xFFFFFFFF)
					modifier = ((decorated_addr >> 32) & 0xFFFF)
					if decorated_addr & 0x1000000000000:
						if modifier == 0:
							modifier = current_reloc
							modifier_type = 'ptr_addr'
						else:
							modifier_type = '0x%X << 48 | ptr_addr & 0xFFFFFFFFFFFF'%(modifier)
							modifier = (current_reloc & 0xFFFFFFFFFFFF) | (modifier << 48)
					else:
						modifier_type = '0x%X'%modifier
					if sign_type == 0:
						decorator = 'PACIA %s'%modifier_type if modifier else 'PACIZA'
					elif sign_type == 1:
						decorator = 'PACIB %s'%modifier_type if modifier else 'PACIZB'
					elif sign_type == 2:
						decorator = 'PACDA %s'%modifier_type if modifier else 'PACDZA'
					elif sign_type == 3:
						decorator = 'PACDB %s'%modifier_type if modifier else 'PACDZB'
					idaapi.set_cmt(current_reloc , decorator, 1)
				else:
					real_addr = ((decorated_addr << 13) & 0xFF00000000000000) | (decorated_addr & 0x7ffffffffff)
					if decorated_addr & 0x40000000000:
						real_addr |= 0xfffc0000000000
				idaapi.patch_qword(current_reloc, real_addr)
				idaapi.op_offset(current_reloc, 0, idaapi.REF_OFF64)
				nb_relocs += 1
			delta_next_reloc = ((decorated_addr >> 51) & 0x7ff) * multiplier
			if delta_next_reloc == 0:
				break
			current_reloc += delta_next_reloc
		cursor += 4
		delta = idaapi.get_dword(cursor)
	print '%d relocs fixed!'%nb_relocs

def is_iOS_12(mach_header):
	if idaapi.get_dword(mach_header) != 0xFEEDFACF:
		return False
	nb_load_commands = idaapi.get_dword(mach_header + 0x10)
	if nb_load_commands > 100: #arbitrary limit
		return False
	sizeof_load_commands = idaapi.get_dword(mach_header + 0x14)
	if sizeof_load_commands > 0x2000: #arbitrary limit
		return False
	load_command_limit = mach_header + 0x20 + sizeof_load_commands
	current_load_command = mach_header + 0x20
	for i in xrange(nb_load_commands):
		if current_load_command + 8 > load_command_limit:
			return False
		cmd = idaapi.get_dword(current_load_command)
		cmdsize = idaapi.get_dword(current_load_command+4)
		if cmdsize < 8 or current_load_command + cmdsize > load_command_limit:
			return False
		if cmd == 0x32: # LC_BUILD_VERSION
			platform = idaapi.get_dword(current_load_command+8)
			if platform != 2: # PLATFORM_IOS
				return False
			minos = idaapi.get_dword(current_load_command+8+4)
			if minos >> 16 != 12: # 12.X.X
				return False
			sdk = idaapi.get_dword(current_load_command+8+8)
			ntools = idaapi.get_dword(current_load_command+8+12)
			return True
		current_load_command += cmdsize
	else:
		return False

class IDBHook(idaapi.IDB_Hooks):
	is_iOS12 = False
	is_kernelcache = False
	relocs_address = None
	def segm_added(self, segm):
		if idaapi.get_segm_name(segm) == 'HEADER':
			self.base_address = segm.startEA
			self.is_iOS12 = is_iOS_12(self.base_address)
		if idaapi.get_segm_name(segm) == '__thread_starts':
			self.relocs_address = segm.startEA
			self.relocs_size = segm.endEA-segm.startEA
		if idaapi.get_segm_name(segm) == '__kmod_info':
			self.is_kernelcache = True
			if self.is_iOS12 and self.relocs_address is not None:
				print 'iOS12 kernelcache detected!'
				print 'let\'s fix relocs'
				fix_relocs(self.base_address, self.relocs_address, self.relocs_size)
		return 0


class IOS12KernelcacheHelper(idaapi.plugin_t):
	flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MOD
	wanted_name = 'iOS12 kernelcache helper'
	comment = "iOS12 kernelcache helper - (C) Synacktiv"
	wanted_hotkey = ""
	help = "Runs transparently"

	def init(self):
		if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.cvar.inf.filetype != idaapi.f_MACHO:
			return idaapi.PLUGIN_SKIP
		self.idbhook = IDBHook()
		self.idbhook.hook()
		print self.comment
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		pass

	def term(self):
		if self.idbhook:
			self.idbhook.unhook()

def PLUGIN_ENTRY():
	return IOS12KernelcacheHelper()