.data
	SSN DWORD 0h		; Syscall Service Number
	jumpAddr QWORD 0h	; Address of Syscall instruction

.code




public SetSyscallValues
SetSyscallValues proc

	mov SSN, ecx		
	mov jumpAddr, rdx
	ret

SetSyscallValues endp




public SyscallGeneric
SyscallGeneric proc
		
		mov r10, rcx
		mov eax, SSN
		jmp qword ptr [jumpAddr]
		ret
	
SyscallGeneric endp





end
