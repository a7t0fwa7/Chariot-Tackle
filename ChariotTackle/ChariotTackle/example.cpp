#include <Windows.h>
#include "ChariotTackle.h"


CT_DECLARESYSCALL(NtAllocateVirtualMemory); //Declaring the syscalls we want to use
CT_DECLARESYSCALL(NtProtectVirtualMemory);





int main() {

	if (!GetModuleHandleW(L"NTDLL.DLL")) { //ALWAYS MAKE SURE NTDLL IS LOADED BEFORE CALLING CT_INIT!!
		LoadLibraryW(L"ntdll.dll");
	}

	
	CT_INIT(NtAllocateVirtualMemory, NtProtectVirtualMemory); //Initializing our syscalls
	

	
	PVOID baseAddress = nullptr;
	SIZE_T regionSize = 1000;
	NTSTATUS status = 0x00;
	ULONG oldProtect = NULL;






	//	-- Calling NtAllocateVirtualMemory
	
	status = ctCall(NtAllocateVirtualMemory,
		(HANDLE)-1,
		&baseAddress,
		0,
		&regionSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	
	PRINTA("NtAllocateVirtualMemory status: 0x%0.8X\n", status); //handle any errors
	if (status != ERROR_SUCCESS) {
		return -1;
	}

	PRINTA("base region at: 0x%p\n", baseAddress);
	PRINTA("region size: %d\n\n\n", regionSize);





	//	-- Calling NtProtectVirtualMemory

	status = ctCall(NtProtectVirtualMemory,
		(HANDLE)-1,
		&baseAddress,
		&regionSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtect);

	PRINTA("NtProtectVirtualMemory status: 0x%0.8X\n", status);
	if (status != ERROR_SUCCESS) {
		return -1;
	}

	PRINTA("Changed memory permissions to RWX at: 0x%p\n", baseAddress);
	PRINTA("Previous protection value: 0x%0.8X\n", oldProtect);





	//	-- Cleaning up
	ctCleanup();
	
	return 0;
}