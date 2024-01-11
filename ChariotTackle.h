#pragma once
#include <Windows.h>
#include <winternl.h>




volatile unsigned char g_SyscallOpcodeFirst = 0x16;				//16 ^ 25 = 0x0F
volatile unsigned char g_SyscallOpcodeSecond = 0x1C;				//1C ^ 25 = 0x05




extern "C" void SetSyscallValues(WORD SSN, PVOID syscallOpcodeAddress);
extern "C" NTSTATUS SyscallGeneric(...);






// ** Common ** //


INT PseudoRandomIntegerSubroutine(PULONG Context)
{
	return ((*Context = *Context * 1103515245 + 12345) % ((ULONG)0x7FFF + 1));
}

INT CreatePseudoRandomInteger(IN ULONG Seed)
{
	return (PseudoRandomIntegerSubroutine(&Seed));
}




#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  



constexpr size_t StringLengthCustomA(const char* string) {

	size_t counter = 0;
	while (*string != '\0') {

		++counter;
		++string;
	}

	return counter;
}


constexpr size_t StringLengthCustomW(const wchar_t* string) {

	size_t counter = 0;
	while (*string != L'\0') {

		++counter;
		++string;
	}

	return counter;
}










// ** Hashing ** //


constexpr int randomSeed() {

	return 0x3A * 420 +

		__TIME__[0] +
		__TIME__[1] +
		__TIME__[2] +
		__TIME__[3] +
		__TIME__[4] +
		__TIME__[5] +
		__TIME__[6] +
		__TIME__[7];
}

constexpr int hashSeed = randomSeed();








// NOTE: only one of these strings should be passed in, the other should be NULL.
// I did this because I was too fucking lazy to just make 2 seperate functions.

constexpr ULONG JenkinsHash(const char* asciiString, const wchar_t* wideString) {



	ULONG HASH = (ULONG)hashSeed;

	if ((!asciiString && !wideString) || (asciiString && wideString)) {
		return NULL;

	}



	size_t strLen = (asciiString ? StringLengthCustomA(asciiString) : StringLengthCustomW(wideString));


	for (size_t i = 0; i < strLen; i++) {

		if (asciiString) {
			if (asciiString[i] == '.') {
				break;
			}
		}

		else {
			if (wideString[i] == L'.') {
				break;
			}
		}


		asciiString ? HASH += asciiString[i] : HASH += wideString[i];
		HASH += (HASH << 10);
		HASH ^= (HASH >> 6);
	}


	HASH += (HASH << 3);
	HASH ^= (HASH >> 11);
	HASH += (HASH << 15);

	return HASH;
}




constexpr ULONG jenkinsHashSyscallWrapper(const char* name) {

	return (name[0] != 'Z' && name[0] != 'N' ? JenkinsHash(name, NULL) : JenkinsHash(&name[2], NULL));
}






#define CREATEHASHA(str) constexpr auto str##_compHashed = JenkinsHash((const char*)#str, NULL)
#define CREATEHASHW(str) constexpr auto str##_compHashed = JenkinsHash(NULL, (const wchar_t*)L#str)

CREATEHASHW(ntdll);












// ** Data Structures ** //



template <typename T>
class CustomVector {

private:
	size_t dataSize;
	T* array = nullptr;
	size_t arrayLen = 0;

public:

	size_t size() {
		return dataSize * arrayLen;
	}

	size_t length() {
		return arrayLen;
	}




	void pushBack(T newElement) {

		if (array == nullptr) {

			array = (T*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataSize);
			array[0] = newElement;
			arrayLen++;

			return;
		}

		arrayLen++;
		array = (T*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, array, dataSize * arrayLen);
		array[arrayLen - 1] = newElement;
	}


	T indexOf(size_t i) {
		return array[i];
	}



	void insertionSort() {

		if (array == nullptr || arrayLen < 2) {
			return;
		}

		size_t right = arrayLen - 1;
		T temp;

		for (size_t i = 1; i <= right; i++) {

			for (size_t j = i; j >= 1; j--) {

				if (array[j] < array[j - 1]) {

					temp = array[j - 1];
					array[j - 1] = array[j];
					array[j] = temp;

				}
			}
		}

	}


	void manualDelete() {
		if (array != nullptr) {
			HeapFree(GetProcessHeap(), 0, array);
		}
	}


	CustomVector(size_t typeSize) : dataSize(typeSize) {}


	//Deconstructors use CRT lib
	/*
	~customVector() {

		if (array != nullptr) {
			HeapFree(GetProcessHeap(), 0, array);
		}
	}
	*/
};
















typedef struct _TREENODE {

	ULONG hashVal = NULL;
	WORD SSN = NULL;
	PVOID ZwAddress = nullptr;

	_TREENODE* right = nullptr;
	_TREENODE* left = nullptr;

}TREENODE, * PTREENODE;



class SyscallTree {

private:
	TREENODE Head;
	CustomVector<PTREENODE> nodesToFree;



	void inOrderTraversal() {

		if (Head.hashVal == NULL) {
			return;
		}


		HANDLE hHeap = GetProcessHeap();
		PTREENODE itr = &Head;
		PTREENODE* stack = nullptr;
		size_t stackSize = 0;

		
		while (itr != nullptr || stackSize > 0) {

			while (itr != nullptr) {

				stackSize++;
				if (stack == nullptr) {
					stack = (PTREENODE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(PTREENODE));
				
				}
				else {
					stack = (PTREENODE*)HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, stack, stackSize * sizeof(PTREENODE));
				}


				if (stack == nullptr) {
					return;
				}

				stack[stackSize - 1] = itr;
				itr = itr->left;
			}


			itr = (PTREENODE)(stack[stackSize - 1]);

			PRINTA("%ul\n", itr->hashVal);

			itr = itr->right; //check right subtree

			stackSize--;
			stack = (PTREENODE*)HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, stack, stackSize * sizeof(PTREENODE)); //Decrease stack size after pop
		}

	}




public:


	bool isEmpty() {
		return (Head.hashVal == NULL);
	}



	bool insertNewNode(ULONG hash) {

		if (Head.hashVal == NULL) {
			Head.hashVal = hash;
			return true;
		}


		PTREENODE itr = &Head;
		PTREENODE newNode = (PTREENODE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TREENODE));
		if (!newNode) {
			return false;
		}


		newNode->left = nullptr;
		newNode->right = nullptr;
		newNode->hashVal = hash;



		while (itr != nullptr) {

			if (hash == itr->hashVal) { //possible hash collision or duplicate node
				break;
			}


			if (hash > itr->hashVal && itr->right == nullptr) {
				itr->right = newNode;
				nodesToFree.pushBack(newNode);
				return true;
			}


			if (hash < itr->hashVal && itr->left == nullptr) {
				itr->left = newNode;
				nodesToFree.pushBack(newNode);
				return true;
			}


			itr = (hash > itr->hashVal ? itr->right : itr->left);
		}


		HeapFree(GetProcessHeap(), 0, newNode);
	}





	bool retrieveMembers(IN ULONG hash, OUT OPTIONAL WORD* SSN, OUT OPTIONAL PVOID* ZwAddress) {

		if (Head.hashVal == NULL) {
			return false;
		}

		PTREENODE itr = &Head;


		while (itr != nullptr) {

			if (itr->hashVal == hash) {

				if (SSN) {
					*SSN = itr->SSN;
				}

				if (ZwAddress) {
					*ZwAddress = itr->ZwAddress;
				}

				return true;
			}


			itr = (hash > itr->hashVal ? itr->right : itr->left);
		}

		return false;
	}





	bool insertMembers(IN ULONG hash, IN OPTIONAL WORD SSN, IN OPTIONAL PVOID ZwAddress) {

		if (Head.hashVal == NULL) {
			return false;
		}

		PTREENODE itr = &Head;


		while (itr != nullptr) {

			if (itr->hashVal == hash) {

				if (SSN) {
					itr->SSN = SSN;
				}

				if (ZwAddress != nullptr) {
					itr->ZwAddress = ZwAddress;
				}

				return true;
			}


			itr = (hash > itr->hashVal ? itr->right : itr->left);
		}

		return false;
	}




	//this must be called manually since deconstructors use parts of the CRT lib
	void freeAllNodes() {
		
		for (size_t i = 0; i < nodesToFree.length(); i++) {
			HeapFree(GetProcessHeap(), 0, nodesToFree.indexOf(i));
		}
		nodesToFree.manualDelete();
	}

	void printAllNodes() {
		inOrderTraversal();
	}

	SyscallTree() : nodesToFree(sizeof(PTREENODE)) {}
};










class NTDLL {

private:

	HMODULE hTargetMod = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = nullptr;
	ULONG randomIntegerSeed = 4;
	bool initStatus = false;



	bool resolveDLL(ULONG dllHash) {
		
		PPEB pPeb = (PPEB)__readgsqword(0x60);
		PBYTE dllBase = NULL;
		


		PLDR_DATA_TABLE_ENTRY pDataEntry = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);
		PLIST_ENTRY pListHead = (PLIST_ENTRY)(&(pPeb->Ldr->InMemoryOrderModuleList));
		PLIST_ENTRY nodeItr = (PLIST_ENTRY)(pListHead->Flink);

		

		do {

			if (pDataEntry->FullDllName.Length) {

				if (dllHash == JenkinsHash(NULL, pDataEntry->FullDllName.Buffer)) {

					dllBase = (PBYTE)(pDataEntry->Reserved2[0]); //module base address
					break;
				}
			}

			pDataEntry = (PLDR_DATA_TABLE_ENTRY)(nodeItr->Flink);
			nodeItr = (PLIST_ENTRY)(nodeItr->Flink);

		} while (nodeItr != pListHead);



		if (dllBase == NULL) {
			return false;
		}

		hTargetMod = (HMODULE)dllBase; //set private member




		//Get the export directory of the module
		PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)dllBase;
		PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(dllBase + (pImgDosHdr->e_lfanew));
		PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + (pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

		if (pImgExportDir == nullptr) {
			return false;
		}

		this->pImgExportDir = pImgExportDir;

		return true;
	}





public:


	bool resolveNTDLLStubAddresses(SyscallTree& syscallTree, CustomVector<PVOID>& ZwAddresses, CustomVector<PVOID>& NtAddresses) {

		if (!hTargetMod || !pImgExportDir || syscallTree.isEmpty()) {
			return false;
		}

		PBYTE pBase = (PBYTE)hTargetMod;


		PDWORD funcAddresses = (PDWORD)(pBase + (pImgExportDir->AddressOfFunctions));
		PDWORD funcNames = (PDWORD)(pBase + (pImgExportDir->AddressOfNames));
		PWORD funcOrdinals = (PWORD)(pBase + (pImgExportDir->AddressOfNameOrdinals));




		for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

			char* pName = (char*)(pBase + funcNames[i]);
			PVOID fnAddress = (PVOID)(pBase + funcAddresses[funcOrdinals[i]]);



			if (pName[0] == 'Z') {

				ZwAddresses.pushBack(fnAddress);
				syscallTree.insertMembers(JenkinsHash(&pName[2], NULL), NULL, fnAddress); //check if we can insert current function
			}



			if (pName[0] == 'N' && pName[1] == 't' && NtAddresses.length() < 30) {
				NtAddresses.pushBack(fnAddress);
			}
		}


		ZwAddresses.insertionSort(); //Sort Zw functions by address

		this->initStatus = true;
		return true;
	}





	//Zw addresses must be sorted at this point for this to work
	WORD getSSNFromAddress(CustomVector<PVOID>& sortedZwAddresses, PVOID targetAddress) {

		if (targetAddress == NULL || sortedZwAddresses.length() < 5) {
			return NULL;
		}

		for (size_t i = 0; i < sortedZwAddresses.length(); i++) {
			if (sortedZwAddresses.indexOf(i) == targetAddress) {
				return i;
			}
		}

		return NULL;
	}






	PBYTE getRandomSyscallOpcode(CustomVector<PVOID>& randomNtAddresses) {

		if (randomNtAddresses.length() < 30) {
			return NULL;
		}

		ULONG randomIndex = (ULONG)((CreatePseudoRandomInteger(randomIntegerSeed) + 0x3A) % 30);
		PBYTE funcAddress = (PBYTE)(randomNtAddresses.indexOf(randomIndex));
		randomIntegerSeed += 2;


		while (*funcAddress != 0xC3) {


			// Use XOR with "volatile" bytes to keep syscall opcodes _Out_ of the binary
			if ((g_SyscallOpcodeFirst ^ 25) == *funcAddress && (g_SyscallOpcodeSecond ^ 25) == *(funcAddress + 1)) {

				return funcAddress;
			}

			funcAddress++;
		}

		return NULL;
	}





	PVOID _GetProcAddress(ULONG functionHash) {

		if (hTargetMod == NULL || pImgExportDir == nullptr) {
			return nullptr;
		}


		PBYTE pBase = (PBYTE)hTargetMod;


		PDWORD funcAddresses = (PDWORD)(pBase + (pImgExportDir->AddressOfFunctions));
		PDWORD funcNames = (PDWORD)(pBase + (pImgExportDir->AddressOfNames));
		PWORD funcOrdinals = (PWORD)(pBase + (pImgExportDir->AddressOfNameOrdinals));



		for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

			char* pName = (char*)(pBase + funcNames[i]);
			PVOID fnAddress = (PVOID)(pBase + funcAddresses[funcOrdinals[i]]);


			if (functionHash == JenkinsHash(pName, NULL)) {
				return fnAddress;
			}

		}

		return nullptr;
	}




	HMODULE getTargetModule() {
		return hTargetMod;
	}


	bool status() {
		return this->initStatus;
	}


	NTDLL(ULONG targetDLLHash) {

		if (!resolveDLL(targetDLLHash)) {
			PRINTA("FAILED TO GET NTDLL!\n");
		}
		
	}
};












// ** Initialization ** //

NTDLL				g_NtdllObject = NULL;
CustomVector<PVOID> g_ZwAddresses = NULL;
CustomVector<PVOID> g_NtAddresses = NULL;
SyscallTree			g_SyscallTree;






template<typename... Args> NTSTATUS ctCall(ULONG syscallName, Args... args) {

	WORD SSN = NULL;
	PVOID jumpAddr = nullptr;
	NTSTATUS STATUS = 0x00;
	PVOID funcAddress = nullptr;

	
	if (g_NtdllObject.status() == false) {

		g_NtdllObject.resolveNTDLLStubAddresses(g_SyscallTree, g_ZwAddresses, g_NtAddresses);
	}


	g_SyscallTree.retrieveMembers(syscallName, &SSN, NULL);
	if (SSN == NULL) {

		g_SyscallTree.retrieveMembers(syscallName, NULL, &funcAddress);
		SSN = g_NtdllObject.getSSNFromAddress(g_ZwAddresses, funcAddress);
		g_SyscallTree.insertMembers(syscallName, SSN, nullptr);
	}



	SetSyscallValues(SSN, g_NtdllObject.getRandomSyscallOpcode(g_NtAddresses));
	STATUS = SyscallGeneric(args...);

	return STATUS;
}






#define CT_DECLARESYSCALL(syscallName) constexpr auto syscallName = jenkinsHashSyscallWrapper((const char*)#syscallName)



//
// Note: This shit is unfathomably horrible. I want to bleach my eyes looking at this abomination.
// But I need to initialize these global objects like this,
// because if I don't, everything becomes fucked. Why? Idk. fml.
//

#define CT_INIT(...)														\
	NTDLL ntdllobj(ntdll_compHashed);										\
	g_NtdllObject = ntdllobj;												\
	CustomVector<PVOID> ntaddresses(sizeof(PVOID));							\
	g_NtAddresses = ntaddresses;											\
	CustomVector<PVOID> zwaddresses(sizeof(PVOID));							\
	g_ZwAddresses = zwaddresses;											\
do {																						\
	ULONG args[] = {__VA_ARGS__, 0};														\
																							\
	for(size_t i = 0; args[i] != 0; i++){													\
		g_SyscallTree.insertNewNode((ULONG)args[i]);										\
	}																						\
}while(0)\








// ** Cleanup ** //

void ctCleanup() {
	g_SyscallTree.freeAllNodes();
	g_NtAddresses.manualDelete();
	g_ZwAddresses.manualDelete();
}
