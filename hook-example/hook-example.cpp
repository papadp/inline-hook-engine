// hook-example.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "hook-example.h"

//function typedefs
typedef DWORD (*messageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

//function pointer globals
messageBoxA lpMessageBoxA;

hookEngine::hookEngine()
{
	this->lpBuffer = VirtualAlloc(NULL, HOOKED_FUNC_AMOUNT * 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	this->dwBufferUsed = 0;
}
LPVOID hookEngine::addDetour(LPVOID lpHookedFunction, DWORD dwPrologueSize, LPVOID lpHookFunc)
{
	LPVOID lpStartAddress = (LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed);
	memcpy((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), lpHookedFunction, dwPrologueSize);
	this->dwBufferUsed += dwPrologueSize;
	
	this->dwBufferUsed += this->installJmp((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), (LPVOID)((DWORD)lpHookedFunction + dwPrologueSize));
	//memcpy((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), lpHookedFunction, dwPrologueSize);
	//this->dwBufferUsed += dwPrologueSize;
	//this->dwBufferUsed += this->installJmp((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), (LPVOID)((DWORD)lpHookedFunction + dwPrologueSize));
	return lpStartAddress;
}
DWORD hookEngine::installCall(LPVOID lpStartAddress, LPVOID lpCallTarget)
{
	DWORD dwSizeOfGadget = 0;
	*(LPBYTE)lpStartAddress = (BYTE)CALL_REL_OPCODE;
	dwSizeOfGadget += sizeof((BYTE)CALL_REL_OPCODE);
	*(LPDWORD)((DWORD)lpStartAddress + dwSizeOfGadget) = (DWORD)((DWORD)lpCallTarget - ((DWORD)lpStartAddress + dwSizeOfGadget + sizeof(DWORD)));
	dwSizeOfGadget += sizeof(DWORD);
	return dwSizeOfGadget;
}
DWORD hookEngine::installJmp(LPVOID lpStartAddress, LPVOID lpCallTarget)
{
	DWORD dwSizeOfGadget = 0;
	*(LPBYTE)lpStartAddress = (BYTE)JMP_REL_OPCODE;
	dwSizeOfGadget += sizeof((BYTE)JMP_REL_OPCODE);
	*(LPDWORD)((DWORD)lpStartAddress + dwSizeOfGadget) = (DWORD)((DWORD)lpCallTarget - ((DWORD)lpStartAddress + dwSizeOfGadget + sizeof(DWORD)));
	dwSizeOfGadget += sizeof(DWORD);
	return dwSizeOfGadget;
}
BOOL hookEngine::installHook(DWORD dwPrologueSize, LPVOID lpHookedFunction, LPVOID lpDetourFunction, _Out_ LPVOID* lpRealFunction)
{
	DWORD dwOldProtect;
	if (!VirtualProtect(lpHookedFunction, dwPrologueSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		return false;
	}
	if (!VirtualProtect(lpDetourFunction, dwPrologueSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		return false;
	}
	*lpRealFunction = (LPVOID)this->addDetour(lpHookedFunction, dwPrologueSize, lpDetourFunction);
	DWORD dwGadgetSize = installJmp(lpHookedFunction, lpDetourFunction);
	DWORD dwNopFill = dwPrologueSize - dwGadgetSize;
	//LPVOID lpJ
	if (dwNopFill > 0)
	{
		memset((LPVOID)((DWORD)lpHookedFunction + dwGadgetSize), NOP_OPCODE, dwNopFill);
	}
	FlushInstructionCache((HANDLE)-1, lpHookedFunction, dwPrologueSize + dwNopFill);
}

int myMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	if (strcmp(lpText, "ok") == 0)
	{
		lpText = "CHANGED INPUT";
	}
	DWORD dwReturnValue = lpMessageBoxA(hWnd, lpText, lpCaption, uType);

	return dwReturnValue;
}

// change the hook installment to take an additional parameter which would specify what pointer to call from the detour function (_Out_)

int _tmain(int argc, _TCHAR* argv[])
{
	hookEngine he = hookEngine();
	he.installHook(7, &MessageBoxA, myMessageBoxA, (LPVOID*)&lpMessageBoxA);
	//he.installHook(5, &VirtualAlloc, virtualAllocHook);
	MessageBoxA(NULL, "ok", "catch this", MB_OK);
	LPVOID lpVirt = VirtualAlloc(NULL, 100, MEM_COMMIT, PAGE_READWRITE);
	return 0;
}

