// hook-example.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "hook-example.h"

hookEngine::hookEngine()
{
	this->lpBuffer = VirtualAlloc(NULL, HOOKED_FUNC_AMOUNT * 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	this->dwBufferUsed = 0;
}
LPVOID hookEngine::addDetour(LPVOID lpHookedFunction, DWORD dwPrologueSize, LPVOID lpHookFunc)
{
	LPVOID lpStartAddress = (LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed);
	this->dwBufferUsed += this->installCall(lpStartAddress, lpHookFunc);
	memcpy((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), lpHookedFunction, dwPrologueSize);
	this->dwBufferUsed += dwPrologueSize;
	this->dwBufferUsed += this->installJmp((LPVOID)((DWORD)this->lpBuffer + this->dwBufferUsed), (LPVOID)((DWORD)lpHookedFunction + dwPrologueSize));
	return lpStartAddress;
}
DWORD hookEngine::installCall(LPVOID lpStartAddress, LPVOID lpCallTarget)
{
	DWORD dwSizeOfGadget = 0;
	*(LPBYTE)lpStartAddress = CALL_REL_OPCODE;
	dwSizeOfGadget += sizeof(CALL_REL_OPCODE);
	*(LPDWORD)((DWORD)lpStartAddress + dwSizeOfGadget) = (DWORD)((DWORD)lpCallTarget - ((DWORD)lpStartAddress + dwSizeOfGadget + sizeof(DWORD)));
	dwSizeOfGadget += sizeof(DWORD);
	return dwSizeOfGadget;
}
DWORD hookEngine::installJmp(LPVOID lpStartAddress, LPVOID lpCallTarget)
{
	DWORD dwSizeOfGadget = 0;
	*(LPBYTE)lpStartAddress = JMP_REL_OPCODE;
	dwSizeOfGadget += sizeof(JMP_REL_OPCODE);
	*(LPDWORD)((DWORD)lpStartAddress + dwSizeOfGadget) = (DWORD)((DWORD)lpCallTarget - ((DWORD)lpStartAddress + dwSizeOfGadget + sizeof(DWORD)));
	dwSizeOfGadget += sizeof(DWORD);
	return dwSizeOfGadget;
}
BOOL hookEngine::installHook(DWORD dwPrologueSize, LPVOID lpHookedFunction, LPVOID lpDetourFunction)
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
	LPVOID lpGeneratedFunc = this->addDetour(lpHookedFunction, dwPrologueSize, lpDetourFunction);
	DWORD dwGadgetSize = installJmp(lpHookedFunction, lpGeneratedFunc);
	DWORD dwNopFill = dwPrologueSize - dwGadgetSize;
	if (dwNopFill > 0)
	{
		memset((LPVOID)((DWORD)lpHookedFunction + dwGadgetSize), NOP_OPCODE, dwNopFill);
	}
}

__declspec(naked) void msgBoxHookA()
{
	LPSTR lpText;
	LPSTR lpCaption;
	LPVOID lpStackPointer;
	__asm
	{
		mov lpStackPointer, esp
	}
	lpText = (LPSTR)*(LPDWORD)((DWORD)lpStackPointer + 12);
	lpCaption = (LPSTR)*(LPDWORD)((DWORD)lpStackPointer + 16);
	printf("MsgBoxCalled with text: %s and caption: %s\n", lpText, lpCaption);
	__asm
	{
		retn
	}
}
__declspec(naked) void virtualAllocHook()
{
	printf("VirtualAllocCalled\n");
	__asm
	{
		retn
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	hookEngine he = hookEngine();
	he.installHook(7, &MessageBoxA, msgBoxHookA);
	he.installHook(5, &VirtualAlloc, virtualAllocHook);
	MessageBoxA(NULL, "ok", "catch this", MB_OK);
	LPVOID lpVirt = VirtualAlloc(NULL, 100, MEM_COMMIT, PAGE_READWRITE);
	return 0;
}

