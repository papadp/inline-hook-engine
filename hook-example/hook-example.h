#include "Windows.h"

#define HOOKED_FUNC_AMOUNT	2
#define PUSH_OPCODE			(BYTE)0x68
#define RET_OPCODE			(BYTE)0xC3
#define NOP_OPCODE			(BYTE)0x90
#define CALL_REL_OPCODE		(BYTE)0xE8
#define JMP_REL_OPCODE		(BYTE)0xE9

typedef struct hookEngine
{
	hookEngine();
	LPVOID addDetour(LPVOID lpHookedFunction, DWORD dwPrologueSize, LPVOID lpHookFunc);
	BOOL installHook(DWORD dwPrologueSize, LPVOID lpHookedFunction, LPVOID lpDetourFunction, _Out_ LPVOID* lpRealFunction);
	DWORD installCall(LPVOID lpStartAddress, LPVOID lpCallTarget);
	DWORD installJmp(LPVOID lpStartAddress, LPVOID lpCallTarget);
	LPVOID lpBuffer;
	DWORD dwBufferUsed;

}*phookEngine;
typedef struct functionHook
{
	LPVOID lpHookedFunction;
	LPVOID lpHookingFunction;
	LPVOID lpDetourFunction;
	DWORD dwPrologueSize;
}*pfunctionHook;
