#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <stdio.h>
#include <stddef.h>
typedef LONG(WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE, UINT, PVOID, ULONG, PULONG);
PNTQUERYINFORMATIONPROCESS  myNtQueryInformationProcess = NULL; 
#include "GetPEB.h"

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

extern PVOID GetPeb(HANDLE ProcessHandle);



int main(int argc, TCHAR* argv[])
{
	myNtQueryInformationProcess = (PNTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
	if (!myNtQueryInformationProcess) return 0;
//		;

	PPEB pPeb;
	PVOID pImage, pEntry;
	PIMAGE_NT_HEADERS pNtHeaders;
	LONG e_lfanew;
	SIZE_T NumberOfBytesRead;

	STARTUPINFOA StartupInfo = { sizeof(STARTUPINFO) };
	StartupInfo.cb = sizeof(StartupInfo);
	//StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	//StartupInfo.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION ProcessInfo;

	if (!CreateProcessA("C:\\windows\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		printf("CreateProcess() failed with error 0x%08X\n", GetLastError());
		system("PAUSE");
		return -1;
	}

	printf("Current process:\n");
	pPeb = (PPEB)GetPeb(GetCurrentProcess());
	printf("PEB: 0x%08X\n", pPeb);
	pImage = pPeb->Reserved3[1];
	printf("Image base: 0x%08X\n", pImage);
	pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pImage + ((PIMAGE_DOS_HEADER)pImage)->e_lfanew);
	pEntry = (PVOID)((PCHAR)pImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("Image entry point: 0x%08X\n", pEntry);

	printf("\n");

	printf("Child process:\n");
	pPeb = (PPEB)GetPeb(ProcessInfo.hProcess);
	printf("PEB: 0x%08X\n", pPeb);

	if (!ReadProcessMemory(
		ProcessInfo.hProcess,
		&pPeb->Reserved3[1],
		&pImage,
		sizeof(pImage),
		&NumberOfBytesRead) || NumberOfBytesRead != sizeof(pImage))
	{
		printf("ReadProcessMemory(&pImage) failed with error 0x%08X\n", GetLastError());
		goto End;
	}
	printf("Image base: 0x%08X\n", pImage);

	if (!ReadProcessMemory(
		ProcessInfo.hProcess,
		(PCHAR)pImage + offsetof(IMAGE_DOS_HEADER, e_lfanew),
		&e_lfanew,
		sizeof(e_lfanew),
		&NumberOfBytesRead) || NumberOfBytesRead != sizeof(e_lfanew))
	{
		printf("ReadProcessMemory(&e_lfanew) failed with error 0x%08X\n", GetLastError());
		goto End;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pImage + e_lfanew);

	if (!ReadProcessMemory(
		ProcessInfo.hProcess,
		(PCHAR)pNtHeaders + offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint),
		&pEntry,
		sizeof(pEntry),
		&NumberOfBytesRead) || NumberOfBytesRead != sizeof(pEntry))
	{
		printf("ReadProcessMemory(&pEntry) failed with error 0x%08X\n", GetLastError());
		goto End;
	}
	pEntry = (PVOID)((PCHAR)pImage + (SIZE_T)pEntry);
	printf("Image entry point: 0x%08X\n", pEntry);

End:

	//TerminateProcess(ProcessInfo.hProcess, 0);
	CloseHandle(ProcessInfo.hThread);
	CloseHandle(ProcessInfo.hProcess);
	system("PAUSE");
	return 0;
}
