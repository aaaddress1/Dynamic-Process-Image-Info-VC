#include <Winternl.h>

PVOID GetPeb(HANDLE ProcessHandle)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	PVOID pPeb;

	memset(&pbi, 0, sizeof(pbi));

	status = myNtQueryInformationProcess(
		ProcessHandle,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		NULL);

	pPeb = NULL;

	if (NT_SUCCESS(status))
	{
		pPeb = pbi.PebBaseAddress;
	}

	return pPeb;
}
