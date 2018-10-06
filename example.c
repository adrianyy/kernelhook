#include <ntifs.h>
#include "hk.h"

NTSTATUS (*OriginalNtClose)(_In_ HANDLE Handle);
NTSTATUS HookedNtClose(
	_In_ HANDLE Handle
)
{
	DbgPrintEx(0, 0, "Called NtClose.\n");

	return OriginalNtClose(Handle);
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	HkRestoreFunction((PVOID)NtClose, (PVOID)OriginalNtClose);
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT		DriverObject,
	_In_ PUNICODE_STRING	RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	/*
		nt!NtClose:
		fffff801`51eff010 4056					push	rsi
		fffff801`51eff012 57					push	rdi
		fffff801`51eff013 4156					push	r14
		fffff801`51eff015 4157					push	r15
		fffff801`51eff017 4883ec38				sub		rsp,38h
		fffff801`51eff01b 65488b042588010000	mov		rax,qword ptr gs:[188h]
	*/
	HkDetourFunction((PVOID)NtClose, (PVOID)HookedNtClose, 20, (PVOID*)&OriginalNtClose);

	return STATUS_SUCCESS;
}