#include "hk.h"

//
// jmp QWORD PTR [rip+0x0]
//
static const UCHAR HkpDetour[] = {
	0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

#define FULL_DETOUR_SIZE			(sizeof(HkpDetour) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE	(16ul)
#define HK_POOL_TAG					('  kh')

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpReplaceCode16Bytes(
	_In_ PVOID	Address,
	_In_ PUCHAR	Replacement
)
{
	//
	// Check for proper alignment. cmpxchg16b works only with 16-byte aligned addresses.
	//
	if ((ULONG64)Address != ((ULONG64)Address & ~0xf))
	{
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	//
	// Create memory descriptor list to map read-only (or RX) memory as read-write.
	//
	PMDL Mdl = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Make memory pages resident in RAM and make sure they won't get paged out.
	//
	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);

		return STATUS_INVALID_ADDRESS;
	}

	//
	// Create new mapping for read-only memory.
	//
	PLONG64 RwMapping = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (RwMapping == NULL)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return STATUS_INTERNAL_ERROR;
	}

	//
	// Set new mapping page protection to read-write in order to modify it.
	//
	NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		MmUnmapLockedPages(RwMapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return Status;
	}

	LONG64 PreviousContent[2];
	PreviousContent[0] = RwMapping[0];
	PreviousContent[1] = RwMapping[1];

	//
	// Replace 16 bytes of code using created read-write mapping.
	// Interlocked compare and exchange (cmpxchg16b) is used to avoid concurrency issues.
	//
	InterlockedCompareExchange128(
		RwMapping,
		((PLONG64)Replacement)[1],
		((PLONG64)Replacement)[0],
		PreviousContent
	);

	//
	// Unlock and unmap pages, free MDL. 
	//
	MmUnmapLockedPages(RwMapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID HkpPlaceDetour(
	_In_ PVOID Address,
	_In_ PVOID Destination
)
{
	//
	// Save jump instruction and detour destination.
	// This will create code as shown:
	// +0	jmp QWORD PTR [rip+0x0]
	// +6	0x................
	//
	RtlCopyMemory((PUCHAR)Address, HkpDetour, sizeof(HkpDetour));
	RtlCopyMemory((PUCHAR)Address + sizeof(HkpDetour), &Destination, sizeof(PVOID));
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
)
{
	PUCHAR OriginalBytes = (PUCHAR)OriginalTrampoline - INTERLOCKED_EXCHANGE_SIZE;

	//
	// If that will fail we are probably going to bugcheck anyway...
	//
	NTSTATUS Status = HkpReplaceCode16Bytes(HookedFunction, OriginalBytes);

	//
	// Wait 10 ms to make sure no code will jump to trampoline after freeing.
	//
	LARGE_INTEGER DelayInterval;
	DelayInterval.QuadPart = -100000;
	KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);

	//
	// Free resources.
	//
	ExFreePoolWithTag(OriginalBytes, HK_POOL_TAG);

	return Status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 Hook,
	_In_ SIZE_T  CodeLength,
	_Out_ PVOID* OriginalTrampoline
)
{
	//
	// Check if CodeLength is big enough to hold detour.
	//
	if (CodeLength < FULL_DETOUR_SIZE)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	//
	// NonPagedPool is used to be compatibile with functions that run at high IRQL (>= DISPATCH_LEVEL).
	//
	PUCHAR Trampoline = ExAllocatePoolWithTag(
		NonPagedPool, 
		INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + CodeLength, 
		HK_POOL_TAG
	);
	if (Trampoline == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Save 16 original bytes to restore function later (needed for HkRestoreFunction).
	//
	RtlCopyMemory(Trampoline, TargetFunction, INTERLOCKED_EXCHANGE_SIZE);

	//
	// Create trampoline to original function containing original bytes and jump to function + CodeLength.
	//
	RtlCopyMemory(Trampoline   + INTERLOCKED_EXCHANGE_SIZE, TargetFunction, CodeLength);
	HkpPlaceDetour(Trampoline  + INTERLOCKED_EXCHANGE_SIZE + CodeLength, (PVOID)((ULONG_PTR)TargetFunction + CodeLength));

	//
	// Generate detour bytes.
	//
	UCHAR DetourBytes[INTERLOCKED_EXCHANGE_SIZE];

	HkpPlaceDetour(DetourBytes, Hook);
	RtlCopyMemory(
		(PUCHAR)DetourBytes			+ FULL_DETOUR_SIZE,
		(PUCHAR)TargetFunction		+ FULL_DETOUR_SIZE,
		INTERLOCKED_EXCHANGE_SIZE	- FULL_DETOUR_SIZE
	);

	//
	// Apply detour to target function.
	//
	NTSTATUS Status = HkpReplaceCode16Bytes(TargetFunction, DetourBytes);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
	}
	else
	{
		*OriginalTrampoline = Trampoline + INTERLOCKED_EXCHANGE_SIZE;
	}

	return Status;
}