Inline hooking in Windows kernel. 
This is simple tool to show how to properly create inline hooks in kernel. It requires disabling PatchGuard which is
relatively simple via patching kernel image (ntoskrnl.exe).

Most of tools like this one in order to write to read-only code disable write-protect bit in CR0.
The problem with that method is that control registers are per-processor, not per-thread registers.
After disabling CR0.WP context switch changing processor on which the thread is executing can happen.
Because of this we will write over read-only with CR0.WP disabled which will cause bluescreen.
The simple solution to this would be raising IRQL to DPC level to make sure context switch won't happen.
This however creates problem of accessing paged memory with interrupts disabled, which will cause bluescreen
when memory have been paged out to disk. Solution used here is creating read-write mapping of the code 
using memory descriptors list.

The hooks need at least 14 bytes available at the beginning of function. It doesn't trash any registers.
Usage example (hooking NtClose) is in example.c.

Current limitations:
- RIP-relative addressing is not handled.
- Relative CALLs, JMPs, Jccs are not handled.
