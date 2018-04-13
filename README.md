# Stack-Backtrace
Introduce Stack back trace functions in UDK2017

This is a demostration to show how to trace back the function calling path from the x64 Unwind information.

1. Build OvmfPkg with IA32 X64 architecture and DEBUG target.
2. Run qemu-system-x86_64.exe with Ovmf.fd bios binary and dump the debug message as below example message.
3. The sample trace back demo function is insert at OvmfPkg/SmbiosPlatformDxe/SmbiosPlatformDxe.c
4. The Library for Unwind Information is located at MdePkg/Library/basePeCoffUnwindInfoLib.

