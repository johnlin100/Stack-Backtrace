# Stack-Backtrace
Introduce Stack back trace functions in UDK2017

This is a demostration to show how to trace back the function calling path from the x64 Unwind information.

1. Build OvmfPkg with IA32 X64 architecture and DEBUG target.
2. Run qemu-system-x86_64.exe with Ovmf.fd bios binary and dump the debug message as below example message.
3. The sample trace back demo function is insert at OvmfPkg/SmbiosPlatformDxe/SmbiosPlatformDxe.c
4. The Library for Unwind Information is located at MdePkg/Library/basePeCoffUnwindInfoLib.

Example message:
============================================
SmbiosTablePublishEntry(): Address Of Return Address = 0x7EFDD58
SmbiosTablePublishEntry(): Return Address            = 0x7D913DE
============================================
============================================
StackTraceTestFunc(): Address Of Return Address = 0x7EFDD58
StackTraceTestFunc(): Return Address            = 0x7D913DE
============================================
0. Address Of Return Address = 0x7EFDD58
0. Return Address            = 0x7D913DE
============================================
1. Driver Start Address      = 0x7D91000
1. Function Start : End      = 0x3D0 : 0x3E3
1. Next Stack Offset         = 0x30
1. Address Of Return Address = 0x7EFDD88
1. Return Address            = 0x7F06D15
============================================
2. Driver Start Address      = 0x7EFE000
2. Function Start : End      = 0x8BE8 : 0x8E7A
2. Next Stack Offset         = 0x40
2. Address Of Return Address = 0x7EFDDC8
2. Return Address            = 0x7F097C9
============================================
3. Driver Start Address      = 0x7EFE000
3. Function Start : End      = 0xB558 : 0xB864
3. Next Stack Offset         = 0x50
3. Address Of Return Address = 0x7EFDE18
3. Return Address            = 0x7EFF6A2
============================================
4. Driver Start Address      = 0x7EFE000
4. Function Start : End      = 0xD50 : 0x1819
4. Next Stack Offset         = 0x170
4. Address Of Return Address = 0x7EFDF88
4. Return Address            = 0x7EFE9D4
============================================
5. Driver Start Address      = 0x7EFE000
5. Function Start : End      = 0x9C4 : 0xA04
5. Next Stack Offset         = 0x30
5. Address Of Return Address = 0x7EFDFB8
5. Return Address            = 0x7F372D4
============================================
!!!! Can't find Function entry
