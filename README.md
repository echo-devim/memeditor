# MemEditor

MemEditor is a C program that can attach to a process, find the executable memory region of a specific module (e.g. a library such as kernel32.dll), and replace some opcodes with new ones. You can use this tool to change on-the-fly executable code (i.e. behaviour) of your target process. I wrote it in a single simple plain C file.
You can use it as a debugger example.

The program uses various Windows API functions to perform the following tasks:
*  Enumerate the processes and modules in the system and get their information
*  Open the process and attach as a debugger
*  Suspend and resume the process execution
*  Query and modify the memory regions and their protection
*  Read and write the memory bytes
*  Convert the input hex strings (representing the opcodes) to byte arrays
*  Compare and replace the opcodes
*  Close the handles and detach from the process

The program is intended to demonstrate how to patch executable code on-the-fly in a Windows process. It may not work on some processes or modules that have anti-debugging or self-modifying techniques. It also assumes that the old and new opcodes have the same length.

This program should be used with caution and only for educational purposes.

# Usage
The program takes four arguments: the process name, the module name, the old opcodes, and the new opcodes.
The old and new opcodes should be strings of hex characters.

To compile the program, you can use any C compiler that supports the Windows API, such as Visual Studio or MinGW.

To run the program, you need to have administrator privileges.

Example of usage:

To replace the call instruction (E8 00 00 00 00) with five nop instructions (90 90 90 90 90) in the code section of the kernel32.dll module of the notepad.exe process, you can use the following command:
`memeditor.exe notepad.exe kernel32.dll E800000000 9090909090`
