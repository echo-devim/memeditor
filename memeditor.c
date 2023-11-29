#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

/*
This is a C program that can attach to a process, find the executable memory region of a specific module,
and replace some opcodes with new ones.
The program takes four arguments: the process name, the module name, the old opcodes, and the new opcodes.

author: echo-devim 2023
License: MIT

*/

// Function that suspends all the threads of a process
void SuspendProcess(HANDLE hProcess) {
    HANDLE hThreadSnap;
    THREADENTRY32 te32;

    // Takes a snapshot of all the threads in the system
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    // Checks that the snapshot is valid
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        printf("Unable to take a snapshot of the threads\n");
        return;
    }

    // Sets the size of the structure
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieves information about the first thread
    if (!Thread32First(hThreadSnap, &te32)) {
        printf("Unable to get the first thread\n");
        CloseHandle(hThreadSnap);
        return;
    }

    // Loops through all the threads
    do {
        // Checks if the thread belongs to the process
        if (te32.th32OwnerProcessID == GetProcessId(hProcess)) {
            // Opens the thread
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

            // Checks that the thread is valid
            if (hThread != NULL) {
                // Suspends the thread
                SuspendThread(hThread);

                // Closes the thread handle
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32)); // Gets the next thread

    // Closes the snapshot handle
    CloseHandle(hThreadSnap);
}

// Function that resumes all the threads of a process
void ResumeProcess(HANDLE hProcess) {
    HANDLE hThreadSnap;
    THREADENTRY32 te32;

    // Takes a snapshot of all the threads in the system
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    // Checks that the snapshot is valid
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        printf("Unable to take a snapshot of the threads\n");
        return;
    }

    // Sets the size of the structure
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieves information about the first thread
    if (!Thread32First(hThreadSnap, &te32)) {
        printf("Unable to get the first thread\n");
        CloseHandle(hThreadSnap);
        return;
    }

    // Loops through all the threads
    do {
        // Checks if the thread belongs to the process
        if (te32.th32OwnerProcessID == GetProcessId(hProcess)) {
            // Opens the thread
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

            // Checks that the thread is valid
            if (hThread != NULL) {
                // Resumes the thread
                ResumeThread(hThread);

                // Closes the thread handle
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32)); // Gets the next thread

    // Closes the snapshot handle
    CloseHandle(hThreadSnap);
}

//
//  SetPrivilege enables/disables process token privilege.
//
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet=FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}

// Function that finds the process id of a process with a given name
DWORD FindProcessId(char* processName) {
    DWORD processIds[1024];
    DWORD processCount;
    DWORD processId;
    HANDLE hProcess;
    char moduleName[MAX_PATH];

    // Enumerates all the processes in the system
    EnumProcesses(processIds, sizeof(processIds), &processCount);

    // Loops through each process
    for (int i = 0; i < processCount / sizeof(DWORD); i++) {
        // Gets the process id
        processId = processIds[i];

        // Opens the process
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

        // Checks that the process is valid
        if (hProcess != NULL) {
            // Gets the base name of the process
            GetModuleBaseName(hProcess, NULL, moduleName, sizeof(moduleName));

            // Compares the base name with the given name
            if (strcmp(moduleName, processName) == 0) {
                // Closes the process handle
                CloseHandle(hProcess);

                // Returns the process id
                return processId;
            }

            // Closes the process handle
            CloseHandle(hProcess);
        }
    }

    // If no process is found, returns 0
    return 0;
}

// Function that finds the code section address and size of a process by querying the memory regions
// and matching the module name
void FindCodeSectionByModuleName(HANDLE hProcess, char* libraryName, PVOID64* codeAddress, DWORD64* codeSize) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID64 baseAddress;
    DWORD64 regionSize;
    DWORD regionProtect;

    // Initializes the code address and size to zero
    *codeAddress = 0;
    *codeSize = 0;

    // Loops through the memory regions of the process
    baseAddress = 0;
    while (VirtualQueryEx(hProcess, (LPCVOID)baseAddress, &mbi, sizeof(mbi)) != 0) {
        // Gets the region size and protection
        regionSize = mbi.RegionSize;
        regionProtect = mbi.Protect;

        // Checks if the region is a code section
        if (regionProtect == PAGE_EXECUTE || regionProtect == PAGE_EXECUTE_READ || regionProtect == PAGE_EXECUTE_READWRITE || regionProtect == PAGE_EXECUTE_WRITECOPY) {
            // Gets the module name of the region
            char moduleName[MAX_PATH];
            DWORD len = GetModuleBaseNameA(hProcess, (HMODULE)mbi.AllocationBase, moduleName, MAX_PATH);
            if (len > 0) {
                // Compares the module name with the library name (case-insensitive)
                if (strcasecmp(moduleName, libraryName) == 0) {
                    // Sets the code address and size to the region address and size
                    *codeAddress = (PVOID64)mbi.BaseAddress;
                    *codeSize = regionSize;

                    // Breaks the loop
                    break;
                }
            }
        }

        // Increments the base address by the region size
        baseAddress += regionSize;
    }

}

// Function that converts a string of hex characters to a byte array
void HexStringToByteArray(char* hexString, BYTE* byteArray, DWORD* byteSize) {
    DWORD hexLength;
    DWORD byteIndex;

    // Gets the length of the hex string
    hexLength = strlen(hexString);

    // Checks that the hex string has an even length
    if (hexLength % 2 != 0) {
        printf("Invalid hex string\n");
        return;
    }

    *byteSize = hexLength / 2;

    // Loops through the hex string in pairs of two characters
    for (DWORD i = 0; i < hexLength; i += 2) {
        // Gets the index of the byte array
        byteIndex = i / 2;

        // Converts the two hex characters to a byte value using sscanf
        sscanf(hexString + i, "%2hhx", &byteArray[byteIndex]);
    }
}

// Function that replaces a sequence of bytes in a memory region with another sequence of bytes of the same length
int ReplaceOpcodes(HANDLE hProcess, PVOID64 regionAddress, DWORD64 regionSize, char* oldOpcodes, char* newOpcodes) {
    DWORD oldProtect;
    DWORD newProtect;
    SIZE_T bytesRead;
    SIZE_T bytesWritten;
    BOOL result;
    BYTE oldByteArray [256];
    BYTE newByteArray [256];
    DWORD byteSize;
    int occurrences = 0;

    // Converts the old opcodes string to a byte array
    HexStringToByteArray(oldOpcodes, oldByteArray, &byteSize);

    // Converts the new opcodes string to a byte array
    HexStringToByteArray(newOpcodes, newByteArray, &byteSize);

    // Changes the memory protection of the region to allow writing
    newProtect = PAGE_EXECUTE_READWRITE;
    result = VirtualProtectEx(hProcess, regionAddress, regionSize, newProtect, &oldProtect);

    // Checks that the protection change is successful
    if (result == FALSE) {
        printf("Unable to change the memory protection\n");
        return 0;
    }

    printf("byte size: %d\n", byteSize);
    printf("region size: %lld\n", regionSize);

    // Loops through the memory region in blocks of byte size
    for (DWORD64 i = 0; (i+byteSize) < regionSize; i++) {
        // Reads the bytes from the region
        BYTE buffer [byteSize];
        ReadProcessMemory(hProcess, (LPCVOID)(regionAddress + i), buffer, byteSize, &bytesRead);

        // Compares the bytes with the old byte array
        if (memcmp(buffer, oldByteArray, byteSize) == 0) {
            // Writes the new byte array to the region
            WriteProcessMemory(hProcess, (LPVOID)(regionAddress + i), newByteArray, byteSize, &bytesWritten);
            if (bytesWritten == 0) {
                printf("Error: Cannot overwrite");
            }
            occurrences++;
        }
    }

    // Restores the original memory protection of the region
    VirtualProtectEx(hProcess, regionAddress, regionSize, oldProtect, &newProtect);

    return occurrences;
}


int main(int argc, char* argv[]) {
    HANDLE hProcess;
    DWORD processId;
    BOOL result;
    PVOID64 codeAddress = 0;
    DWORD64 codeSize = 0;
    MODULEINFO moduleInfo;
    char* oldOpcodes;
    char* newOpcodes;

    // Checks that the program receives three arguments
    if (argc != 5) {
        printf("Usage: %s <process name> <module name> <old opcodes> <new opcodes>\n", argv[0]);
        printf("Exmample 1: %s notepad.exe notepad.exe \"7503\" \"9090\"\n", argv[0]);
        printf("Exmample 2: %s notepad.exe comctl32.dll \"7503\" \"9090\"\n", argv[0]);
        return 0;
    }

    // Gets the arguments
    char* processName = argv[1];
    char* moduleName = argv[2];
    oldOpcodes = argv[3];
    newOpcodes = argv[4];

    // Finds the process id of the process with the given name
    processId = FindProcessId(processName);

    // Checks that the process id is valid
    if (processId == 0) {
        printf("Invalid process name\n");
        return -1;
    } else {
        printf("Found process id %d\n", processId);
    }

    HANDLE selfProcess=GetCurrentProcess();
    HANDLE hToken;

    if (OpenProcessToken(selfProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        if (!(SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))) {
            printf("Failed to SetPrivilege\n");
            return -1;
        } else {
            printf("SetPrivilege ok\n");
            CloseHandle(hToken);
        }
    }

    // Opens the process with the given id
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);

    // Checks that the process is valid
    if (hProcess == NULL) {
        printf("Unable to open the process\n");
        return -1;
    }

    if (DebugActiveProcess(processId)) {
        printf("Attached as debugger\n");
    } else {
        printf("Error: cannot attach as debugger to the process\n");
        return -1;
    }

    // Gets the module information of the process
    result = GetModuleInformation(hProcess, NULL, &moduleInfo, sizeof(moduleInfo));
    printf("Module size: %d\n", moduleInfo.SizeOfImage);

    // Suspends the process execution
    SuspendProcess(hProcess);

    // Finds the code section address and size of the process by querying the memory regions
    FindCodeSectionByModuleName(hProcess, moduleName, &codeAddress, &codeSize);

    // Checks that the code section is found
    if (codeAddress == 0 || codeSize == 0) {
        printf("Unable to find the code section\n");
    } else {
        // Prints the code section address and size
        printf("Code section address: %016llX\n", codeAddress);
        printf("Code section size: %lld\n", codeSize);
    }

    // Replaces the opcodes in the code section
    printf("Replacing opcodes..\n");
    int occurrences = ReplaceOpcodes(hProcess, codeAddress, codeSize, oldOpcodes, newOpcodes);
    if ( occurrences > 0 ) {
        printf("COMPLETED (occurrences found: %d)\n", occurrences);
    } else {
        printf("NO OCCURRENCE FOUND\n");
    }

    /*
    // Waits for a key press
    printf("Press any key to resume\n");
    getchar();
    */

    // Resumes the process execution
    ResumeProcess(hProcess);

    // Detach from process
    if (DebugActiveProcessStop(processId)) {
        printf("Detached from process\n");
    } else {
        printf("Error: cannot detach from process\n");
    }

    // Closes the process handle
    CloseHandle(hProcess);

    return 0;
}
