#include "ScannerOpcodes.h"
#include "../OpcodeDll/shared.h"

#include <iostream>
#include <stdio.h>

const char* DLL_NAME = "OpcodeDll.dll";
const char* const OUTPUT_FILE = "opcodes.txt";

const unsigned char SEARCH_SIGNATURE[] = {
  0x55,                         // push ebp
  0x8B, 0xEC,                   // mov  ebp, esp
  0x8B, 0x45, 0x08,             // mov  eax, [ebp+8]
  0x0F, 0xB7, 0xC0,             // movzx eax, ax
  0x3D, 0x88, 0x13, 0x00, 0x00, // cmp eax, 5000
};

bool ScannerOpcodes::isDone() {
  return done;
}

bool ScannerOpcodes::isMatch(MEMORY_BASIC_INFORMATION mbi) {
  if (mbi.Type != MEM_IMAGE) return false;
  if (mbi.Protect != PAGE_EXECUTE_READWRITE) return false;
  return true;
}

void ScannerOpcodes::scan(unsigned char* buf, size_t size, uint32_t offset) {
  for (uint32_t diff = 0; diff + sizeof(SEARCH_SIGNATURE) < size; diff += 0x01) {
    if (memcmp(buf + diff, SEARCH_SIGNATURE, sizeof(SEARCH_SIGNATURE)) != 0) continue;

    std::cerr << "found opcode signature" << std::endl;
    done = true;
    
    /***************
     * dll exports *
     ***************/
    g_bEnabled = true;
    g_iFuncAddress = offset + diff;

    GetCurrentDirectoryA(MAX_PATH, g_szOutputPath);
    if (strnlen(g_szOutputPath, MAX_PATH) + 1 + strnlen(OUTPUT_FILE, MAX_PATH) + 1 > MAX_PATH) {
      std::cerr << "output path too long" << std::endl;
      return;
    }
    _snprintf(g_szOutputPath, MAX_PATH, "%s\\%s", g_szOutputPath, OUTPUT_FILE);
    std::cout << g_szOutputPath << std::endl;

    /*****************
     * dll injection *
     *****************/
    // get dll handle
    HMODULE hModule = GetModuleHandleA(DLL_NAME);
    if (hModule == NULL) {
      std::cerr << "failed to get dll handle" << std::endl;
      return;
    }

    // get dll path
    char szDllPath[MAX_PATH];
    auto res = GetModuleFileNameA(hModule, szDllPath, MAX_PATH);
    if (res == 0) {
      std::cerr << "failed to get dll path" << std::endl;
      return;
    }

    // write dll path to process
    std::cout << "writing dll name" << std::endl;
    LPVOID pDllName = VirtualAllocEx(hProcess, NULL, strlen(szDllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pDllName, szDllPath, strlen(szDllPath), NULL);

    // call LoadLibrary
    std::cout << "loading dll" << std::endl;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    LPVOID pFreeLibrary = (LPVOID)GetProcAddress(hKernel32, "FreeLibrary");

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllName, 0, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD hLibModule;
    GetExitCodeThread(hRemoteThread, &hLibModule); // value returned by LoadLibrary (HMODULE)

    CloseHandle(hRemoteThread);

    /************
     * clean up *
     ************/
    VirtualFreeEx(hProcess, pDllName, strlen(szDllPath), MEM_RELEASE);

    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hLibModule, 0, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);

    break;
  }
}
