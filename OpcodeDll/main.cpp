#define WIN32_LEAN_AND_MEAN
#define INJECT_DLL

#include <windows.h>
#include <fstream>
#include <string>

#include "shared.h"

#pragma data_seg(".shared")
bool g_bEnabled = false;
uint32_t g_iFuncAddress = 0;
char g_szOutputPath[MAX_PATH] = "";
#pragma data_seg()

#pragma comment(linker,"/SECTION:.shared,RWS")

std::string ConvertCase(std::string str) {
  for (auto it = str.begin(); it != str.end(); ++it) {
    if (*it == '_') {
      it = str.erase(it); // crashes on string ending with _
    } else {
      *it = ::tolower(*it);
    }
  }
  return str;
}

DWORD WINAPI Thread(LPVOID lpParameter) {
  if (g_iFuncAddress <= 0) {
    MessageBoxA(NULL, "invalid func address", NULL, NULL);
    return 2;
  }

  if (strcmp(g_szOutputPath, "") == 0) {
    MessageBoxA(NULL, "output path is empty", NULL, NULL);
    return 2;
  }
  
  std::ofstream fOutput(g_szOutputPath);
  
  for (int i = 0; i < 0x10000; i++) {
    char* pName = NULL;

    __asm {
      push i
      call g_iFuncAddress
      add esp, 4
      mov [pName], eax
    }
    
    if (pName != NULL && strcmp(pName, "") != 0) {
      fOutput << ConvertCase(std::string(pName)) << " " << i << std::endl;
    }
  }
  
  fOutput.close();
	return 1;
}

BOOL WINAPI DllMain(HANDLE hModule, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH && g_bEnabled) {
    Thread(NULL);
  }
  
	return TRUE;
}
