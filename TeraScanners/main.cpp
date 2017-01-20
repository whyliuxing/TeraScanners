#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>

#include "IScanner.h"
#include "ScannerEncryption.h"
#include "ScannerOpcodes.h"
#include "ScannerSysmsg.h"

int main() {
  // find window
  HWND hwnd = FindWindowA(NULL, "TERA");
  if (!hwnd) {
    std::cout << "cannot find TERA" << std::endl;;
    return 1;
  }

  // get handle
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  HANDLE pHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
  if (pHandle == INVALID_HANDLE_VALUE) {
    std::cout << "cannot open process" << std::endl;
    return 1;
  }

  // load scanners
  std::cout << "initializing scanners" << std::endl;
  std::vector<IScanner*> arrScanners;
  arrScanners.push_back(new ScannerEncryption());
  arrScanners.push_back(new ScannerSysmsg());
  arrScanners.push_back(new ScannerOpcodes(pHandle));
  
  // start scans
  std::cout << "starting scan" << std::endl;

  uint32_t aStart = 0x00000000;
  uint32_t aEnd = 0xFFFF0000;

  while (aStart < aEnd) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!VirtualQueryEx(pHandle, (LPCVOID)aStart, &mbi, sizeof(mbi))) {
      std::cerr << "couldn't query memory region " << aStart << std::endl;
      break;
    }

    auto offset = aStart;
    auto size = mbi.RegionSize;
    aStart += size; // ugly

    if (mbi.State != MEM_COMMIT) continue;
    // check protect flags

    unsigned char* buf = NULL;
    auto it = arrScanners.begin();
    while (it != arrScanners.end()) {
      auto scanner = *it;
      if (scanner->isMatch(mbi)) {
        if (buf == NULL) {
          buf = new unsigned char[size];
          ReadProcessMemory(pHandle, mbi.BaseAddress, buf, size, NULL);
        }
        
        std::cout << "calling scan" << std::endl;
        scanner->scan(buf, size, offset);
        
        if (scanner->isDone()) {
          delete scanner;
          it = arrScanners.erase(it);
          continue;
        }
      }
      
      ++it;
    }

    if (buf != NULL) delete[] buf;

    if (arrScanners.size() == 0) break;
  }

  // clean up
  CloseHandle(pHandle);
  return 0;
}
