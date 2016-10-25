#pragma once

#include "IScanner.h"

class ScannerOpcodes : public IScanner {
private:
  HANDLE hProcess;
  bool done;

public:
  ScannerOpcodes(HANDLE hTera) : done(false), hProcess(hTera) {};
  virtual ~ScannerOpcodes() {};
  virtual bool isDone();
  virtual bool isMatch(MEMORY_BASIC_INFORMATION mbi);
  virtual void scan(unsigned char* buf, size_t size, uint32_t offset);
};
