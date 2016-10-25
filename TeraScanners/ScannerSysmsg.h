#pragma once

#include "IScanner.h"

class ScannerSysmsg : public IScanner {
private:
  bool done;

public:
  ScannerSysmsg() : done(false) {};
  virtual ~ScannerSysmsg() {};
  virtual bool isDone();
  virtual bool isMatch(MEMORY_BASIC_INFORMATION mbi);
  virtual void scan(unsigned char* buf, size_t size, uint32_t offset);
};
