#pragma once

#include "IScanner.h"

class ScannerEncryption : public IScanner {
private:
  bool done;

public:
  ScannerEncryption() : done(false) {};
  virtual ~ScannerEncryption() {};
  virtual bool isDone();
  virtual bool isMatch(MEMORY_BASIC_INFORMATION mbi);
  virtual void scan(unsigned char* buf, size_t size, uint32_t offset);
};
