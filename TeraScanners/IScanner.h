#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

class IScanner {
public:
  virtual ~IScanner() {};
  virtual bool isDone() = 0;
  virtual bool isMatch(MEMORY_BASIC_INFORMATION mbi) = 0;
  virtual void scan(unsigned char* buf, size_t size, uint32_t offset) = 0;
};
