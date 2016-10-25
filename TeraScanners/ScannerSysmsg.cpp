#include "ScannerSysmsg.h"
#include <iostream>
#include <fstream>
#include <string>

const char* const OUTPUT_FILE = "sysmsgs.txt";

const unsigned char SEARCH_SIGNATURE[] = {
  0x55,             // push ebp
  0x8B, 0xEC,       // mov  ebp, esp
  0x8B, 0x45, 0x08, // mov  eax, [ebp+8]
  0x85, 0xC0,       // test eax, eax
  0x78, 0x10,       // js   [+10]
  0x3D,             // cmp  [...]
};

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

bool ScannerSysmsg::isDone() {
  return done;
}

bool ScannerSysmsg::isMatch(MEMORY_BASIC_INFORMATION mbi) {
  if (mbi.Type != MEM_IMAGE) return false;
  if (mbi.Protect != PAGE_EXECUTE_READWRITE) return false;
  return true;
}

void ScannerSysmsg::scan(unsigned char* buf, size_t size, uint32_t offset) {
  for (uint32_t diff = 0; diff + sizeof(SEARCH_SIGNATURE) < size; diff += 0x01) {
    if (memcmp(buf + diff, SEARCH_SIGNATURE, sizeof(SEARCH_SIGNATURE)) != 0) continue;

    std::cerr << "found sysmsg signature" << std::endl;

    auto base = diff + sizeof(SEARCH_SIGNATURE);
    if (!(base + 13 < size)) {
      std::cerr << "region not large enough - skipping" << std::endl;
      continue;
    }

    done = true;

    // [...]
    // 73 09          # jae [+0x09]
    // 8B 04 85 [...] # mov eax, [eax*4+...]
    auto numMsgs = *reinterpret_cast<int32_t*>(buf + base);
    auto baseAddress = *reinterpret_cast<uint32_t*>(buf + base + 9);

    std::cerr << "messages: " << numMsgs << std::endl;
    
    std::ofstream fOutput(OUTPUT_FILE);

    for (int i = 0; i < numMsgs; i++) {
      auto pointerAddr = baseAddress + (i * 4);
      
      if (!(offset < pointerAddr && offset + size > pointerAddr)) {
        std::cerr << "string pointer not in region - parse not available" << std::endl;
        break;
      }

      auto stringAddr = *reinterpret_cast<uint32_t*>(buf + pointerAddr - offset);
      if (!(offset < stringAddr && offset + size > stringAddr)) {
        std::cerr << "string not in region - parse not available" << std::endl;
        break;
      }

      auto wszStr = reinterpret_cast<wchar_t*>(buf + stringAddr - offset);
      std::wstring wsStr(wszStr);
      std::string sStr(wsStr.begin(), wsStr.end());
      
      fOutput << ConvertCase(sStr) << " " << i << std::endl;
    }
    
    fOutput.close();
    break;
  }
}
