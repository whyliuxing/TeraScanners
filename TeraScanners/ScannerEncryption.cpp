#include "ScannerEncryption.h"
#include <iostream>
#include <fstream>
#include <string>

const char* const OUTPUT_FILE = "encryption.txt";

const unsigned char SEARCH_SIGNATURE[] = {
  0x56,                               // push esi
  0x57,                               // push edi
  0x50,                               // push eax
  0x8D, 0x45, 0xF4,                   // lea  eax, [ebp-12]
  0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, // mov  fs:[0], eax
  0x8B, 0x73, 0x08,                   // mov esi, [ebx+8]
  0x8B, 0xCE,                         // mov ecx, esi
};

uint32_t ReadInt(unsigned char* buf) {
  // C7 45 [...] [...] # mov [ebp-...], [...]
  if (buf[0] != 0xC7 || buf[1] != 0x45) {
    // TODO error
    return 0;
  }

  return (buf[3] << 24) | (buf[4] << 16) | (buf[5] << 8) | buf[6];
}

bool ScannerEncryption::isDone() {
  return done;
}

bool ScannerEncryption::isMatch(MEMORY_BASIC_INFORMATION mbi) {
  if (mbi.Type != MEM_IMAGE) return false;
  if (mbi.Protect != PAGE_EXECUTE_READWRITE) return false;
  return true;
}

void ScannerEncryption::scan(unsigned char* buf, size_t size, uint32_t offset) {
  for (uint32_t diff = 0; diff + sizeof(SEARCH_SIGNATURE) < size; diff += 0x01) {
    if (memcmp(buf + diff, SEARCH_SIGNATURE, sizeof(SEARCH_SIGNATURE)) != 0) continue;

    std::cerr << "found encryption signature" << std::endl;

    auto base = diff + sizeof(SEARCH_SIGNATURE);
    if (!(base + 5 + 7*8 < size)) {
      std::cerr << "region not large enough - skipping" << std::endl;
      continue;
    }

    // 8B 06 # mov eax, [esi]
    if (!(buf[base + 21] == 0x8B && buf[base + 22] == 0x06)) {
      std::cerr << "asm does not match - skipping" << std::endl;
      continue;
    }

    // 8B 40 2C # mov eax, [eax+44]
    if (!(buf[base + 44] == 0x8B && buf[base + 45] == 0x40 && buf[base + 46] == 0x2C)) {
      std::cerr << "asm does not match - skipping" << std::endl;
      continue;
    }
    
    done = true;

    // C7 45 [...] [...] # mov [ebp-...], [...]
    auto key1 = ReadInt(buf + base);
    auto key2 = ReadInt(buf + base + 7);
    auto key3 = ReadInt(buf + base + 14);
    auto key4 = ReadInt(buf + base + 23);

    auto iv1 = ReadInt(buf + base + 30);
    auto iv2 = ReadInt(buf + base + 37);
    auto iv3 = ReadInt(buf + base + 47);
    auto iv4 = ReadInt(buf + base + 54);
    
    std::ofstream fOutput(OUTPUT_FILE);
    fOutput.fill('0');
    fOutput.width(8);
    fOutput << std::hex << std::endl;
    fOutput << "key: " << key1 << " " << key2 << " " << key3 << " " << key4 << std::endl;
    fOutput << "iv: " << iv1 << " " << iv2 << " " << iv3 << " " << iv4 << std::endl;
    fOutput.close();
    break;
  }
}
