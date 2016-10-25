#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

#ifdef INJECT_DLL
#define DLL_IPC __declspec(dllexport)
#else
#define DLL_IPC __declspec(dllimport)
#endif

extern DLL_IPC bool g_bEnabled;
extern DLL_IPC uint32_t g_iFuncAddress;
extern DLL_IPC char g_szOutputPath[MAX_PATH];
