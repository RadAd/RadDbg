#pragma once
#include <Windows.h>
#include <vector>
#include <string>

#ifdef  UNICODE
#define tstring wstring
#else
#define tstring string
#endif

DWORD64 GetRegValue(ULONG reg, const CONTEXT& context);
void ShowValue(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address);

struct FoundValue
{
    ULONG TypeId;
    DWORD64 Address;
};

FoundValue FindValue(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, LPCWSTR strName);
