#pragma once
#include <Windows.h>

DWORD64 GetRegValue(ULONG reg, const CONTEXT& context);
void ShowValue(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address);
