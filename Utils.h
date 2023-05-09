#pragma once
#include <Windows.h>

#include <memory>
#include <string>
#include <vector>

void ShowError(LPCTSTR msg, DWORD e);

#define CHECK(x, r) if (!(x)) { ShowError(TEXT(#x), GetLastError()); r; }
#define CHECK_IGNORE(x, i, r) if (!(x)) { DWORD e = GetLastError(); if (e != i) { ShowError(TEXT(#x), e); r; } }

#define COLOR_ERROR "\x1b[31m"
#define COLOR_INFO "\x1b[33m"
#define COLOR_MESSAGE "\x1b[34m"
#define COLOR_PROMPT "\x1b[32m"
#define COLOR_NAME "\x1b[33m"
#define COLOR_TYPENAME "\x1b[32m"
#define COLOR_RETURN "\x1b[0m"

void ShowAssert(LPCTSTR msg, LPCTSTR file, int line);

#define MYASSERT(x) if (!(x)) ShowAssert(TEXT(#x), TEXT(__FILE__), __LINE__)
#define NOT_IMPLEMENTED ShowAssert(TEXT("Not Implemented"), TEXT(__FILE__), __LINE__)

#ifdef  UNICODE
#define tstring wstring
#else
#define tstring string
#endif

std::vector<std::string> split_quoted(const std::string & str);
std::vector<std::wstring> split_quoted(const std::wstring & str);

struct FreeDeleter
{
    void operator()(void* p) const
    {
        free(p);
    }
};

template<class T>
std::unique_ptr<T, FreeDeleter> zmalloc(size_t extra)
{
    const size_t size = sizeof(T) + extra;
    std::unique_ptr<T, FreeDeleter> p((T*) malloc(size));
    memset(p.get(), 0, size);
    return p;
}
