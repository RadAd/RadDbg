#include "Utils.h"

#include <tchar.h>

#include <iomanip> // quoted
#include <sstream>

void ShowError(LPCTSTR msg, DWORD e)
{
    _ftprintf(stderr, _T(COLOR_ERROR "Error: %s %d" COLOR_RETURN "\n"), msg, e);
}

void ShowAssert(LPCTSTR msg, LPCTSTR file, int line)
{
    TCHAR buf[1024];
    _stprintf_s(buf, TEXT("%s on %s:%d"), msg, file, line);
    if (MessageBox(NULL, msg, _T("Assert"), MB_ICONHAND | MB_OKCANCEL) == IDCANCEL)
        DebugBreak();
}

std::vector<std::string> split(const std::string& s, char delim)
{
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim))
        result.push_back(item);

    return result;
}

std::vector<std::wstring> split(const std::wstring& s, wchar_t delim)
{
    std::vector<std::wstring> result;
    std::wstringstream ss(s);
    std::wstring item;

    while (getline(ss, item, delim))
        result.push_back(item);

    return result;
}

std::vector<std::string> split_quoted(const std::string& str)
{
    std::vector<std::string> ret;
    std::stringstream ss(str);
    std::string word;
    while (ss >> std::quoted(word))
        ret.emplace_back(word);
    return ret;
}

std::vector<std::wstring> split_quoted(const std::wstring& str)
{
    std::vector<std::wstring> ret;
    std::wstringstream ss(str);
    std::wstring word;
    while (ss >> std::quoted(word))
        ret.emplace_back(word);
    return ret;
}
