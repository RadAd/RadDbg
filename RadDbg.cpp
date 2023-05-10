#ifdef  UNICODE
#define DBGHELP_TRANSLATE_TCHAR
#endif

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#define _NO_CVCONST_H
#include <DbgHelp.h>
#include <tlhelp32.h>

#include <cstdio>
//#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <map>
#include <cinttypes>

#include "Utils.h"
#include "Types.h"
#include "Values.h"

// https://github.com/rogerorr/articles/blob/main/Debugging_Optimised_Code/SimpleStackWalker.cpp - shows inline frames in stackwalk
// See https://skanthak.homepage.t-online.de/tidbits.html#debugger

struct EnumSymProcData
{
    HANDLE  hProcess;
    ULONG   FlagMask;
    CONTEXT* pContext;
};

BOOL CALLBACK EnumSymProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
    MYASSERT(SymbolSize == pSymInfo->Size);

    const EnumSymProcData* pData = (EnumSymProcData*) UserContext;

    // https://accu.org/journals/overload/29/165/orr/

    if (pData->FlagMask == 0 or pSymInfo->Flags & pData->FlagMask)
    {
        if (pSymInfo->Flags != 0)
        {
            ULONG Flags = pSymInfo->Flags;
#define HANDLE_FLAG(f, y) if (Flags & (f)) { Flags &= ~(f); y;}
            HANDLE_FLAG(SYMFLAG_VALUEPRESENT | SYMFLAG_REGISTER | SYMFLAG_REGREL | SYMFLAG_FRAMEREL, 0);
            HANDLE_FLAG(SYMFLAG_PARAMETER | SYMFLAG_LOCAL, 0);
            HANDLE_FLAG(SYMFLAG_EXPORT, _tprintf(_T(" export")));
            HANDLE_FLAG(SYMFLAG_PUBLIC_CODE, _tprintf(_T(" public_code")));
            HANDLE_FLAG(SYMFLAG_RESET, _tprintf(_T(" reset")));
            HANDLE_FLAG(SYMFLAG_FUNC_NO_RETURN, _tprintf(_T(" no_return")));
#undef HANDLE_FLAG
            MYASSERT(Flags == 0);
        }

        if (pSymInfo->TypeIndex == 0)
        {
            _tprintf(_T(" " COLOR_NAME "%s" COLOR_RETURN "\n"), pSymInfo->Name); // TODO
            MYASSERT((pSymInfo->Flags & (SYMFLAG_VALUEPRESENT | SYMFLAG_REGISTER | SYMFLAG_REGREL | SYMFLAG_FRAMEREL)) == 0);
        }
        else
        {
            MYASSERT(((pSymInfo->Flags & ~(SYMFLAG_LOCAL | SYMFLAG_PARAMETER | SYMFLAG_REGREL)) & (SYMFLAG_VALUEPRESENT | SYMFLAG_REGISTER | SYMFLAG_REGREL | SYMFLAG_FRAMEREL)) == 0);

            ULONG64 Length = 0;
            if (SymGetTypeInfo(pData->hProcess, pSymInfo->ModBase, pSymInfo->TypeIndex, TI_GET_LENGTH, &Length))
            {
                if (Length > 0)
                    MYASSERT(Length == pSymInfo->Size);
            }

            // https://www.debuginfo.com/articles/dbghelptypeinfo.html
            ShowType(pData->hProcess, pSymInfo->ModBase, pSymInfo->TypeIndex, pSymInfo->Name, 0);

            switch (pSymInfo->Flags & (SYMFLAG_NULL | SYMFLAG_VALUEPRESENT | SYMFLAG_REGISTER | SYMFLAG_REGREL))
            {
            case 0:
                _tprintf(_T(" ="));
                ShowValue(pData->hProcess, pSymInfo->ModBase, pSymInfo->TypeIndex, pSymInfo->Address);
                break;
            case SYMFLAG_NULL:
                _tprintf(_T(" = NULL"));
                break;
            case SYMFLAG_VALUEPRESENT:
                _tprintf(_T(" = v:%llu"), pSymInfo->Value);
                break;
            case SYMFLAG_REGISTER:
                _tprintf(_T(" = r:%lu"), pSymInfo->Register);
                break;
            case SYMFLAG_REGREL:
                if (pData->pContext != nullptr)
                {
                    //_tprintf(_T(" reg:%lu"), pSymInfo->Register);
                    DWORD64 regvalue = GetRegValue(pSymInfo->Register, *pData->pContext);
                    //MYASSERT(regvalue != 0);
                    //_tprintf(_T(" Address:%llu + %llu"), regvalue, pSymInfo->Address);
                    MYASSERT(pSymInfo->Address >= 0 && pSymInfo->Address <= 0x7fffffff); // TODO Handle negative offset
                    DWORD64 Address = regvalue + pSymInfo->Address;

                    _tprintf(_T(" ="));
                    ShowValue(pData->hProcess, pSymInfo->ModBase, pSymInfo->TypeIndex, Address);
                }
                break;
            default:
                NOT_IMPLEMENTED;
                break;
            }

            _tprintf(_T("\n"));
        }
    }
    return TRUE;
}

LPCTSTR GetSymType(SYM_TYPE SymType)
{
    switch (SymType)
    {
    case SymNone:       return TEXT("-nosymbols-");
    case SymCoff:       return TEXT("COFF");
    case SymCv:         return TEXT("CV");
    case SymPdb:        return TEXT("PDB");
    case SymExport:     return TEXT("-exported-");
    case SymDeferred:   return TEXT("-deferred-");
    case SymSym:        return TEXT("SYM");
    case SymDia:        return TEXT("DIA");
    case SymVirtual:    return TEXT("Virtual");
    default:            return TEXT("-unknown-");
    }
}

ULONG64 GetAddressFromName(HANDLE hProcess, LPCTSTR strName, bool log)
{
    auto pSymbol = zmalloc<SYMBOL_INFO>(MAX_SYM_NAME);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(hProcess, strName, pSymbol.get()))
    {
        if (log)
            ShowError(TEXT("SymFromName"), GetLastError());
        return 0;
    }
    else
        return pSymbol->Address;
}

ULONG64 GetAddressFromSource(HANDLE hProcess, LPCTSTR strFileName, DWORD dwLineNumber, bool log)
{
    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    LONG disp = 0;
    if (!SymGetLineFromName64(hProcess, nullptr, strFileName, dwLineNumber, &disp, &line))
    {
        if (log)
            ShowError(TEXT("SymGetLineFromName64"), GetLastError());
        return 0;
    }
    else
        return line.Address;
}

void ShowStackFrame(HANDLE hProcess, DWORD64 Offset)
{
    auto pSymbol = zmalloc<SYMBOL_INFO>(MAX_SYM_NAME);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    IMAGEHLP_LINE64 Line = {};
    Line.SizeOfStruct = sizeof(Line);

    IMAGEHLP_MODULE64 Module = {};
    Module.SizeOfStruct = sizeof(Module);

    DWORD64 offsetFromSmybol = 0;
    TCHAR undName[MAX_SYM_NAME] = TEXT("");
    TCHAR undFullName[MAX_SYM_NAME] = TEXT("");

    DWORD offsetFromLine = 0;

    if (Offset != 0)
    {
        if (!SymFromAddr(hProcess, Offset, &offsetFromSmybol, pSymbol.get()))
            ; // ShowError(TEXT("SymFromAddr"), GetLastError());
        else
        {
            UnDecorateSymbolName(pSymbol->Name, undName, MAX_SYM_NAME, UNDNAME_NAME_ONLY);
            UnDecorateSymbolName(pSymbol->Name, undFullName, MAX_SYM_NAME, UNDNAME_COMPLETE);
        }

        if (!SymGetLineFromAddr64(hProcess, Offset, &offsetFromLine, &Line))
            Line; // ShowError(TEXT("SymGetLineFromAddr64"), GetLastError());

        if (!SymGetModuleInfo64(hProcess, Offset, &Module))
            Module; // ShowError(TEXT("SymGetModuleInfo64"), GetLastError());
    }

    LPCTSTR name
        = undFullName[0] != 0 ? undFullName
        : undName[0] != 0 ? undName
        : pSymbol->Name[0] != 0 ? pSymbol->Name
        : nullptr;

    LPCTSTR lineFileName
        = Line.FileName != nullptr ? Line.FileName
        : nullptr;

    LPCTSTR moduleName
        = Module.ImageName[0] != 0 ? Module.ModuleName
        : TEXT("(unknown)");

    _tprintf(_T("0x%p (%s):"), (LPVOID) Offset, moduleName);
    if (name != nullptr)
        _tprintf(_T(" %s:%lld"), name, offsetFromSmybol);
    if (lineFileName != nullptr)
        _tprintf(_T(" %s:%d"), lineFileName, Line.LineNumber);
    _tprintf(_T("\n"));
}

std::vector<STACKFRAME64> GetCallstack(HANDLE hProcess, HANDLE hThread)
{
    CONTEXT lcContext = {};
    lcContext.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &lcContext);

    // init STACKFRAME for first call
    STACKFRAME64 s = {}; // in/out stackframe
    DWORD imageType;
#ifdef _M_IX86
    // normally, call ImageNtHeader() and use machine info from PE header
    imageType = IMAGE_FILE_MACHINE_I386;
    s.AddrPC.Offset = lcContext.Eip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = lcContext.Ebp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = lcContext.Esp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    imageType = IMAGE_FILE_MACHINE_AMD64;
    s.AddrPC.Offset = lcContext.Rip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = lcContext.Rbp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = lcContext.Rsp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
    imageType = IMAGE_FILE_MACHINE_IA64;
    s.AddrPC.Offset = lcContext.StIIP;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = lcContext.IntSp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrBStore.Offset = lcContext.RsBSP;
    s.AddrBStore.Mode = AddrModeFlat;
    s.AddrStack.Offset = lcContext.IntSp;
    s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif

    std::vector<STACKFRAME64> stack;
    while (StackWalk64(imageType, hProcess, hThread, &s, &lcContext, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
    {
        // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
        // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
        // assume that either you are done, or that the stack is so hosed that the next
        // deeper frame could not be found.
        // CONTEXT need not to be suplied if imageTyp is IMAGE_FILE_MACHINE_I386!

        if (s.AddrPC.Offset == s.AddrReturn.Offset)
        {
            _tprintf(_T("StackWalk64 Endless Callstack! %llu\n"), s.AddrPC.Offset);
            break;
        }

        stack.push_back(s);

#if 0
        IMAGEHLP_STACK_FRAME imghlp_frame = {};
        //imghlp_frame.InstructionOffset = (ULONG64) ExceptionRecord.ExceptionAddress;
        imghlp_frame.InstructionOffset = (ULONG64) s.AddrPC.Offset;
        CHECK_IGNORE(SymSetContext(hProcess, &imghlp_frame, nullptr), ERROR_SUCCESS, continue);

        DWORD64 BaseOfImage = SymGetModuleBase64(hProcess, (DWORD64) s.AddrPC.Offset);
        if (BaseOfImage == 0)
            ShowError(TEXT("SymGetModuleBase64"), GetLastError());

        EnumSymProcData espdata = { hProcess, BaseOfImage, SYMFLAG_LOCAL, &lcContext };
        CHECK(SymEnumSymbols(hProcess, 0, "*", EnumSymProc, &espdata), 0);
#endif


        if (s.AddrReturn.Offset == 0)
        {
            SetLastError(ERROR_SUCCESS);
            break;
        }
    }
    return stack;
}

void ShowThread(HANDLE hProcess, HANDLE hThread, DWORD dwThreadId, BOOL bCurrent)
{
    _tprintf(_T("%c %5d"), bCurrent ? _T('*') : _T(' '), dwThreadId);

    CONTEXT lcContext = {};
    lcContext.ContextFlags = CONTEXT_ALL;
    CHECK(GetThreadContext(hThread, &lcContext), 0)
    else
        _tprintf(_T(" 0x%p"), (LPVOID) lcContext.Rip);

    auto pSymbol = zmalloc<SYMBOL_INFO>(MAX_SYM_NAME);
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    DWORD64 dispsym = 0;
    CHECK(SymFromAddr(hProcess, lcContext.Rip, &dispsym, pSymbol.get()), 0)
    else
        _tprintf(_T(" %s:%llu"), pSymbol->Name, dispsym);

    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD dispfn = 0;
    if (!SymGetLineFromAddr64(hProcess, lcContext.Rip, &dispfn, &line))
        ; // ShowError(TEXT("SymGetLineFromAddr64"), GetLastError());
    else
        _tprintf(_T(" %s:%d"), line.FileName, line.LineNumber);

    PWSTR Description = nullptr;
    if (FAILED(GetThreadDescription(hThread, &Description)))
        ShowError(TEXT("GetThreadDescription"), GetLastError());
    else
        wprintf(L" %s", Description);
    LocalFree(Description);

    _tprintf(_T("\n"));
}

struct BreakPoint
{
    HANDLE hProcess;
    ULONG64 Address;
    DWORD dwThreadId;
    BYTE cInstruction;

    void Set()
    {
        SIZE_T dwReadWriteBytes;
        CHECK(ReadProcessMemory(hProcess, (LPCVOID) Address, &cInstruction, 1, &dwReadWriteBytes), 0);

        BYTE cInt3Instruction = 0xCC;   // INT 3 - hardcoded breakpoint
        CHECK(WriteProcessMemory(hProcess, (LPVOID) Address, &cInt3Instruction, 1, &dwReadWriteBytes), 0);
        CHECK(FlushInstructionCache(hProcess, (LPCVOID) Address, 1), 0);
    }

    void Unset()
    {
        SIZE_T dwReadWriteBytes;
        CHECK(WriteProcessMemory(hProcess, (LPVOID) Address, &cInstruction, 1, &dwReadWriteBytes), 0);
        CHECK(FlushInstructionCache(hProcess, (LPCVOID) Address, 1), 0);
        cInstruction = 0;
    }
};

class Debugger
{
public:
    void DoEventLoop();

    void BreakProcess()
    {
        for (auto it : m_Processes)
            DebugBreakProcess(it.second);
    }

    void AddBreakpoint(HANDLE hProcess, ULONG64 Address)
    {
        auto it1 = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [Address](const BreakPoint& bp) { return bp.Address == Address; });
        if (it1 != m_breakpoints.end())
            return; // breakpoint already exists

        auto it2 = std::find_if(m_tempbreakpoints.begin(), m_tempbreakpoints.end(), [Address](const BreakPoint& bp) { return bp.Address == Address; });
        if (it2 != m_tempbreakpoints.end())
        {
            it2->Unset();
            m_tempbreakpoints.erase(it2);
        }

        BreakPoint bp({ hProcess, Address });
        bp.Set();
        m_breakpoints.push_back(bp);
    }

    void AddTempBreakpoint(HANDLE hProcess, ULONG64 Address, DWORD dwThreadId)
    {
        // TODO Should we allow multiple breakpoints at same address but different threads?
        auto it1 = std::find_if(m_tempbreakpoints.begin(), m_tempbreakpoints.end(), [Address](const BreakPoint& bp) { return bp.Address == Address; });
        if (it1 != m_tempbreakpoints.end())
            return; // breakpoint already exists

        auto it2 = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [Address](const BreakPoint& bp) { return bp.Address == Address; });
        if (it2 != m_breakpoints.end())
            return; // full breakpoint already exists

        BreakPoint bp({ hProcess, Address, dwThreadId });
        bp.Set();
        m_tempbreakpoints.push_back(bp);
    }

protected:
    enum class UserCommand
    {
        NONE,
        CONT,
        STEP_IN,
        EXIT,
    };

    UserCommand UserInputLoop(const DEBUG_EVENT& DebugEv, const EXCEPTION_RECORD& ExceptionRecord);

    DWORD OnExceptionDebugEvent(const DEBUG_EVENT& DebugEv, const EXCEPTION_DEBUG_INFO& Exception);
    DWORD OnCreateThreadDebugEvent(const DEBUG_EVENT& DebugEv, const CREATE_THREAD_DEBUG_INFO& CreateThread);
    DWORD OnCreateProcessDebugEvent(const DEBUG_EVENT& DebugEv, const CREATE_PROCESS_DEBUG_INFO& CreateProcessInfo);
    DWORD OnExitThreadDebugEvent(const DEBUG_EVENT& DebugEv, const EXIT_THREAD_DEBUG_INFO& ExitThread);
    DWORD OnExitProcessDebugEvent(const DEBUG_EVENT& DebugEv, const EXIT_PROCESS_DEBUG_INFO& ExitProcess);
    DWORD OnLoadDllDebugEvent(const DEBUG_EVENT& DebugEv, const LOAD_DLL_DEBUG_INFO& LoadDll);
    DWORD OnUnloadDllDebugEvent(const DEBUG_EVENT& DebugEv, const UNLOAD_DLL_DEBUG_INFO& UnloadDll);
    DWORD OnOutputDebugStringEvent(const DEBUG_EVENT& DebugEv, const OUTPUT_DEBUG_STRING_INFO& DebugString);
    DWORD OnRipEvent(const DEBUG_EVENT& DebugEv, const RIP_INFO& RipInfo);

    HANDLE GetProcess(DWORD id) const
    {
        auto it = m_Processes.find(id);
        return it != m_Processes.end() ? it->second : NULL;
    }

    HANDLE GetThread(DWORD id) const
    {
        auto it = m_Threads.find(id);
        return it != m_Threads.end() ? it->second : NULL;
    }

private:
    std::map<DWORD, HANDLE> m_Processes;
    std::map<DWORD, HANDLE> m_Threads;
    UserCommand m_LastCmd = UserCommand::NONE;
    std::vector<BreakPoint> m_breakpoints;
    std::vector<BreakPoint> m_tempbreakpoints;
    BreakPoint* m_pLastBreakPoint = nullptr;
    IMAGEHLP_LINE   m_CurrentLine;
    std::map<LPVOID, std::tstring> m_DLLs;
};

Debugger::UserCommand Debugger::UserInputLoop(const DEBUG_EVENT& DebugEv, const EXCEPTION_RECORD& ExceptionRecord)
{
    ZeroMemory(&m_CurrentLine, sizeof(m_CurrentLine));

    const HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);
    DWORD dwThreadId = DebugEv.dwThreadId;
    HANDLE hThread = GetThread(dwThreadId);

    TCHAR line[1024];
    // TODO Use ReadConsole and trap F? keys to step, next, etc
    while (_tprintf(_T(COLOR_PROMPT "%d:%d> " COLOR_RETURN), DebugEv.dwProcessId, dwThreadId)
        && SUCCEEDED(StringCchGets(line, ARRAYSIZE(line))))
    {
        std::vector<std::tstring> args = split_quoted(line);
        if (args.empty())
            ;
        else if (args[0] == TEXT("help"))
        {
            _tprintf(_T("cont    - continue\n"));
            _tprintf(_T("next    - step over to new line\n"));
            _tprintf(_T("step    - step in to new line\n"));
            _tprintf(_T("return  - step out to new line\n"));
            _tprintf(_T("context - show registers\n"));
            _tprintf(_T("stack   - show stacktrace\n"));
            _tprintf(_T("mem [addresss]     - show memory contents\n"));
            _tprintf(_T("source  - show sourcecode\n"));
            _tprintf(_T("bp      - list breakpoints\n"));
            _tprintf(_T("bp add [symbol]    - add a breakpoint\n"));
            _tprintf(_T("threads - list threads\n"));
            _tprintf(_T("thread [thread_id] - switch threads\n"));
            _tprintf(_T("detach  - detach debugger\n"));
            _tprintf(_T("exit    - exit debugger\n"));
        }
        else if (args[0] == TEXT("break"))
            DebugBreak();
        else if (args[0] == TEXT("cont"))
            return UserCommand::CONT;
        else if (args[0] == TEXT("next"))
        {
            // Step-over

            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD disp = 0;
            CHECK(SymGetLineFromAddr64(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress, &disp, &line), continue);

            // TODO what if this is the last or is return statement

            CHECK(SymGetLineNext64(hProcess, &line), continue);

            // TODO if get line fails do a STEP_ASM

            AddTempBreakpoint(hProcess, line.Address, dwThreadId);

            // TODO Also set breakpoint on any jumps in case it branches or loops

            return UserCommand::CONT;
        }
        else if (args[0] == TEXT("step"))
        {
            // Step-in
            m_CurrentLine.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD disp = 0;
            CHECK(SymGetLineFromAddr64(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress, &disp, &m_CurrentLine), continue);

            CONTEXT lcContext = {};
            lcContext.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &lcContext);

            lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
            SetThreadContext(hThread, &lcContext);

            return UserCommand::STEP_IN;
        }
        else if (args[0] == TEXT("return"))
        {
            // Step-out
            std::vector<STACKFRAME64> stack = GetCallstack(hProcess, hThread);

            AddTempBreakpoint(hProcess, stack.front().AddrReturn.Offset, dwThreadId);

            // TODO This wont work correctly for recursive functions
            // Maybe add call depth to breakpoint or compare EBP?

            return UserCommand::CONT;
        }
        else if (args[0] == TEXT("context"))
        {
            BOOL bIsWow64;
            CHECK(IsWow64Process(hProcess, &bIsWow64), continue)

            if (bIsWow64)
            {
                WOW64_CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                CHECK(Wow64GetThreadContext(hThread, &lcContext), continue);

                _tprintf(
                    _T("EAX = %08X\nEBX = %08X\nECX = %08X\n")
                    _T("EDX = %08X\nESI = %08X\nEDI = %08X\n")
                    _T("EIP = %08X\nESP = %08X\nEBP = %08X\n")
                    _T("EFL = %08X"),
                    lcContext.Eax, lcContext.Ebx, lcContext.Ecx,
                    lcContext.Edx, lcContext.Esi, lcContext.Edi,
                    lcContext.Eip, lcContext.Esp, lcContext.Ebp,
                    lcContext.EFlags
                );
            }
            else
            {
                CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                CHECK(GetThreadContext(hThread, &lcContext), continue);

                _tprintf(
                    _T("RAX = %016" PRIX64 "\tRBX = %016" PRIX64 "\tRCX = %016" PRIX64 "\tRDX = %016" PRIX64 "\n")
                    _T("RSI = %016" PRIX64 "\tRDI = %016" PRIX64 "\n")
                    _T("RIP = %016" PRIX64 "\tRSP = %016" PRIX64 "\tRBP = %016" PRIX64 "\n")
                    _T("EFL = %08" PRIX32 "\n"),
                    lcContext.Rax, lcContext.Rbx, lcContext.Rcx, lcContext.Rdx,
                    lcContext.Rsi, lcContext.Rdi,
                    lcContext.Rip, lcContext.Rsp, lcContext.Rbp,
                    lcContext.EFlags
                );
            }
        }
        else if (args[0] == TEXT("stack"))
        {
            std::vector<STACKFRAME64> stack = GetCallstack(hProcess, hThread);
            for (const STACKFRAME64& s : stack)
            {
                ShowStackFrame(hProcess, s.AddrPC.Offset);

#if 0
                IMAGEHLP_STACK_FRAME imghlp_frame = {};
                //imghlp_frame.InstructionOffset = (ULONG64) ExceptionRecord.ExceptionAddress;
                imghlp_frame.InstructionOffset = (ULONG64) s.AddrPC.Offset;
                CHECK_IGNORE(SymSetContext(hProcess, &imghlp_frame, nullptr), ERROR_SUCCESS, continue);

                DWORD64 BaseOfImage = SymGetModuleBase64(hProcess, (DWORD64) s.AddrPC.Offset);
                if (BaseOfImage == 0)
                    ShowError(TEXT("SymGetModuleBase64"), GetLastError());

                EnumSymProcData espdata = { hProcess, BaseOfImage, SYMFLAG_LOCAL, &lcContext };
                CHECK(SymEnumSymbols(hProcess, 0, "*", EnumSymProc, &espdata), continue);
#endif
            }
        }
        else if (args[0] == TEXT("mem"))
        {
            if (args.size() == 2)
            {
                const int LineLength = 16;
                DWORD64 Address = std::_tcstoull(args[1].c_str(), nullptr, 0);
                DWORD64 Length = 10 * LineLength;

                auto Memory = amalloc<BYTE>(Length);
                CHECK(ReadProcessMemory(hProcess,
                    (LPCVOID) Address,
                    Memory.get(),
                    Length * sizeof(BYTE), nullptr), continue);

                for (DWORD64 i = 0; i < Length; ++i)
                {
                    if ((i % LineLength) == 0)
                        _tprintf(_T("%p: "), (LPCVOID) (Address + i));
                    _tprintf(_T("%02x "), Memory[i]);
                    if (((i + 1) % LineLength) == 0)
                    {
                        for (DWORD64 j = i + 1 - LineLength; j <= i; ++j)
                        {
                            printf("%c", std::isprint(Memory[j]) ? Memory[j] : '.');
                        }
                        _tprintf(_T("\n"));
                    }
                }
            }
            else
                _tprintf(_T("Usage: mem [address]\n"));
        }
        else if (args[0] == TEXT("dump"))
        {
            _tprintf(_T("TODO\n"));
            // MiniDumpWriteDump
        }
        else if (args[0] == TEXT("source"))
        {
            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD disp = 0;
            if (!SymGetLineFromAddr64(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress, &disp, &line))
            {
                _tprintf(_T("No source data\n"));
                continue;
            }

            _tprintf(_T("%s:%d+%d\n"), line.FileName, line.LineNumber, disp);

            FILE* f = nullptr;
            _tfopen_s(&f, line.FileName, _T("r"));
            if (f != nullptr)
            {
                TCHAR linestr[1024];
                int LineNumber = 0;
                while (_fgetts(linestr, ARRAYSIZE(linestr), f))
                {
                    ++LineNumber;
                    if (LineNumber >= ((int) line.LineNumber - 3) && LineNumber < ((int) line.LineNumber + 5))
                        _tprintf(_T("%c%4d%s"), LineNumber == line.LineNumber ? _T('*') : _T(' '), LineNumber, linestr);
                    if (LineNumber >= ((int) line.LineNumber + 5))
                        break;
                }
                fclose(f);
            }
            else
                _ftprintf(stderr, _T(COLOR_ERROR "Error: fopen_s %s %d" COLOR_RETURN "\n"), line.FileName, errno);
        }
        else if (args[0] == TEXT("bp"))
        {
            if (args.size() == 1)
            {
                for (const BreakPoint& bp : m_breakpoints)
                {
                    _tprintf(_T("%c"), bp.Address == (ULONG64) ExceptionRecord.ExceptionAddress ? _T('*') : _T(' '));
                    ShowStackFrame(hProcess, bp.Address);
                    //_tprintf(_T("\n"));
                }
            }
            else if(args[1] == TEXT("add") && args.size() == 3)
            {
                ULONG64 Address = GetAddressFromName(hProcess, args[2].c_str(), true);
                if (Address != 0)
                    AddBreakpoint(hProcess, Address);
            }
            else
                _tprintf(_T("Unknown command\n"));
        }
        else if (args[0] == TEXT("threads"))
        {
            for (const auto& i : m_Threads)
            {
                const HANDLE hThisThread = i.second;

                ShowThread(hProcess, hThisThread, i.first, hThread == hThisThread);
            }
        }
        else if (args[0] == TEXT("thread"))
        {
            if (args.size() == 2)
            {
                DWORD dwNewThreadId = std::_tcstoul(args[1].c_str(), nullptr, 10);
                auto it = m_Threads.find(dwNewThreadId);
                if (it == m_Threads.end())
                    _tprintf(_T("Thread not found\n"));
                else
                {
                    dwThreadId = it->first;
                    hThread = it->second;

                    std::vector<STACKFRAME64> stack = GetCallstack(hProcess, hThread);

                    ShowStackFrame(hProcess, stack.front().AddrPC.Offset);
                }
            }
            else
                _tprintf(_T("Usage: thread [thread_id]\n"));
        }
        else if (args[0] == TEXT("threadse"))
        {
            HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, DebugEv.dwProcessId);
            if (h != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 te;
                te.dwSize = sizeof(te);
                BOOL bCont;
                for (bCont = Thread32First(h, &te); bCont; bCont = Thread32Next(h, &te))
                {
                    if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
                    {
                        if (te.th32OwnerProcessID == DebugEv.dwProcessId)
                        {
                            //const HANDLE hThisThread = GetThread(te.th32ThreadID);  // Shouldn't use GetThread
                            const HANDLE hThisThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                            if (hThisThread == NULL)
                                ShowError(TEXT("OpenThread"), GetLastError());
                            else
                            {
                                ShowThread(hProcess, hThisThread, te.th32ThreadID, hThread == hThisThread);
                                CloseHandle(hThisThread);
                            }
                        }
                    }
                    te.dwSize = sizeof(te);
                }
                CloseHandle(h);
            }
        }
        else if (args[0] == TEXT("symbols"))
        {
            if (args.size() > 2)
                _tprintf(_T("Usage: symbols [mask]\n"));
            else
            {
                LPCTSTR Mask = args.size() >= 2 ? args[1].c_str() : TEXT("*");

                DWORD64 BaseOfImage = SymGetModuleBase64(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress);
                if (BaseOfImage == 0)
                    ShowError(TEXT("SymGetModuleBase64"), GetLastError());

                EnumSymProcData espdata = { hProcess };
                CHECK(SymEnumSymbols(hProcess, BaseOfImage, Mask, EnumSymProc, &espdata), continue);
            }
        }
        else if (args[0] == TEXT("locals"))
        {
            if (args.size() > 2)
                _tprintf(_T("Usage: locals [mask]\n"));
            else
            {
                CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                CHECK(GetThreadContext(hThread, &lcContext), continue);

                std::vector<STACKFRAME64> stack = GetCallstack(hProcess, hThread);

                LPCTSTR Mask = args.size() >= 2 ? args[1].c_str() : TEXT("*");

                IMAGEHLP_STACK_FRAME imghlp_frame = {};
                //imghlp_frame.InstructionOffset = (ULONG64) ExceptionRecord.ExceptionAddress;
                imghlp_frame.InstructionOffset = (ULONG64) stack.front().AddrPC.Offset;
                CHECK_IGNORE(SymSetContext(hProcess, &imghlp_frame, nullptr), ERROR_SUCCESS, continue);

                EnumSymProcData espdata = { hProcess, SYMFLAG_LOCAL, lcContext.Rbp != 0 ? &lcContext : nullptr};
                CHECK(SymEnumSymbols(hProcess, 0, Mask, EnumSymProc, &espdata), continue);
            }
        }
        else if (args[0] == TEXT("parameters"))
        {
            if (args.size() == 2)
                _tprintf(_T("Usage: parameters [mask]\n"));
            else
            {
                CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                CHECK(GetThreadContext(hThread, &lcContext), continue);

                std::vector<STACKFRAME64> stack = GetCallstack(hProcess, hThread);

                LPCTSTR Mask = args.size() >= 2 ? args[1].c_str() : TEXT("*");

                IMAGEHLP_STACK_FRAME imghlp_frame = {};
                //imghlp_frame.InstructionOffset = (ULONG64) ExceptionRecord.ExceptionAddress;
                imghlp_frame.InstructionOffset = (ULONG64) stack.front().AddrPC.Offset;
                CHECK_IGNORE(SymSetContext(hProcess, &imghlp_frame, nullptr), ERROR_SUCCESS, continue);

                EnumSymProcData espdata = { hProcess, SYMFLAG_PARAMETER, lcContext.Rbp != 0 ? &lcContext : nullptr };
                CHECK(SymEnumSymbols(hProcess, 0, Mask, EnumSymProc, &espdata), continue);
            }
        }
        else if (args[0] == TEXT("detach"))
        {
            CHECK(DebugActiveProcessStop(DebugEv.dwProcessId), continue);
            return UserCommand::EXIT;
        }
        else if (args[0] == TEXT("exit"))
            return UserCommand::EXIT;
        else
            _tprintf(_T("Unknown command\n"));
    }

    return UserCommand::NONE;
}

DWORD Debugger::OnExceptionDebugEvent(const DEBUG_EVENT& DebugEv, const EXCEPTION_DEBUG_INFO& Exception)
{
    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);
    const HANDLE hThread = GetThread(DebugEv.dwThreadId);

    DWORD ret = DBG_CONTINUE;
    // Process the exception code. When handling 
    // exceptions, remember to set the continuation 
    // status parameter (dwContinueStatus). This value 
    // is used by the ContinueDebugEvent function. 
    const EXCEPTION_RECORD& ExceptionRecord = DebugEv.u.Exception.ExceptionRecord;

    switch (ExceptionRecord.ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        // First chance: Pass this on to the system. 
        // Last chance: Display an appropriate error. 
        _tprintf(_T(COLOR_MESSAGE "Access violation: " COLOR_RETURN "%s 0x%p (%llu), %llu)\n"),
            DebugEv.u.Exception.dwFirstChance ? _T("First-chance") : _T("Last-chance"),
            ExceptionRecord.ExceptionAddress, 
            ExceptionRecord.ExceptionInformation[0], ExceptionRecord.ExceptionInformation[1]);
        if (DebugEv.u.Exception.dwFirstChance)
            ret = DBG_EXCEPTION_NOT_HANDLED;
        else
        {
            ShowStackFrame(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress);

            m_LastCmd = UserInputLoop(DebugEv, ExceptionRecord);
            // ret = DBG_EXCEPTION_NOT_HANDLED;
        }
        break;

    case EXCEPTION_BREAKPOINT:
    {
        // First chance: Display the current 
        // instruction and register values. 

        // TODO Should it stop on the first breakpoint set by the system?

        MYASSERT(m_pLastBreakPoint == nullptr);

        bool found = false;
        for (const BreakPoint& bp : m_tempbreakpoints)
        {
            if (bp.hProcess == hProcess
                && (PVOID) bp.Address == ExceptionRecord.ExceptionAddress
                && bp.dwThreadId == DebugEv.dwThreadId)
            {
                MYASSERT(!found);
                found = true;
            }
        }
        if (found)
        {
            for (BreakPoint& bp : m_tempbreakpoints)
                bp.Unset();
            m_tempbreakpoints.clear();
        }

        for (BreakPoint& bp : m_breakpoints)
        {
            if (bp.hProcess == hProcess
                && (PVOID) bp.Address == ExceptionRecord.ExceptionAddress)
            {
                MYASSERT(!found);
                found = true;
                m_pLastBreakPoint = &bp;
                bp.Unset();
                break;
            }
        }

        if (found)
        {
            BOOL bIsWow64;
            CHECK(IsWow64Process(hProcess, &bIsWow64), 0);

            if (bIsWow64)
            {
                WOW64_CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                Wow64GetThreadContext(hThread, &lcContext);

                lcContext.Eip--; // Move back one byte
                if (m_pLastBreakPoint != nullptr)
                    lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                Wow64SetThreadContext(hThread, &lcContext);
            }
            else
            {
                CONTEXT lcContext = {};
                lcContext.ContextFlags = CONTEXT_ALL;
                GetThreadContext(hThread, &lcContext);

                lcContext.Rip--; // Move back one byte
                if (m_pLastBreakPoint != nullptr)
                    lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                SetThreadContext(hThread, &lcContext);
            }
        }

        if (found)
        {
            _tprintf(_T(COLOR_MESSAGE "Breakpoint: " COLOR_RETURN "0x%p\n"), ExceptionRecord.ExceptionAddress);

            ShowStackFrame(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress);

            ret = DBG_CONTINUE;
            m_LastCmd = UserInputLoop(DebugEv, ExceptionRecord);
        }
    }
    break;

    case EXCEPTION_DATATYPE_MISALIGNMENT:
        // First chance: Pass this on to the system. 
        // Last chance: Display an appropriate error. 
        _tprintf(_T(COLOR_MESSAGE "Data type misalignment: " COLOR_RETURN "0x%p\n"), ExceptionRecord.ExceptionAddress);
        break;

    case EXCEPTION_SINGLE_STEP:
        // First chance: Update the display of the 
        // current instruction and register values. 
    {
        ret = DBG_CONTINUE;
        if (m_pLastBreakPoint != nullptr)
        {
            m_pLastBreakPoint->Set();
            m_pLastBreakPoint = nullptr;
        }

        bool DoUserInputLoop = false;

        if (m_LastCmd == UserCommand::STEP_IN)
        {
            IMAGEHLP_LINE64 line = {};
            line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD disp = 0;
            CHECK(SymGetLineFromAddr64(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress, &disp, &line), DoUserInputLoop = true)
            else
            {
                if (line.LineNumber == m_CurrentLine.LineNumber
                    && _tcscpy_s(line.FileName, MAX_PATH, m_CurrentLine.FileName) == 0)
                {
                    CONTEXT lcContext = {};
                    lcContext.ContextFlags = CONTEXT_ALL;
                    GetThreadContext(hThread, &lcContext);

                    lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                    SetThreadContext(hThread, &lcContext);
                }
                else
                    DoUserInputLoop = true;
            }
        }

        if (DoUserInputLoop)
        {
            _tprintf(_T(COLOR_MESSAGE "Single step: " COLOR_RETURN "0x%p\n"), ExceptionRecord.ExceptionAddress);
            ShowStackFrame(hProcess, (DWORD64) ExceptionRecord.ExceptionAddress);
            m_LastCmd = UserInputLoop(DebugEv, ExceptionRecord);
        }
    }
    break;

    case DBG_CONTROL_C:
        // First chance: Pass this on to the system. 
        // Last chance: Display an appropriate error. 
        _tprintf(_T(COLOR_MESSAGE "Control C: " COLOR_RETURN "0x%p\n"), ExceptionRecord.ExceptionAddress);
        break;

    case 0x406d1388: // Set thread name
    {   // https://learn.microsoft.com/en-us/archive/blogs/stevejs/naming-threads-in-win32-and-net
        _tprintf(_T(COLOR_MESSAGE "Set thread name: " COLOR_RETURN "%s 0x%p 0x%08x"),
            DebugEv.u.Exception.dwFirstChance ? _T("First-chance") : _T("Last-chance"),
            ExceptionRecord.ExceptionAddress,
            ExceptionRecord.ExceptionCode);
        if (ExceptionRecord.NumberParameters > 0)
        {
            _tprintf(_T(" (%llu"), ExceptionRecord.ExceptionInformation[0]);
            for (DWORD i = 1; i < ExceptionRecord.NumberParameters; ++i)
                _tprintf(_T(", %llu"), ExceptionRecord.ExceptionInformation[i]);
            _tprintf(_T(")"));
        }
        _tprintf(_T("\n"));

        struct THREADNAME_INFO
        {
            DWORD dwType; // must be 0x1000
            LPCSTR szName; // pointer to name (in user addr space)
            DWORD dwThreadID; // thread ID (-1=caller thread)
            DWORD dwFlags; // reserved for future use, must be zero
        };
        // RaiseException(0x406D1388, 0, sizeof(info) / sizeof(DWORD), (DWORD*) &info)
    }
        break;

    default:
        // Handle other exceptions. 
        _tprintf(_T(COLOR_MESSAGE "Other exception: " COLOR_RETURN "%s 0x%p 0x%08x"),
            DebugEv.u.Exception.dwFirstChance ? _T("First-chance") : _T("Last-chance"),
            ExceptionRecord.ExceptionAddress,
            ExceptionRecord.ExceptionCode);
        if (ExceptionRecord.NumberParameters > 0)
        {
            _tprintf(_T(" (%llu"), ExceptionRecord.ExceptionInformation[0]);
            for (DWORD i = 1; i < ExceptionRecord.NumberParameters; ++i)
                _tprintf(_T(", %llu"), ExceptionRecord.ExceptionInformation[i]);
            _tprintf(_T(")"));
        }
        _tprintf(_T("\n"));
        break;
    }

    return ret;
}

DWORD Debugger::OnCreateThreadDebugEvent(const DEBUG_EVENT& DebugEv, const CREATE_THREAD_DEBUG_INFO& CreateThread)
{
    _tprintf(_T(COLOR_INFO "Create thread: " COLOR_RETURN));

    // As needed, examine or change the thread's registers 
    // with the GetThreadContext and SetThreadContext functions; 
    // and suspend and resume thread execution with the 
    // SuspendThread and ResumeThread functions. 

    _tprintf(_T("%d at: 0x%p\n"),
        DebugEv.dwThreadId,
        CreateThread.lpStartAddress);

    // TODO Check GetThread(DebugEv.dwThreadId) == NULL;
    m_Threads[DebugEv.dwThreadId] = CreateThread.hThread;

    return DBG_CONTINUE;
}

DWORD Debugger::OnCreateProcessDebugEvent(const DEBUG_EVENT& DebugEv, const CREATE_PROCESS_DEBUG_INFO& CreateProcessInfo)
{
    _tprintf(_T(COLOR_INFO "Create process: " COLOR_RETURN));

    // As needed, examine or change the registers of the
    // process's initial thread with the GetThreadContext and
    // SetThreadContext functions; read from and write to the
    // process's virtual memory with the ReadProcessMemory and
    // WriteProcessMemory functions; and suspend and resume
    // thread execution with the SuspendThread and ResumeThread
    // functions. Be sure to close the handle to the process image
    // file with CloseHandle.

    const int FileNameSize = 32767;
    auto FileName = amalloc<TCHAR>(FileNameSize);
    FileName[0] = TEXT('\0');
    GetFinalPathNameByHandle(CreateProcessInfo.hFile, FileName.get(), FileNameSize, FILE_NAME_OPENED | VOLUME_NAME_DOS);
    _tprintf(_T("%s"), FileName.get() + 4); // Skip "\\?\"
    CloseHandle(CreateProcessInfo.hFile);

    m_Processes[DebugEv.dwProcessId] = CreateProcessInfo.hProcess;
    m_Threads[DebugEv.dwThreadId] = CreateProcessInfo.hThread;

    const HANDLE hProcess = CreateProcessInfo.hProcess;

    CHECK(SymInitialize(hProcess, nullptr, FALSE), 0);

    CHECK(SymLoadModuleEx(hProcess, 0, FileName.get(), 0, (DWORD64) CreateProcessInfo.lpBaseOfImage, 0, nullptr, 0) != 0, 0);

    IMAGEHLP_MODULE64 Module = {};
    Module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    LPCTSTR szSymType = TEXT("-unknown-");
    CHECK(SymGetModuleInfo64(hProcess, (DWORD64) CreateProcessInfo.lpBaseOfImage, &Module), 0)
    else
        szSymType = GetSymType(Module.SymType);

    _tprintf(_T(", %s\n"), szSymType);

    for (LPCTSTR Name : { TEXT("mainCRTStartup"), TEXT("wWinMainCRTStartup"), TEXT("main"), TEXT("wmain"), TEXT("WinMain"), TEXT("wWinMain") })
    {
        ULONG64 Address = GetAddressFromName(hProcess, Name, false);
        if (Address != 0)
            AddBreakpoint(hProcess, Address);
    }

    return DBG_CONTINUE;
}

DWORD Debugger::OnExitThreadDebugEvent(const DEBUG_EVENT& DebugEv, const EXIT_THREAD_DEBUG_INFO& ExitThread)
{
    _tprintf(_T(COLOR_INFO "Exit thread: " COLOR_RETURN));

    // Display the thread's exit code. 

    HANDLE hThread = GetThread(DebugEv.dwThreadId);

    _tprintf(_T("%d exited with code: 0x%x (%d))\n"),
        DebugEv.dwThreadId,
        ExitThread.dwExitCode,
        ExitThread.dwExitCode);

    m_Threads.erase(DebugEv.dwThreadId);

    return DBG_CONTINUE;
}

DWORD Debugger::OnExitProcessDebugEvent(const DEBUG_EVENT& DebugEv, const EXIT_PROCESS_DEBUG_INFO& ExitProcess)
{
    _tprintf(_T(COLOR_INFO "Exit process: " COLOR_RETURN));

    // Display the process's exit code. 

    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);

    _tprintf(_T("exited with code: 0x%x (%d))\n"), ExitProcess.dwExitCode, ExitProcess.dwExitCode);

    m_Threads.erase(DebugEv.dwThreadId);

    SymCleanup(hProcess);

    m_Processes.erase(DebugEv.dwProcessId);

    return DBG_CONTINUE;
}

DWORD Debugger::OnLoadDllDebugEvent(const DEBUG_EVENT& DebugEv, const LOAD_DLL_DEBUG_INFO& LoadDll)
{
    _tprintf(_T(COLOR_INFO "Load DLL: " COLOR_RETURN));

    // Read the debugging information included in the newly 
    // loaded DLL. Be sure to close the handle to the loaded DLL 
    // with CloseHandle.

    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);

    const int FileNameSize = 32767;
    auto FileName = amalloc<TCHAR>(FileNameSize);
    FileName[0] = '\0';
    GetFinalPathNameByHandle(LoadDll.hFile, FileName.get(), FileNameSize, FILE_NAME_OPENED | VOLUME_NAME_DOS);
    _tprintf(_T("%s"), FileName.get() + 4); // Skip "\\?\"
    CloseHandle(LoadDll.hFile);

    CHECK(SymLoadModuleEx(hProcess, 0, FileName.get(), 0, (DWORD64) LoadDll.lpBaseOfDll, 0, nullptr, 0) != 0, 0);

    IMAGEHLP_MODULE64 Module = {};
    Module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    LPCTSTR szSymType = TEXT("-unknown-");
    CHECK(SymGetModuleInfo64(hProcess, (DWORD64) LoadDll.lpBaseOfDll, &Module), 0)

    _tprintf(_T(", %s\n"), szSymType);

    m_DLLs[LoadDll.lpBaseOfDll] = FileName.get() + 4; // Skip "\\?\"

    return DBG_CONTINUE;
}

DWORD Debugger::OnUnloadDllDebugEvent(const DEBUG_EVENT& DebugEv, const UNLOAD_DLL_DEBUG_INFO& UnloadDll)
{
    _tprintf(_T(COLOR_INFO "Unload DLL: " COLOR_RETURN));

    // Display a message that the DLL has been unloaded. 

#if 0
    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);

    // I suspect this is causing the dll to be loaded again
    IMAGEHLP_MODULE64 Module = {};
    Module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    LPCTSTR szSymType = "-unknown-";
    CHECK(SymGetModuleInfo64(hProcess, (DWORD64) UnloadDll.lpBaseOfDll, &Module), 0)

    _tprintf(_T("%s\n"), Module.ImageName + 4); // Skip "\\?\"
#elif 1
    auto it = m_DLLs.find(UnloadDll.lpBaseOfDll);
    if (it != m_DLLs.end())
    {
        _tprintf(_T("%s\n"), it->second.c_str());
        // TODO sometimes dlls get loaded twice, may need to keep a count here
        m_DLLs.erase(it);
    }
    else
        _tprintf(_T("0x%p\n"), UnloadDll.lpBaseOfDll);
#else
    _tprintf(_T("0x%p\n"), UnloadDll.lpBaseOfDll);
#endif

    return DBG_CONTINUE;
}

DWORD Debugger::OnOutputDebugStringEvent(const DEBUG_EVENT& DebugEv, const OUTPUT_DEBUG_STRING_INFO& DebugString)
{
    _tprintf(_T(COLOR_MESSAGE "Debug: " COLOR_RETURN));

    // Display the output debugging string.

    const HANDLE hProcess = GetProcess(DebugEv.dwProcessId);

    if (DebugString.fUnicode)
    {
        auto msg = amalloc<WCHAR>(DebugString.nDebugStringLength);
        CHECK(ReadProcessMemory(hProcess,
            DebugString.lpDebugStringData,
            msg.get(),
            DebugString.nDebugStringLength * sizeof(WCHAR), nullptr), 0);
        wprintf(msg.get());
    }
    else
    {
        auto msg = amalloc<CHAR>(DebugString.nDebugStringLength);
        CHECK(ReadProcessMemory(hProcess,
            DebugString.lpDebugStringData,
            msg.get(),
            DebugString.nDebugStringLength * sizeof(CHAR), nullptr), 0);
        printf(msg.get());
    }

    return DBG_CONTINUE;
}

DWORD Debugger::OnRipEvent(const DEBUG_EVENT& DebugEv, const RIP_INFO& RipInfo)
{
    _tprintf(_T(__FUNCTION__ "\n"));

    return DBG_CONTINUE;
}

void Debugger::DoEventLoop()
{
    DEBUG_EVENT DebugEv = {};

    bool bContinue = true;
    while (bContinue)
    {
        CHECK(WaitForDebugEvent(&DebugEv, INFINITE), return);

        DWORD dwContinueStatus = DBG_CONTINUE;
        switch (DebugEv.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:         dwContinueStatus = OnExceptionDebugEvent(DebugEv, DebugEv.u.Exception); break;
        case CREATE_THREAD_DEBUG_EVENT:     dwContinueStatus = OnCreateThreadDebugEvent(DebugEv, DebugEv.u.CreateThread); break;
        case CREATE_PROCESS_DEBUG_EVENT:    dwContinueStatus = OnCreateProcessDebugEvent(DebugEv, DebugEv.u.CreateProcessInfo); break;
        case EXIT_THREAD_DEBUG_EVENT:       dwContinueStatus = OnExitThreadDebugEvent(DebugEv, DebugEv.u.ExitThread); break;
        case EXIT_PROCESS_DEBUG_EVENT:      dwContinueStatus = OnExitProcessDebugEvent(DebugEv, DebugEv.u.ExitProcess); break;
        case LOAD_DLL_DEBUG_EVENT:          dwContinueStatus = OnLoadDllDebugEvent(DebugEv, DebugEv.u.LoadDll); break;
        case UNLOAD_DLL_DEBUG_EVENT:        dwContinueStatus = OnUnloadDllDebugEvent(DebugEv, DebugEv.u.UnloadDll); break;
        case OUTPUT_DEBUG_STRING_EVENT:     dwContinueStatus = OnOutputDebugStringEvent(DebugEv, DebugEv.u.DebugString); break;
        case RIP_EVENT:                     dwContinueStatus = OnRipEvent(DebugEv, DebugEv.u.RipInfo); break;
        }

        ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);

        if (DebugEv.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT or m_LastCmd == UserCommand::EXIT)
        {
            // TODO Kill or release the process
            bContinue = false;
        }
    }
}

BOOL StartDebugProcess(const int argc, const TCHAR* argv[])
{
    TCHAR cmd[MAX_PATH] = TEXT("");
    for (int i = 0; i < argc; ++i)
    {
        if (i != 0)
            StringCchCat(cmd, ARRAYSIZE(cmd), TEXT(" "));
        // TODO Use quotes where necessary
        StringCchCat(cmd, ARRAYSIZE(cmd), argv[i]);
    }

    STARTUPINFO si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    CHECK(CreateProcess(nullptr, cmd, nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi), return FALSE)
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TRUE;
    }
}

Debugger* g_pdbg = nullptr;

BOOL WINAPI ConsoleCtrlHandler(_In_ DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_BREAK_EVENT:
        _tprintf(_T("Ctrl-Break\n"));
        g_pdbg->BreakProcess();
        return TRUE;

    default:
        return FALSE;
    }
}

bool ParseProcessId(LPCTSTR pStr, DWORD* ppid)
{
    TCHAR* pend = nullptr;
    *ppid = std::_tcstoul(pStr, &pend, 10);
    return *pend == TEXT('\0');
}

int _tmain(const int argc, const TCHAR* argv[])
{
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    Debugger dbg;
    g_pdbg = &dbg;

    DWORD pid = 0;
    if (argc == 2 && ParseProcessId(argv[1], &pid))
    {
        CHECK(DebugActiveProcess(pid), return EXIT_FAILURE);
    }
    else if (!StartDebugProcess(argc - 1, argv + 1))
        return EXIT_FAILURE;

    dbg.DoEventLoop();

    g_pdbg = nullptr;
    return EXIT_SUCCESS;
}
