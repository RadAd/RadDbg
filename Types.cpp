#include "Types.h"

#include <tchar.h>
#include <DbgHelp.h>

#include "cvconst.h"

#include "Utils.h"

static void ShowTypeData(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    WCHAR* pName = nullptr;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMNAME, &pName), 0)
    else
    {
        _tprintf(_T(" " COLOR_TYPENAME "%s" COLOR_RETURN), pName);
        LocalFree(pName);
    }

    DWORD TypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &TypeIndex), 0)
    else
    {
        _tprintf(_T(":("));
        ShowType(hProcess, ModBase, TypeIndex, nullptr, 0);
        _tprintf(_T(")"));
    }

    DWORD dataKind = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_DATAKIND, &dataKind), 0)
    else
    {
        switch (dataKind)
        {
        //case DataIsGlobal:
        //case DataIsStaticLocal:
        //case DataIsFileStatic:
        //case DataIsStaticMember:
        //case DataIsLocal:
        //case DataIsParam:
        //case DataIsObjectPtr:
        //case DataIsMember:
        //break;

        case DataIsConstant:
        {
            VARIANT var;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_VALUE, &var), 0)
            else
            {
                switch (var.vt)
                {   // https://www.quickmacros.com/help/Tables/IDP_VARIANT.html
                case VT_I2: _tprintf(_T(":%d"), var.iVal); break;
                case VT_INT: _tprintf(_T(":%d"), var.intVal); break;
                default: _tprintf(_T(" Unknown type %u"), var.vt); break;
                }
            }
        }

        default:
            break;
        }
    }
}

void ShowTypeUDTClass(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    WCHAR* pName = nullptr;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMNAME, &pName), 0)
    else
    {
        _tprintf(_T(" " COLOR_TYPENAME "%s" COLOR_RETURN), pName);
        LocalFree(pName);
    }
}

static void ShowTypeUDT(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    DWORD UDTKind = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_UDTKIND, &UDTKind), 0)
    else
    {
        switch ((enum UdtKind) UDTKind)
        {
        case UdtStruct: _tprintf(_T(" struct")); ShowTypeUDTClass(hProcess, ModBase, TypeId); break;
        case UdtClass: _tprintf(_T(" class")); ShowTypeUDTClass(hProcess, ModBase, TypeId); break;
        case UdtUnion: //DumpUDTUnion(Index, Info.Info.sUdtUnionInfo); break;
        default: _tprintf(_T(" type:%d"), UDTKind); break;
        }
    }
}

static void ShowTypeEnum(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    WCHAR* pName = nullptr;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMNAME, &pName), 0)
    else
    {
        _tprintf(_T(" enum " COLOR_TYPENAME "%s" COLOR_RETURN), pName);
        LocalFree(pName);
    }

    DWORD TypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &TypeIndex), 0)
    else
    {
        //_tprintf(_T(" TypeIndex %u"), TypeIndex);
        _tprintf(_T(":("));
        ShowType(hProcess, ModBase, TypeIndex, nullptr, 0);
        _tprintf(_T(")"));
    }

    DWORD Nested = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_NESTED, &Nested), 0)
    else
    {
        if (Nested != 0)
            _tprintf(_T(" Nested %u"), Nested);   // TODO What does this mean?
    }

#if 0
    DWORD NumChildren = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CHILDRENCOUNT, &NumChildren), 0)
    else
    {
        //_tprintf(_T(" NumChildren %u"), NumChildren);
        auto pFC = zmalloc<TI_FINDCHILDREN_PARAMS>(NumChildren * sizeof(ULONG));
        pFC->Count = NumChildren;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_FINDCHILDREN, pFC.get()), 0)
        else
        {
            _tprintf(_T(" {"));
            for (DWORD i = 0; i < NumChildren; ++i)
            {
                if (i != 0)
                    _tprintf(_T(","));
                //_tprintf(_T(" %u"), pFC->ChildId[i]);
                ShowType(hProcess, ModBase, pFC->ChildId[i], nullptr, 0);
            }
            _tprintf(_T("}"));
        }
    }
#endif
}

static void ShowTypeFunctionType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, LPCTSTR pName, int pointer)
{
    DWORD Type = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPE, &Type), 0)
    else
    {
        ShowType(hProcess, ModBase, Type, nullptr, 0);
    }

    DWORD NumArgs = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_COUNT, &NumArgs), 0)

        DWORD CallConv = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CALLING_CONVENTION, &CallConv), 0)
    else
    {
        // TODO CV_call_e;
    }

    if (pointer > 0)
    {
        _tprintf(_T(" ("));
        if (pName != nullptr)
            _tprintf(_T(COLOR_NAME "%s" COLOR_RETURN), pName);
        while (pointer > 0)
        {
            _tprintf(_T("*"));
            --pointer;
        }
        _tprintf(_T(")"));
    }
    else
        _tprintf(_T(" " COLOR_NAME "%s" COLOR_RETURN), pName);

    ULONG ThisAdjust = 0;
    if (SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_THISADJUST, &ThisAdjust))
    {
        if (ThisAdjust != 0)
        {
            _tprintf(_T(" ThisAdjust:%lu"), ThisAdjust);
            NOT_IMPLEMENTED;
        }
    }

    DWORD NumChildren = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CHILDRENCOUNT, &NumChildren), 0)
    else
    {
        //MYASSERT(NumArgs == NumChildren);

#if 1
        auto pFC = zmalloc<TI_FINDCHILDREN_PARAMS>(NumChildren * sizeof(ULONG));
        pFC->Count = NumChildren;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_FINDCHILDREN, pFC.get()), 0)
    else
    {
        _tprintf(_T("("));
        for (DWORD i = 0; i < NumChildren; ++i)
        {
            if (i != 0)
                _tprintf(_T(","));
            //_tprintf(_T(" %u"), pFC->ChildId[i]);
            ShowType(hProcess, ModBase, pFC->ChildId[i], nullptr, 0);
        }
        _tprintf(_T(")"));
    }
#endif
    }
}

static void ShowTypePointerType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, LPCTSTR pName, int pointer)
{
    DWORD Type = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPE, &Type), 0)
    else
    {
        ShowType(hProcess, ModBase, Type, pName, pointer);
    }
}

static void ShowTypeArrayType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    DWORD ElementTypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &ElementTypeIndex), 0)
    else
    {
        ShowType(hProcess, ModBase, ElementTypeIndex, nullptr, 0);
    }

    ULONG64 ElementSize = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, ElementTypeIndex, TI_GET_LENGTH, &ElementSize), 0)

    ULONG64 Length = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0)
    else
    {
        ULONG64 Count = Length / ElementSize;

        _tprintf(_T("[%llu:("), Count);

        DWORD IndexTypeIndex = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_ARRAYINDEXTYPEID, &IndexTypeIndex), 0)
        else
        {
            ShowType(hProcess, ModBase, IndexTypeIndex, nullptr, 0);
        }

        _tprintf(_T(")]"));
    }

    // CTypeInfoDump::ArrayDims( ULONG Index, ULONG64* pDims, int& Dims, int MaxDims ) 
}

static void ShowTypeBaseType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    DWORD BaseType = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_BASETYPE, &BaseType), 0)
    else
    {
        switch ((enum BasicType) BaseType)
        {
        case btNoType:      _tprintf(_T(" notype")); break;
        case btVoid:        _tprintf(_T(" void")); break;
        case btChar:        _tprintf(_T(" char")); break;
        case btWChar:       _tprintf(_T(" wchar")); break;
        case btInt:         _tprintf(_T(" int")); break;
        case btUInt:        _tprintf(_T(" uint")); break;
        case btFloat:       _tprintf(_T(" float")); break;
        case btBCD:         _tprintf(_T(" bcd")); break;
        case btBool:        _tprintf(_T(" bool")); break;
        case btLong:        _tprintf(_T(" long")); break;
        case btULong:       _tprintf(_T(" ulong")); break;
        case btCurrency:    _tprintf(_T(" currency")); break;
        case btDate:        _tprintf(_T(" dat")); break;
        case btVariant:     _tprintf(_T(" variant")); break;
        case btComplex:     _tprintf(_T(" complex")); break;
        case btBit:         _tprintf(_T(" bit")); break;
        case btBSTR:        _tprintf(_T(" BSTR")); break;
        case btHresult:     _tprintf(_T(" HResult")); break;
        default:            _tprintf(_T(" type:%d"), BaseType); break;
        }
    }
}

static void ShowTypeFunctionArgType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId)
{
    DWORD TypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &TypeIndex), 0)
    else
    {
        ShowType(hProcess, ModBase, TypeIndex, nullptr, 0);
    }
}

void ShowType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, LPCTSTR pName, int pointer)
{
    DWORD Tag = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMTAG, &Tag), 0)
    else
    {
        bool showPostName = true;
        //_tprintf(_T(" %u"), Tag);
        switch ((enum SymTagEnum) Tag)
        {
        case SymTagData: ShowTypeData(hProcess, ModBase, TypeId); break;
        case SymTagUDT: ShowTypeUDT(hProcess, ModBase, TypeId); break;
        case SymTagEnum: ShowTypeEnum(hProcess, ModBase, TypeId); break;
        case SymTagFunctionType: ShowTypeFunctionType(hProcess, ModBase, TypeId, pName, pointer); showPostName = false; break;
        case SymTagPointerType: ShowTypePointerType(hProcess, ModBase, TypeId, pName, pointer + 1); showPostName = false; break;
        case SymTagArrayType: ShowTypeArrayType(hProcess, ModBase, TypeId); break;
        case SymTagBaseType: ShowTypeBaseType(hProcess, ModBase, TypeId); break;
        case SymTagFunctionArgType: ShowTypeFunctionArgType(hProcess, ModBase, TypeId); break;
        default: _tprintf(_T(" Unknown tag: %u " COLOR_NAME "%s" COLOR_RETURN), Tag, pName);
        }

        if (showPostName)
        {
            while (pointer > 0)
            {
                _tprintf(_T("*"));
                --pointer;
            }
            if (pName != nullptr)
                _tprintf(_T(" " COLOR_NAME "%s" COLOR_RETURN), pName);
        }
    }
}
