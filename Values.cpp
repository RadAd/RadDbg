#include "Values.h"

#include <DbgHelp.h>
#include <propvarutil.h>

#include "cvconst.h"

#include "Types.h"
#include "Utils.h"

DWORD64 GetRegValue(ULONG reg, const CONTEXT& context)
{
    switch (reg)
    {
#ifdef _M_IX86
    case CV_REG_EBP: return context.Ebp;
    case CV_REG_ESP: return context.Esp;
#elif _M_X64
    case CV_AMD64_RBP: return context.Rbp;
    case CV_AMD64_RSP: return context.Rsp;
#endif
    default: NOT_IMPLEMENTED; return 0;
    }
}

void ShowValueBaseType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, VARIANT* pValue);

static void ShowValueData(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    DWORD dataKind = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_DATAKIND, &dataKind), 0)
    else
    {
        switch ((enum DataKind) dataKind)
        {
        case DataIsGlobal:
        case DataIsStaticLocal:
        case DataIsFileStatic:
        case DataIsStaticMember:
        {
            // Use Address; Offset is not defined

            // Note: If it is DataIsStaticMember, then this is a static member 
            // of a class defined in another module 
            // (it does not have an address in this module) 

            ULONG64 DataAddress = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_ADDRESS, &DataAddress), 0)
            else
            {
                printf(" Address %llu", DataAddress);
                NOT_IMPLEMENTED;
            }
        }
        break;

        case DataIsLocal:
        case DataIsParam:
        case DataIsObjectPtr:
        case DataIsMember:
        {
            // Use Offset; Address is not defined

            DWORD DataTypeId = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPE, &DataTypeId), 0)
            else
            {
                ULONG Offset = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_OFFSET, &Offset), 0)
                else
                {
                    ShowValue(hProcess, ModBase, DataTypeId, Address + Offset);
                }
            }
        }
        break;

        case DataIsConstant:
        {
            WCHAR* pName = nullptr;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMNAME, &pName), 0)
            else
            {
                wprintf(L" " COLOR_TYPENAME "%s" COLOR_RETURN, pName);
                LocalFree(pName);
            }

            VARIANT var;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_VALUE, &var), 0)
            else
            {
                switch (var.vt)
                {   // https://www.quickmacros.com/help/Tables/IDP_VARIANT.html
                case VT_I2: printf(":%d", var.iVal); break;
                case VT_INT: printf(":%d", var.intVal); break;
                default: printf(" Unknown type %u", var.vt); NOT_IMPLEMENTED; break;
                }
            }
        }
        break;

        default:
            // Unknown location 
            NOT_IMPLEMENTED;
            break;
        }
    }
}

static void ShowValueUDT(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    wprintf(L" {");
    DWORD NumChildren = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CHILDRENCOUNT, &NumChildren), 0)
    else
    {
        auto pFC = zmalloc<TI_FINDCHILDREN_PARAMS>(NumChildren * sizeof(ULONG));
        pFC->Count = NumChildren;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_FINDCHILDREN, pFC.get()), 0)
        else
        {
            for (DWORD i = 0; i < NumChildren; ++i)
            {
                if (i != 0)
                    wprintf(L",");

                ULONG ChildTypeId = pFC->ChildId[i];

                ShowType(hProcess, ModBase, ChildTypeId, nullptr, 0);

                wprintf(L" =");

                ShowValue(hProcess, ModBase, ChildTypeId, Address);
            }
        }
    }
    wprintf(L" }");
}

LONGLONG VariantToInt64(_In_ REFVARIANT var)
{
    MYASSERT(IsVarTypeSignedInteger(var.vt));
    switch (var.vt)
    {
    case VT_I1: return var.cVal;
    case VT_I2: return var.iVal;
    case VT_I4: return var.lVal;
    case VT_I8: return var.llVal;
    default:    return 0;
    }
}

LONGLONG VariantToUInt64(_In_ REFVARIANT var)
{
    MYASSERT(IsVarTypeUnsignedInteger(var.vt));
    switch (var.vt)
    {
    case VT_UI1: return var.bVal;
    case VT_UI2: return var.uiVal;
    case VT_UI4: return var.ulVal;
    case VT_UI8: return var.ullVal;
    default:    return 0;
    }
}

static int MyVariantCompare(_In_ REFVARIANT var1, _In_ REFVARIANT var2)
{
    if (var1.vt == var2.vt)
        return VariantCompare(var1, var2);
    else if (IsVarTypeSignedInteger(var1.vt) && IsVarTypeSignedInteger(var1.vt))
    {
        VARIANT var1_64;
        InitVariantFromInt64(VariantToInt64(var1), &var1_64);
        VARIANT var2_64;
        InitVariantFromInt64(VariantToInt64(var2), &var2_64);
        return VariantCompare(var1_64, var2_64);
    }
    else if (IsVarTypeUnsignedInteger(var1.vt) && IsVarTypeUnsignedInteger(var1.vt))
    {
        VARIANT var1_64;
        InitVariantFromUInt64(VariantToUInt64(var1), &var1_64);
        VARIANT var2_64;
        InitVariantFromUInt64(VariantToUInt64(var2), &var2_64);
        return VariantCompare(var1_64, var2_64);
    }
    else
        return -1;
}

static void ShowValueEnumChild(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, VARIANT value)
{
    bool found = false;

    DWORD NumChildren = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CHILDRENCOUNT, &NumChildren), 0)
    else
    {
        //printf(" NumChildren %u", NumChildren);
        auto pFC = zmalloc<TI_FINDCHILDREN_PARAMS>(NumChildren * sizeof(ULONG));
        pFC->Count = NumChildren;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_FINDCHILDREN, pFC.get()), 0)
        else
        {
            for (DWORD i = 0; i < NumChildren; ++i)
            {
                ULONG ChildTypeId = pFC->ChildId[i];

                DWORD Tag = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_SYMTAG, &Tag), 0)
                else
                    CHECK(((enum SymTagEnum) Tag) == SymTagData, 0);

                DWORD dataKind = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_DATAKIND, &dataKind), 0)
                else
                    CHECK(((enum DataKind) dataKind) == DataIsConstant, 0);

                VARIANT var;
                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_VALUE, &var), 0)
                else
                {
                    if (MyVariantCompare(var, value) == 0)
                    {
                        found = true;

                        WCHAR* pName = nullptr;
                        CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_SYMNAME, &pName), 0)
                        else
                        {
                            wprintf(L" : " COLOR_TYPENAME "%s" COLOR_RETURN, pName);
                            LocalFree(pName);
                        }
                        break;
                    }
                }
            }
        }
    }

    MYASSERT(found);
}

static void ShowValueEnum(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    DWORD TypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &TypeIndex), 0)
    else
    {
        DWORD Tag = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeIndex, TI_GET_SYMTAG, &Tag), 0)
        else
            CHECK(((enum SymTagEnum) Tag) == SymTagBaseType, 0);

        VARIANT value = { VT_EMPTY };
        ShowValueBaseType(hProcess, ModBase, TypeIndex, Address, &value);
        MYASSERT(value.vt != VT_EMPTY);

        ShowValueEnumChild(hProcess, ModBase, TypeId, value);
    }
}

static void ShowValueFunctionType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    auto pSymbol = zmalloc<IMAGEHLP_SYMBOL>(MAX_SYM_NAME);
    pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
    DWORD64 disp;
    CHECK(SymGetSymFromAddr(hProcess, Address, &disp, pSymbol.get()), 0)
    else
    {
        if (pSymbol->Name[0] != TEXT('\0'))
            printf(" : %s", pSymbol->Name);
    }
}

static void ShowValuePointerType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    ULONG64 Length = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0)
    else if (Length == 8)
    {
        DWORD64 NewAddress = 0;
        ReadProcessMemory(hProcess,
            (LPCVOID) Address,
            &NewAddress,
            (SIZE_T) Length, nullptr);

        printf(" 0x%p", (PVOID) NewAddress);

        DWORD Type = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPE, &Type), 0)
        else
        {
            if (NewAddress != 0)
                ShowValue(hProcess, ModBase, Type, NewAddress);
        }
    }
    else
    {
        printf(" Address length:%llu", Length);
        NOT_IMPLEMENTED;
    }
}

static void ShowValueArrayType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    DWORD ElementTypeIndex = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPEID, &ElementTypeIndex), 0)
    else
    {
        bool bDoDefault = true;

        DWORD Tag = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, ElementTypeIndex, TI_GET_SYMTAG, &Tag), 0)
        else if (((enum SymTagEnum) Tag) == SymTagBaseType)
        {
            DWORD BaseType = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, ElementTypeIndex, TI_GET_BASETYPE, &BaseType), 0)
            else if (((enum BasicType) BaseType) == btChar)
            {
                ULONG64 Length = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0)
                else
                {
                    bDoDefault = false;
                    CHAR* msg = new CHAR[(SIZE_T) Length / sizeof(CHAR)];
                    ReadProcessMemory(hProcess,
                        (LPCVOID) Address,
                        msg,
                        (SIZE_T) Length, nullptr);

                    printf(" \"%s\"", msg);
                    delete[] msg;
                }
            }
            else if (((enum BasicType) BaseType) == btWChar)
            {
                ULONG64 Length = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0)
                else
                {
                    bDoDefault = false;
                    WCHAR* msg = new WCHAR[(SIZE_T) Length / sizeof(WCHAR)];
                    ReadProcessMemory(hProcess,
                        (LPCVOID) Address,
                        msg,
                        (SIZE_T) Length, nullptr);

                    wprintf(L" \"%s\"", msg);
                    delete[] msg;
                }
            }
        }

        if (bDoDefault)
        {
            ULONG64 ElementSize = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, ElementTypeIndex, TI_GET_LENGTH, &ElementSize), 0)

            ULONG64 Length = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0)
            else
            {
                ULONG64 Count = Length / ElementSize;
                printf(" [");

                for (int i = 0; i < Count; ++i)
                {
                    if (i != 0)
                        printf(", ");
                    ShowValue(hProcess, ModBase, ElementTypeIndex, Address + i * ElementSize);
                }

                printf(" ]");
            }
        }
    }

    // CTypeInfoDump::ArrayDims( ULONG Index, ULONG64* pDims, int& Dims, int MaxDims ) 
}

static void ShowValueBaseType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, VARIANT* pValue)
{
    DWORD BaseType = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_BASETYPE, &BaseType), 0)
    else
    {
        ULONG64 Length = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_LENGTH, &Length), 0);

        union {
            CHAR    vchar;
            WCHAR   vwchar;
            DWORD64 value;
            INT8 vint8;
            INT16 vint16;
            INT32 vint32;
            INT64 vint64;
            UINT8 uint8;
            UINT16 uint16;
            UINT32 uint32;
            UINT64 uint64;
            float f16;
            double f32;
        };
        MYASSERT(Length <= sizeof(value));
        SIZE_T dwReadWriteBytes;
        if (Length > 0 && !ReadProcessMemory(hProcess, (LPCVOID) Address, &value, (SIZE_T) Length, &dwReadWriteBytes))
            printf(" *unknown*");
        else
        {
            switch ((enum BasicType) BaseType)
            {
            case btNoType: MYASSERT(Length == 0);  break;
            case btVoid: MYASSERT(Length == 0);  break;
            case btChar: MYASSERT(Length == sizeof(vchar));  printf(" %d '%c'", vchar, vchar); break;
            case btWChar: MYASSERT(Length == sizeof(vwchar));  wprintf(L" %d L'%c'", vwchar, vwchar); break;
            case btInt:
            case btLong:
                switch (Length)
                {
                case sizeof(vint8)  : printf(" %d", vint8); /*if (pValue) InitVariantFromInt8(vint8, pValue);*/ break;
                case sizeof(vint16) : printf(" %d", vint32); if (pValue) InitVariantFromInt16(vint32, pValue); break;
                case sizeof(vint32) : printf(" %d", vint32); if (pValue) InitVariantFromInt32(vint32, pValue); break;
                case sizeof(vint64) : printf(" %lld", vint64); if (pValue) InitVariantFromInt64(vint64, pValue); break;
                default: NOT_IMPLEMENTED; break;
                }
                break;
            case btUInt:
            case btULong:
                switch (Length)
                {
                case sizeof(uint8)  : printf(" %u", uint8); /*if (pValue) InitVariantFromUInt8(uint8, pValue);*/ break;
                case sizeof(uint16) : printf(" %u", uint32); if (pValue) InitVariantFromUInt16(uint16, pValue); break;
                case sizeof(uint32) : printf(" %u", uint32); if (pValue) InitVariantFromUInt32(uint32, pValue); break;
                case sizeof(uint64) : printf(" %llu", uint64); if (pValue) InitVariantFromUInt64(uint64, pValue); break;
                default: NOT_IMPLEMENTED; break;
                }
                break;
                //case btFloat: printf(" float"); break;
                //case btBCD: printf(" bcd"); break;
            case btFloat:
                switch (Length)
                {
                    // TODO Why is a float in the source showing of size 8
                    //case sizeof(f16) : printf(" %f", f16); if (pValue) InitVariantFromDouble(f16, pValue); break;
                    case sizeof(f32) : printf(" %f", f32); if (pValue) InitVariantFromDouble(f32, pValue); break;
                    default: NOT_IMPLEMENTED; break;
                }
                break;
            case btBool: MYASSERT(Length == sizeof(vchar));  printf(" %d (%s)", vchar, vchar ? "true" : "false"); break;
                //case btCurrency: printf(" currency"); break;
                //case btDate: printf(" dat"); break;
                //case btVariant: printf(" variant"); break;
                //case btComplex: printf(" complex"); break;
                //case btBit: printf(" bit"); break;
                //case btBSTR: printf(" BSTR"); break;
                //case btHresult: printf(" HResult"); break;
            default: printf(" ShowValueBaseType:%d", BaseType); NOT_IMPLEMENTED; break;
            }
        }
    }
}

void ShowValue(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    DWORD Tag = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMTAG, &Tag), 0)
    else
    {
        //printf(" %u", Tag);
        switch ((enum SymTagEnum) Tag)
        {
        case SymTagData: ShowValueData(hProcess, ModBase, TypeId, Address); break;
        case SymTagUDT: ShowValueUDT(hProcess, ModBase, TypeId, Address); break;
        case SymTagEnum: ShowValueEnum(hProcess, ModBase, TypeId, Address); break;
        case SymTagFunctionType: ShowValueFunctionType(hProcess, ModBase, TypeId, Address); break;
        case SymTagPointerType: ShowValuePointerType(hProcess, ModBase, TypeId, Address); break;
        case SymTagArrayType: ShowValueArrayType(hProcess, ModBase, TypeId, Address); break;
        case SymTagBaseType: ShowValueBaseType(hProcess, ModBase, TypeId, Address, nullptr); break;
        default: printf(" Unknown tag: %u", Tag); NOT_IMPLEMENTED;  break;
        }
    }
}

static FoundValue FindValueUDT(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, LPCWSTR strName)
{
    DWORD NumChildren = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_CHILDRENCOUNT, &NumChildren), 0)
    else
    {
        auto pFC = zmalloc<TI_FINDCHILDREN_PARAMS>(NumChildren * sizeof(ULONG));
        pFC->Count = NumChildren;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_FINDCHILDREN, pFC.get()), 0)
        else
        {
            for (DWORD i = 0; i < NumChildren; ++i)
            {
                ULONG ChildTypeId = pFC->ChildId[i];

                DWORD Tag = 0;
                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_SYMTAG, &Tag), 0)
                else
                {
                    MYASSERT(((enum SymTagEnum) Tag) == SymTagData);

                    bool found = false;

                    WCHAR* pName = nullptr;
                    CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_SYMNAME, &pName), 0)
                    else
                    {
                        if (_wcsicmp(strName, pName) == 0)
                            found = true;
                        LocalFree(pName);
                    }

                    if (found)
                    {
                        DWORD dataKind = 0;
                        CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_DATAKIND, &dataKind), 0)
                        else
                        {
                            switch ((enum DataKind) dataKind)
                            {
                            case DataIsGlobal:
                            case DataIsStaticLocal:
                            case DataIsFileStatic:
                            case DataIsStaticMember:
                            {
                                // Use Address; Offset is not defined

                                // Note: If it is DataIsStaticMember, then this is a static member 
                                // of a class defined in another module 
                                // (it does not have an address in this module) 

                                ULONG64 DataAddress = 0;
                                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_ADDRESS, &DataAddress), 0)
                                else
                                {
                                    printf(" Address %llu", DataAddress);
                                    NOT_IMPLEMENTED;
                                }
                            }
                            break;

                            case DataIsLocal:
                            case DataIsParam:
                            case DataIsObjectPtr:
                            case DataIsMember:
                            {
                                // Use Offset; Address is not defined

                                DWORD DataTypeId = 0;
                                CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_TYPE, &DataTypeId), 0)
                                else
                                {
                                    ULONG Offset = 0;
                                    CHECK(SymGetTypeInfo(hProcess, ModBase, ChildTypeId, TI_GET_OFFSET, &Offset), 0)
                                    else
                                    {
                                        return { DataTypeId, Address + Offset };
                                    }
                                }
                            }
                            break;

                            case DataIsConstant:
                                NOT_IMPLEMENTED;
                                break;

                            default:
                                // Unknown location 
                                NOT_IMPLEMENTED;
                                break;
                            }
                        }
                    }
                }

                //ShowValue(hProcess, ModBase, ChildTypeId, Address);
            }
        }
    }

    return { (ULONG) -1 };
}

FoundValue FindValue(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, LPCWSTR strName)
{
    DWORD Tag = 0;
    CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_SYMTAG, &Tag), return { (ULONG) -1 })
    else
    {
        switch ((enum SymTagEnum) Tag)
        {
        case SymTagUDT: return FindValueUDT(hProcess, ModBase, TypeId, Address, strName);
        case SymTagBaseType: return { (ULONG) -1 }; // No sub values
        default: printf(" Unknown tag: %u", Tag); NOT_IMPLEMENTED; return { (ULONG) -1 };
        }
    }
}
