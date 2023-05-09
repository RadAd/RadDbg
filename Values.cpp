#include "Values.h"

#include <DbgHelp.h>
#include <propvarutil.h>

#include "cvconst.h"

#include "Utils.h"

DWORD64 GetRegValue(ULONG reg, const CONTEXT& context)
{
    switch (reg)
    {
    case CV_AMD64_RBP: return context.Rbp;
    case CV_AMD64_RSP: return context.Rsp;
    default: NOT_IMPLEMENTED; return 0;
    }
}

void ShowValueBaseType(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address, VARIANT* pValue);

static void ShowValueData(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    // TODO Show some member values
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

            ULONG Offset = 0;
            CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_OFFSET, &Offset), 0)
            else
            {
                printf(" Offset %u", Offset);
                NOT_IMPLEMENTED;
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

        default:
            // Unknown location 
            NOT_IMPLEMENTED;
            break;
        }
    }
}

static void ShowValueUDT(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, DWORD64 Address)
{
    // TODO Show some member values
}

static void ShowValueEnumChild(HANDLE hProcess, DWORD64 ModBase, ULONG TypeId, VARIANT value)
{
    // TODO Only want to show the enum value for the current value of the variable
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
                    if (var.vt == value.vt && VariantCompare(var, value) == 0)
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
    printf(" 0x%p", (PVOID) Address);
    // TODO What else to show??
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
            Length, nullptr);

        printf(" 0x%p", (PVOID) NewAddress);

        DWORD Type = 0;
        CHECK(SymGetTypeInfo(hProcess, ModBase, TypeId, TI_GET_TYPE, &Type), 0)
        else
        {
            printf(" :");
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
                    CHAR* msg = new CHAR[Length / sizeof(CHAR)];
                    ReadProcessMemory(hProcess,
                        (LPCVOID) Address,
                        msg,
                        Length, nullptr);

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
                    WCHAR* msg = new WCHAR[Length / sizeof(WCHAR)];
                    ReadProcessMemory(hProcess,
                        (LPCVOID) Address,
                        msg,
                        Length, nullptr);

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
            INT32 vint32;
            INT64 vint64;
            UINT8 uint8;
            UINT32 uint32;
            UINT64 uint64;
        };
        MYASSERT(Length <= sizeof(value));
        SIZE_T dwReadWriteBytes;
        if (Length > 0 && !ReadProcessMemory(hProcess, (LPCVOID) Address, &value, Length, &dwReadWriteBytes))
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
                case sizeof(vint32) : printf(" %d", vint32); if (pValue) InitVariantFromInt16(vint32, pValue); break;
                case sizeof(vint64) : printf(" %lld", vint64); if (pValue) InitVariantFromInt64(vint64, pValue); break;
                default: NOT_IMPLEMENTED; break;
                }
                break;
            case btUInt:
            case btULong:
                switch (Length)
                {
                case sizeof(uint8)  : printf(" %u", uint8); /*if (pValue) InitVariantFromUInt8(uint8, pValue);*/ break;
                case sizeof(uint32) : printf(" %u", uint32); if (pValue) InitVariantFromUInt32(uint32, pValue); break;
                case sizeof(uint64) : printf(" %llu", uint64); if (pValue) InitVariantFromUInt64(uint64, pValue); break;
                default: NOT_IMPLEMENTED; break;
                }
                break;
                //case btFloat: printf(" float"); break;
                //case btBCD: printf(" bcd"); break;
            case btBool: MYASSERT(Length == sizeof(vchar));  printf(" %d (%s)", vchar, vchar ? "true" : "false"); break;
                //case btCurrency: printf(" currency"); break;
                //case btDate: printf(" dat"); break;
                //case btVariant: printf(" variant"); break;
                //case btComplex: printf(" complex"); break;
                //case btBit: printf(" bit"); break;
                //case btBSTR: printf(" BSTR"); break;
                //case btHresult: printf(" HResult"); break;
            default: printf(" TODO ShowValueBaseType:%d", BaseType); NOT_IMPLEMENTED; break;
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
