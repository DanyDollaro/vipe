module ope::imports;
import ope::common;

struct OpeRawImportDescriptor @packed
{
    uint original_first_thunk;
    uint time_date_stamp;
    uint forwarder_chain;
    uint name_rva;
    uint first_thunk;
}

struct OpeRawImportByName @packed
{
    ushort hint;
    char   name;
}

union OpeRawThunkData32 @packed
{
    uint forwarder_string;
    uint function_ptr;
    uint ordinal;
    uint address_of_data;
}

union OpeRawThunkData64 @packed
{
    ulong forwarder_string;
    ulong function_ptr;
    ulong ordinal;
    ulong address_of_data;
}

struct OpeViewImportDescriptor
{
    OpeRawImportDescriptor* raw;
    ZString                 dll;
}

macro uint OpeViewImportDescriptor.original_first_thunk(&self, uint v = ...)
    => common::@exchange(self.raw.original_first_thunk, v);

macro uint OpeViewImportDescriptor.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro uint OpeViewImportDescriptor.forwarder_chain(&self, uint v = ...)
    => common::@exchange(self.raw.forwarder_chain, v);

macro uint OpeViewImportDescriptor.name_rva(&self, uint v = ...)
    => common::@exchange(self.raw.name_rva, v);

macro uint OpeViewImportDescriptor.first_thunk(&self, uint v = ...)
    => common::@exchange(self.raw.first_thunk, v);

struct OpeViewImport
{
    ZString name;
    ushort  hint;
    ushort  ordinal;
    bool    is_ordinal;
    uint    iat_entry_rva;
}

macro ZString OpeViewImport.name(&self, ZString v = ...)
    => common::@exchange(self.name, v);

macro ushort OpeViewImport.hint(&self, ushort v = ...)
    => common::@exchange(self.hint, v);

macro ushort OpeViewImport.ordinal(&self, ushort v = ...)
    => common::@exchange(self.ordinal, v);

macro bool OpeViewImport.is_ordinal(&self, bool v = ...)
    => common::@exchange(self.is_ordinal, v);

macro uint OpeViewImport.iat_entry_rva(&self, uint v = ...)
    => common::@exchange(self.iat_entry_rva, v);

alias OpeImportDescriptorCallback = fn bool(OpeViewImportDescriptor*);
alias OpeImportCallback           = fn bool(OpeViewImport*);
