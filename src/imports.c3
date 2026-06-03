module vipe::imports;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawImportDescriptor @packed
{
    uint original_first_thunk;
    uint time_date_stamp;
    uint forwarder_chain;
    uint name_rva;
    uint first_thunk;
}

struct VipeRawImportByName @packed
{
    ushort hint;
    char name;
}

union VipeRawThunkData32 @packed
{
    uint forwarder_string;
    uint function_ptr;
    uint ordinal;
    uint address_of_data;
}

union VipeRawThunkData64 @packed
{
    ulong forwarder_string;
    ulong function_ptr;
    ulong ordinal;
    ulong address_of_data;
}

//
// View structures definition
//

struct VipeViewImportDescriptor
{
    VipeRawImportDescriptor* raw;
    ZString name;
    usz index;
}

macro uint VipeViewImportDescriptor.original_first_thunk_rva(&self, uint v = ...)
    => common::@exchange(self.raw.original_first_thunk, v);
macro uint VipeViewImportDescriptor.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);
macro uint VipeViewImportDescriptor.forwarder_chain(&self, uint v = ...)
    => common::@exchange(self.raw.forwarder_chain, v);
macro uint VipeViewImportDescriptor.name_rva(&self, uint v = ...)
    => common::@exchange(self.raw.name_rva, v);
macro uint VipeViewImportDescriptor.first_thunk_rva(&self, uint v = ...)
    => common::@exchange(self.raw.first_thunk, v);

struct VipeViewImport
{
    VipeViewImportDescriptor* descriptor;
    union
    {
        VipeRawThunkData32* thunk32;
        VipeRawThunkData64* thunk64;
    }
    // index into the array of thunks
    sz index;
    VipeRawImportByName* import_by_name;
}

macro ZString VipeViewImport.name(&self) => self.name;
macro ushort VipeViewImport.hint(&self) => self.hint;
macro ushort VipeViewImport.ordinal(&self) => self.ordinal;
macro bool VipeViewImport.is_ordinal(&self) => self.is_ordinal;
macro uint VipeViewImport.iat_entry_rva(&self, uint v = ...)
    => common::@exchange(self.iat_entry_rva, v);

//
// Callbacks
//

alias VipeCallbackImportDescriptor = fn void?(VipeViewImportDescriptor* entry, any user_data = null);
alias VipeCallbackImport = fn void?(VipeViewImport* entry, any user_data = null);
