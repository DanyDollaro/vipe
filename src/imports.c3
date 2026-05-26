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

fn uint VipeViewImportDescriptor.get_original_first_thunk_rva(&self)
    => self.raw.original_first_thunk;
fn void VipeViewImportDescriptor.set_original_first_thunk_rva(&self, uint v)
    => self.raw.original_first_thunk = v;

fn uint VipeViewImportDescriptor.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewImportDescriptor.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn uint VipeViewImportDescriptor.get_forwarder_chain(&self)
    => self.raw.forwarder_chain;
fn void VipeViewImportDescriptor.set_forwarder_chain(&self, uint v)
    => self.raw.forwarder_chain = v;

fn uint VipeViewImportDescriptor.get_name_rva(&self)
    => self.raw.name_rva;
fn void VipeViewImportDescriptor.set_name_rva(&self, uint v)
    => self.raw.name_rva = v;

fn uint VipeViewImportDescriptor.get_first_thunk_rva(&self)
    => self.raw.first_thunk;
fn void VipeViewImportDescriptor.set_first_thunk_rva(&self, uint v)
    => self.raw.first_thunk = v;

fn ZString VipeViewImportDescriptor.get_name(&self)
    => name;

fn usz VipeViewImportDescriptor.get_index(&self)
    => index;

struct VipeViewImport
{
    VipeViewImportDescriptor* descriptor;
    union
    {
        VipeRawThunkData32* thunk32;
        VipeRawThunkData64* thunk64;
    }
    sz thunk_index;
    VipeRawImportByName* imports_by_name;
}

fn ZString VipeViewImport.get_name(&self) => self.name;

fn ushort VipeViewImport.get_hint(&self) => self.hint;
fn ushort VipeViewImport.get_ordinal(&self) => self.ordinal;
fn bool VipeViewImport.is_ordinal(&self) => self.is_ordinal;

fn uint VipeViewImport.get_iat_entry_rva(&self) => self.iat_entry_rva;
fn void VipeViewImport.set_iat_entry_rva(&self, uint v) => self.iat_entry_rva = v;

//
// View structures definition
//

alias VipeCallbackImportDescriptor = fn bool(VipeViewImportDescriptor*, any);
alias VipeCallbackImport = fn bool(VipeViewImport*, any);
