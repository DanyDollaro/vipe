module vipe::delay_imports;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawDelayImportDescriptor @packed
{
    uint attributes;
    uint dll_name_rva;
    uint module_handle_rva;
    uint iat_rva;
    uint ilt_rva;
    uint bound_iat_rva;
    uint unload_iat_rva;
    uint timestamp;
}

//
// View structures definition
//

struct VipeViewDelayedImportDescriptor
{
    VipeRawDelayImportDescriptor* raw;
    ZString dll;
}

macro uint VipeViewDelayedImportDescriptor.attributes(&self, uint v = ...)
    => common::@exchange(self.raw.attributes, v);
macro uint VipeViewDelayedImportDescriptor.dll_name_rva(&self, uint v = ...)
    => common::@exchange(self.raw.dll_name_rva, v);
macro uint VipeViewDelayedImportDescriptor.module_handle_rva(&self, uint v = ...)
    => common::@exchange(self.raw.module_handle_rva, v);
macro uint VipeViewDelayedImportDescriptor.iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.iat_rva, v);
macro uint VipeViewDelayedImportDescriptor.ilt_rva(&self, uint v = ...)
    => common::@exchange(self.raw.ilt_rva, v);
macro uint VipeViewDelayedImportDescriptor.bound_iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.bound_iat_rva, v);
macro uint VipeViewDelayedImportDescriptor.unload_iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.unload_iat_rva, v);
macro uint VipeViewDelayedImportDescriptor.timestamp(&self, uint v = ...)
    => common::@exchange(self.raw.timestamp, v);

struct VipeViewDelayedImport
{
    ZString name;
    ushort hint;
    ushort ordinal;
    bool is_ordinal;
    uint iat_entry_rva;
}

macro ZString VipeViewDelayedImport.name(&self)    => self.name;
macro ushort  VipeViewDelayedImport.hint(&self)    => self.hint;
macro ushort  VipeViewDelayedImport.ordinal(&self) => self.ordinal;
macro bool    VipeViewDelayedImport.is_ordinal(&self) => self.is_ordinal;
macro uint    VipeViewDelayedImport.iat_entry_rva(&self) => self.iat_entry_rva;

//
// Callbacks
//

alias VipeCallbackDelayedImportDescriptor = fn bool(VipeViewDelayedImportDescriptor*, any);
alias VipeCallbackDelayedImport           = fn bool(VipeViewDelayedImport*, any);
