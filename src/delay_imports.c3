module ope::delay_imports;
import ope::common;

struct OpeRawDelayImportDescriptor @packed
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

struct OpeViewDelayedImportDescriptor
{
    OpeRawDelayImportDescriptor* raw;
    ZString                      dll;
}

macro uint OpeViewDelayedImportDescriptor.attributes(&self, uint v = ...)
    => common::@exchange(self.raw.attributes, v);

macro uint OpeViewDelayedImportDescriptor.module_handle_rva(&self, uint v = ...)
    => common::@exchange(self.raw.module_handle_rva, v);

macro uint OpeViewDelayedImportDescriptor.iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.iat_rva, v);

macro uint OpeViewDelayedImportDescriptor.ilt_rva(&self, uint v = ...)
    => common::@exchange(self.raw.ilt_rva, v);

macro uint OpeViewDelayedImportDescriptor.bound_iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.bound_iat_rva, v);

macro uint OpeViewDelayedImportDescriptor.unload_iat_rva(&self, uint v = ...)
    => common::@exchange(self.raw.unload_iat_rva, v);

macro uint OpeViewDelayedImportDescriptor.timestamp(&self, uint v = ...)
    => common::@exchange(self.raw.timestamp, v);

struct OpeViewDelayedImport
{
    ZString name;
    ushort  hint;
    ushort  ordinal;
    bool    is_ordinal;
    uint    iat_entry_rva;
}

macro ZString OpeViewDelayedImport.name(&self, ZString v = ...)
    => common::@exchange(self.name, v);

macro ushort OpeViewDelayedImport.hint(&self, ushort v = ...)
    => common::@exchange(self.hint, v);

macro ushort OpeViewDelayedImport.ordinal(&self, ushort v = ...)
    => common::@exchange(self.ordinal, v);

macro bool OpeViewDelayedImport.is_ordinal(&self, bool v = ...)
    => common::@exchange(self.is_ordinal, v);

macro uint OpeViewDelayedImport.iat_entry_rva(&self, uint v = ...)
    => common::@exchange(self.iat_entry_rva, v);

alias OpeDelayedImportDescriptorCallback = fn bool(OpeViewDelayedImportDescriptor*);
alias OpeDelayedImportCallback           = fn bool(OpeViewDelayedImport*);
