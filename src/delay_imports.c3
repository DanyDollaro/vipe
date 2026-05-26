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

fn uint VipeViewDelayedImportDescriptor.get_attributes(&self)
    => self.raw.attributes;
fn void VipeViewDelayedImportDescriptor.set_attributes(&self, uint v)
    => self.raw.attributes = v;

fn uint VipeViewDelayedImportDescriptor.get_dll_name_rva(&self)
    => self.raw.dll_name_rva;
fn void VipeViewDelayedImportDescriptor.set_dll_name_rva(&self, uint v)
    => self.raw.dll_name_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_module_handle_rva(&self)
    => self.raw.module_handle_rva;
fn void VipeViewDelayedImportDescriptor.set_module_handle_rva(&self, uint v)
    => self.raw.module_handle_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_iat_rva(&self)
    => self.raw.iat_rva;
fn void VipeViewDelayedImportDescriptor.set_iat_rva(&self, uint v)
    => self.raw.iat_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_ilt_rva(&self)
    => self.raw.ilt_rva;
fn void VipeViewDelayedImportDescriptor.set_ilt_rva(&self, uint v)
    => self.raw.ilt_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_bound_iat_rva(&self)
    => self.raw.bound_iat_rva;
fn void VipeViewDelayedImportDescriptor.set_bound_iat_rva(&self, uint v)
    => self.raw.bound_iat_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_unload_iat_rva(&self)
    => self.raw.unload_iat_rva;
fn void VipeViewDelayedImportDescriptor.set_unload_iat_rva(&self, uint v)
    => self.raw.unload_iat_rva = v;

fn uint VipeViewDelayedImportDescriptor.get_timestamp(&self)
    => self.raw.timestamp;
fn void VipeViewDelayedImportDescriptor.set_timestamp(&self, uint v)
    => self.raw.timestamp = v;

struct VipeViewDelayedImport
{
    ZString name;
    ushort hint;
    ushort ordinal;
    bool is_ordinal;
    uint iat_entry_rva;
}

fn ZString VipeViewDelayedImport.get_name(&self) => self.name;
fn ushort VipeViewDelayedImport.get_hint(&self) => self.hint;
fn ushort VipeViewDelayedImport.get_ordinal(&self) => self.ordinal;
fn bool VipeViewDelayedImport.is_ordinal(&self) => self.is_ordinal;
fn uint VipeViewDelayedImport.get_iat_entry_rva(&self) => self.iat_entry_rva;

//
// Callbacks
//

alias VipeCallbackDelayedImportDescriptor = fn bool(VipeViewDelayedImportDescriptor*, any);
alias VipeCallbackDelayedImport = fn bool(VipeViewDelayedImport*, any);
