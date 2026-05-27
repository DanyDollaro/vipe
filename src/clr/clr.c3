module vipe::clr;
import vipe::common;
import vipe::headers::optional;

//
// Raw structures definition
//

struct VipeRawCor20Header @packed
{
    uint cb;
    ushort major_runtime_version;
    ushort minor_runtime_version;
    VipeRawDataDirectory meta_data;
    uint flags;
    uint entry_point_token_or_rva;
    VipeRawDataDirectory resources;
    VipeRawDataDirectory strong_name_signature;
    VipeRawDataDirectory code_manager_table;
    VipeRawDataDirectory vtable_fixups;
    VipeRawDataDirectory export_address_table_jumps;
    VipeRawDataDirectory managed_native_header;
}

//
// View structures definition
//

struct VipeViewCor20Header
{
    VipeRawCor20Header* raw;
}

macro uint VipeViewCor20Header.cb(&self, uint v = ...)
    => common::@exchange(self.raw.cb, v);

macro ushort VipeViewCor20Header.major_runtime_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_runtime_version, v);

macro ushort VipeViewCor20Header.minor_runtime_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_runtime_version, v);

macro uint VipeViewCor20Header.flags(&self, uint v = ...)
    => common::@exchange(self.raw.flags, v);

macro uint VipeViewCor20Header.entry_point_token_or_rva(&self, uint v = ...)
    => common::@exchange(self.raw.entry_point_token_or_rva, v);

fn VipeRawDataDirectory* VipeViewCor20Header.meta_data(&self)
    => &self.raw.meta_data;
fn VipeRawDataDirectory* VipeViewCor20Header.resources(&self)
    => &self.raw.resources;
fn VipeRawDataDirectory* VipeViewCor20Header.strong_name_signature(&self)
    => &self.raw.strong_name_signature;
fn VipeRawDataDirectory* VipeViewCor20Header.code_manager_table(&self)
    => &self.raw.code_manager_table;
fn VipeRawDataDirectory* VipeViewCor20Header.vtable_fixups(&self)
    => &self.raw.vtable_fixups;
fn VipeRawDataDirectory* VipeViewCor20Header.export_address_table_jumps(&self)
    => &self.raw.export_address_table_jumps;
fn VipeRawDataDirectory* VipeViewCor20Header.managed_native_header(&self)
    => &self.raw.managed_native_header;
