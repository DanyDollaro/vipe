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

fn uint VipeViewCor20Header.get_cb(&self)
    => self.raw.cb;
fn void VipeViewCor20Header.set_cb(&self, uint v)
    => self.raw.cb = v;

fn ushort VipeViewCor20Header.get_major_runtime_version(&self)
    => self.raw.major_runtime_version;
fn void VipeViewCor20Header.set_major_runtime_version(&self, ushort v)
    => self.raw.major_runtime_version = v;

fn ushort VipeViewCor20Header.get_minor_runtime_version(&self)
    => self.raw.minor_runtime_version;
fn void VipeViewCor20Header.set_minor_runtime_version(&self, ushort v)
    => self.raw.minor_runtime_version = v;

fn uint VipeViewCor20Header.get_flags(&self)
    => self.raw.flags;
fn void VipeViewCor20Header.set_flags(&self, uint v)
    => self.raw.flags = v;

fn uint VipeViewCor20Header.get_entry_point_token_or_rva(&self)
    => self.raw.entry_point_token_or_rva;
fn void VipeViewCor20Header.set_entry_point_token_or_rva(&self, uint v)
    => self.raw.entry_point_token_or_rva = v;

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
