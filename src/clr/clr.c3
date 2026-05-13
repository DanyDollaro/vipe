module ope::clr;
import ope::common;
import ope::headers::optional;

struct OpeRawCor20Header @packed
{
    uint   cb;
    ushort major_runtime_version;
    ushort minor_runtime_version;
    OpeRawDataDirectory meta_data;
    uint   flags;
    uint   entry_point_token_or_rva;
    OpeRawDataDirectory resources;
    OpeRawDataDirectory strong_name_signature;
    OpeRawDataDirectory code_manager_table;
    OpeRawDataDirectory vtable_fixups;
    OpeRawDataDirectory export_address_table_jumps;
    OpeRawDataDirectory managed_native_header;
}

struct OpeViewCor20Header
{
    OpeRawCor20Header* raw;
}

macro uint OpeViewCor20Header.cb(&self, uint v = ...)
    => common::@exchange(#self.raw.cb, v);

macro ushort OpeViewCor20Header.major_runtime_version(&self, ushort v = ...)
    => common::@exchange(#self.raw.major_runtime_version, v);

macro ushort OpeViewCor20Header.minor_runtime_version(&self, ushort v = ...)
    => common::@exchange(#self.raw.minor_runtime_version, v);

fn OpeRawDataDirectory OpeViewCor20Header.meta_data(&self)                  => self.raw.meta_data;
fn OpeRawDataDirectory OpeViewCor20Header.resources(&self)                  => self.raw.resources;
fn OpeRawDataDirectory OpeViewCor20Header.strong_name_signature(&self)      => self.raw.strong_name_signature;
fn OpeRawDataDirectory OpeViewCor20Header.code_manager_table(&self)         => self.raw.code_manager_table;
fn OpeRawDataDirectory OpeViewCor20Header.vtable_fixups(&self)              => self.raw.vtable_fixups;
fn OpeRawDataDirectory OpeViewCor20Header.export_address_table_jumps(&self) => self.raw.export_address_table_jumps;
fn OpeRawDataDirectory OpeViewCor20Header.managed_native_header(&self)      => self.raw.managed_native_header;

macro uint OpeViewCor20Header.flags(&self, uint v = ...)
    => common::@exchange(#self.raw.flags, v);

macro uint OpeViewCor20Header.entry_point_token_or_rva(&self, uint v = ...)
    => common::@exchange(#self.raw.entry_point_token_or_rva, v);
