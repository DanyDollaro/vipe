module vipe::resources;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawResourceDirectory @packed
{
    uint characteristics;
    uint time_date_stamp;
    ushort major_version;
    ushort minor_version;
    ushort number_of_named_entries;
    ushort number_of_id_entries;
}

struct VipeRawResourceDirectoryEntry @packed
{
    uint name_or_id;
    uint offset_to_data_or_directory;
}

struct VipeRawResourceDataEntry @packed
{
    uint offset_to_data;
    uint size;
    uint code_page;
    uint reserved;
}

struct VipeRawResourceDirString @packed
{
    ushort length;
    ushort name_string;
}

//
// View structures definition
//

struct VipeViewResourceDirectory
{
    VipeRawResourceDirectory* raw;
}

fn uint VipeViewResourceDirectory.get_characteristics(&self)
    => self.raw.characteristics;
fn void VipeViewResourceDirectory.set_characteristics(&self, uint v)
    => self.raw.characteristics = v;

fn uint VipeViewResourceDirectory.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewResourceDirectory.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn ushort VipeViewResourceDirectory.get_major_version(&self)
    => self.raw.major_version;
fn void VipeViewResourceDirectory.set_major_version(&self, ushort v)
    => self.raw.major_version = v;

fn ushort VipeViewResourceDirectory.get_minor_version(&self)
    => self.raw.minor_version;
fn void VipeViewResourceDirectory.set_minor_version(&self, ushort v)
    => self.raw.minor_version = v;

fn ushort VipeViewResourceDirectory.get_number_of_named_entries(&self)
    => self.raw.number_of_named_entries;
fn void VipeViewResourceDirectory.set_number_of_named_entries(&self, ushort v)
    => self.raw.number_of_named_entries = v;

fn ushort VipeViewResourceDirectory.get_number_of_id_entries(&self)
    => self.raw.number_of_id_entries;
fn void VipeViewResourceDirectory.set_number_of_id_entries(&self, ushort v)
    => self.raw.number_of_id_entries = v;

struct VipeViewResource
{
    VipeRawResourceDataEntry* raw;
    uint type_id;
    uint name_id;
    uint language_id;
    char[] data;
}

fn uint VipeViewResource.get_rva(&self)      => self.raw.offset_to_data;
fn void VipeViewResource.set_rva(&self, uint v) => self.raw.offset_to_data = v;

fn uint VipeViewResource.get_size(&self)      => self.raw.size;
fn void VipeViewResource.set_size(&self, uint v) => self.raw.size = v;

fn uint VipeViewResource.get_code_page(&self)      => self.raw.code_page;
fn void VipeViewResource.set_code_page(&self, uint v) => self.raw.code_page = v;

fn uint VipeViewResource.get_reserved(&self)      => self.raw.reserved;
fn void VipeViewResource.set_reserved(&self, uint v) => self.raw.reserved = v;

fn uint VipeViewResource.get_type_id(&self)     => self.type_id;
fn uint VipeViewResource.get_name_id(&self)     => self.name_id;
fn uint VipeViewResource.get_language_id(&self) => self.language_id;

//
// Callbacks
//

alias VipeCallbackResource = fn bool(VipeViewResource*, any);
