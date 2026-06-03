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

macro uint VipeViewResourceDirectory.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);

macro uint VipeViewResourceDirectory.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro ushort VipeViewResourceDirectory.major_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_version, v);

macro ushort VipeViewResourceDirectory.minor_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_version, v);

macro ushort VipeViewResourceDirectory.number_of_named_entries(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_named_entries, v);

macro ushort VipeViewResourceDirectory.number_of_id_entries(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_id_entries, v);

struct VipeViewResource
{
    VipeRawResourceDataEntry* raw;
    uint type_id;
    uint name_id;
    uint language_id;
    char[] data;
}

macro uint VipeViewResource.rva(&self, uint v = ...)
    => common::@exchange(self.raw.offset_to_data, v);

macro uint VipeViewResource.size(&self, uint v = ...)
    => common::@exchange(self.raw.size, v);

macro uint VipeViewResource.code_page(&self, uint v = ...)
    => common::@exchange(self.raw.code_page, v);

macro uint VipeViewResource.reserved(&self, uint v = ...)
    => common::@exchange(self.raw.reserved, v);

macro uint VipeViewResource.type_id(&self)
    => self.type_id;
macro uint VipeViewResource.name_id(&self)
    => self.name_id;
macro uint VipeViewResource.language_id(&self)
    => self.language_id;

//
// Callbacks
//

alias VipeCallbackResource = fn void?(VipeViewResource* entry, any user_data = null);
