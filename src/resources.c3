module ope::resources;
import ope::common;

struct OpeRawResourceDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    ushort number_of_named_entries;
    ushort number_of_id_entries;
}

struct OpeRawResourceDirectoryEntry @packed
{
    uint name_or_id;
    uint offset_to_data_or_directory;
}

struct OpeRawResourceDataEntry @packed
{
    uint offset_to_data;
    uint size;
    uint code_page;
    uint reserved;
}

struct OpeRawResourceDirString @packed
{
    ushort length;
    ushort name_string;
}

struct OpeViewResourceDirectory
{
    OpeRawResourceDirectory* raw;
}

macro uint OpeViewResourceDirectory.characteristics(&self, uint v = ...)
    => common::@exchange(#self.raw.characteristics, v);

macro uint OpeViewResourceDirectory.time_date_stamp(&self, uint v = ...)
    => common::@exchange(#self.raw.time_date_stamp, v);

macro ushort OpeViewResourceDirectory.major_version(&self, ushort v = ...)
    => common::@exchange(#self.raw.major_version, v);

macro ushort OpeViewResourceDirectory.minor_version(&self, ushort v = ...)
    => common::@exchange(#self.raw.minor_version, v);

macro ushort OpeViewResourceDirectory.number_of_named_entries(&self, ushort v = ...)
    => common::@exchange(#self.raw.number_of_named_entries, v);

macro ushort OpeViewResourceDirectory.number_of_id_entries(&self, ushort v = ...)
    => common::@exchange(#self.raw.number_of_id_entries, v);

struct OpeViewResource
{
    OpeRawResourceDataEntry* raw;
    uint                     type_id;
    uint                     name_id;
    uint                     language_id;
    char[]                   data;
}

macro uint OpeViewResource.rva(&self, uint v = ...)
    => common::@exchange(#self.raw.offset_to_data, v);

macro uint OpeViewResource.size(&self, uint v = ...)
    => common::@exchange(#self.raw.size, v);

macro uint OpeViewResource.code_page(&self, uint v = ...)
    => common::@exchange(#self.raw.code_page, v);

macro uint OpeViewResource.reserved(&self, uint v = ...)
    => common::@exchange(#self.raw.reserved, v);

macro uint OpeViewResource.type_id(&self, uint v = ...)
    => common::@exchange(#self.type_id, v);

macro uint OpeViewResource.name_id(&self, uint v = ...)
    => common::@exchange(#self.name_id, v);

macro uint OpeViewResource.language_id(&self, uint v = ...)
    => common::@exchange(#self.language_id, v);

alias OpeResourceCallback = fn bool(OpeViewResource*);
