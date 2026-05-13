module ope::debug;
import ope::common;

struct OpeRawDebugDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   type;
    uint   size_of_data;
    uint   address_of_raw_data;
    uint   pointer_to_raw_data;
}

struct OpeRawCvInfoPdb20 @packed
{
    uint cv_signature;
    uint offset;
    uint signature;
    uint age;
    char pdb_file_name;
}

struct OpeRawCvInfoPdb70 @packed
{
    uint     cv_signature;
    char[16] signature;
    uint     age;
    char     pdb_file_name;
}

struct OpeViewDebug
{
    OpeRawDebugDirectory* raw;
    char[]                data;
}

macro uint OpeViewDebug.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);

macro uint OpeViewDebug.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro ushort OpeViewDebug.major_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_version, v);

macro ushort OpeViewDebug.minor_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_version, v);

macro uint OpeViewDebug.type(&self, uint v = ...)
    => common::@exchange(self.raw.type, v);

macro uint OpeViewDebug.size_of_data(&self, uint v = ...)
    => common::@exchange(self.raw.size_of_data, v);

macro uint OpeViewDebug.rva(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_raw_data, v);

macro uint OpeViewDebug.file_offset(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_raw_data, v);

struct OpeViewDebugDirectory
{
    OpeRawDebugDirectory[] entries;
}

fn void? OpeViewDebugDirectory.foreach_debug_entry(&self, char[][] data_slices, OpeDebugCallback cb)
{
    for (usz i = 0; i < self.entries.len; i++)
    {
        OpeViewDebug entry = { .raw = &self.entries[i], .data = data_slices[i] };
        if (!cb(&entry)) break;
    }
}

alias OpeDebugCallback = fn bool(OpeViewDebug*);
