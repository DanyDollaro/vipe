module vipe::debug;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawDebugDirectory @packed
{
    uint characteristics;
    uint time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint type;
    uint size_of_data;
    uint address_of_raw_data;
    uint pointer_to_raw_data;
}

struct VipeRawCvInfoPdb20 @packed
{
    uint cv_signature;
    uint offset;
    uint signature;
    uint age;
    char pdb_file_name;
}

struct VipeRawCvInfoPdb70 @packed
{
    uint cv_signature;
    char[16] signature;
    uint age;
    char pdb_file_name;
}

//
// View structures definition
//

struct VipeViewDebug
{
    VipeRawDebugDirectory* raw;
    char[] data;
}

macro uint   VipeViewDebug.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);
macro uint   VipeViewDebug.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);
macro ushort VipeViewDebug.major_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_version, v);
macro ushort VipeViewDebug.minor_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_version, v);
macro uint   VipeViewDebug.type(&self, uint v = ...)
    => common::@exchange(self.raw.type, v);
macro uint   VipeViewDebug.size_of_data(&self, uint v = ...)
    => common::@exchange(self.raw.size_of_data, v);
macro uint   VipeViewDebug.rva(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_raw_data, v);
macro uint   VipeViewDebug.file_offset(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_raw_data, v);

struct VipeViewDebugDirectory
{
    VipeRawDebugDirectory[] entries;
}

fn void? VipeViewDebugDirectory.foreach_debug_entry(&self, char[][] data_slices, VipeCallbackDebug callback, any user_data)
{
    for (usz i = 0; i < self.entries.len; i++)
    {
        VipeViewDebug entry = {
            .raw  = &self.entries[i],
            .data = data_slices[i]
        };
        callback(&entry, user_data)!;
    }
}

//
// Callbacks
//

alias VipeCallbackDebug = fn void?(VipeViewDebug*, any);
