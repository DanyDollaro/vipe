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

fn uint VipeViewDebug.get_characteristics(&self)
    => self.raw.characteristics;
fn void VipeViewDebug.set_characteristics(&self, uint v)
    => self.raw.characteristics = v;

fn uint VipeViewDebug.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewDebug.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn ushort VipeViewDebug.get_major_version(&self)
    => self.raw.major_version;
fn void VipeViewDebug.set_major_version(&self, ushort v)
    => self.raw.major_version = v;

fn ushort VipeViewDebug.get_minor_version(&self)
    => self.raw.minor_version;
fn void VipeViewDebug.set_minor_version(&self, ushort v)
    => self.raw.minor_version = v;

fn uint VipeViewDebug.get_type(&self)
    => self.raw.type;
fn void VipeViewDebug.set_type(&self, uint v)
    => self.raw.type = v;

fn uint VipeViewDebug.get_size_of_data(&self)
    => self.raw.size_of_data;
fn void VipeViewDebug.set_size_of_data(&self, uint v)
    => self.raw.size_of_data = v;

fn uint VipeViewDebug.get_rva(&self)
    => self.raw.address_of_raw_data;
fn void VipeViewDebug.set_rva(&self, uint v)
    => self.raw.address_of_raw_data = v;

fn uint VipeViewDebug.get_file_offset(&self)
    => self.raw.pointer_to_raw_data;
fn void VipeViewDebug.set_file_offset(&self, uint v)
    => self.raw.pointer_to_raw_data = v;

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
        if (!callback(&entry, user_data))
        {
            break;
        }
    }
}

//
// Callbacks
//

alias VipeCallbackDebug = fn bool(VipeViewDebug*, any);
