module vipe::sections;
import vipe::common;

const uint SECTION_NAME_SIZE = 8;

//
// Raw structures definition
//

struct VipeRawSectionHeader @packed
{
    char[SECTION_NAME_SIZE] name;
    uint virtual_size;
    uint virtual_address;
    uint size_of_raw_data;
    uint pointer_to_raw_data;
    uint pointer_to_relocations;
    uint pointer_to_linenumbers;
    ushort number_of_relocations;
    ushort number_of_linenumbers;
    uint characteristics;
}

//
// View structures definition
//

struct VipeViewSection
{
    VipeRawSectionHeader* raw;
    char[] data;
}

fn char[] VipeViewSection.get_name(&self)
{
    // TODO: look for a way to make this better
    usz len = SECTION_NAME_SIZE;
    for (usz i = 0; i < SECTION_NAME_SIZE; i++)
    {
        if (self.raw.name[i] == 0) { len = i; break; }
    }
    return self.raw.name[0..len - 1];
}

macro uint VipeViewSection.virtual_size(&self, uint v = ...)
    => common::@exchange(self.raw.virtual_size, v);

macro uint VipeViewSection.virtual_address(&self, uint v = ...)
    => common::@exchange(self.raw.virtual_address, v);

macro uint VipeViewSection.size_of_raw_data(&self, uint v = ...)
    => common::@exchange(self.raw.size_of_raw_data, v);

macro uint VipeViewSection.pointer_to_raw_data(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_raw_data, v);

macro uint VipeViewSection.pointer_to_relocations(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_relocations, v);

macro uint VipeViewSection.pointer_to_linenumbers(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_linenumbers, v);

macro ushort VipeViewSection.number_of_relocations(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_relocations, v);

macro ushort VipeViewSection.number_of_linenumbers(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_linenumbers, v);

macro uint VipeViewSection.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);

//
// Callbacks
//

alias VipeCallbackSection = fn void?(VipeViewSection*, any);
