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

fn uint VipeViewSection.get_virtual_size(&self)
    => self.raw.virtual_size;
fn void VipeViewSection.set_virtual_size(&self, uint v)
    => self.raw.virtual_size = v;

fn uint VipeViewSection.get_virtual_address(&self)
    => self.raw.virtual_address;
fn void VipeViewSection.set_virtual_address(&self, uint v)
    => self.raw.virtual_address = v;

fn uint VipeViewSection.get_size_of_raw_data(&self)
    => self.raw.size_of_raw_data;
fn void VipeViewSection.set_size_of_raw_data(&self, uint v)
    => self.raw.size_of_raw_data = v;

fn uint VipeViewSection.get_pointer_to_raw_data(&self)
    => self.raw.pointer_to_raw_data;
fn void VipeViewSection.set_pointer_to_raw_data(&self, uint v)
    => self.raw.pointer_to_raw_data = v;

fn uint VipeViewSection.get_pointer_to_relocations(&self)
    => self.raw.pointer_to_relocations;
fn void VipeViewSection.set_pointer_to_relocations(&self, uint v)
    => self.raw.pointer_to_relocations = v;

fn uint VipeViewSection.get_pointer_to_linenumbers(&self)
    => self.raw.pointer_to_linenumbers;
fn void VipeViewSection.set_pointer_to_linenumbers(&self, uint v)
    => self.raw.pointer_to_linenumbers = v;

fn ushort VipeViewSection.get_number_of_relocations(&self)
    => self.raw.number_of_relocations;
fn void VipeViewSection.set_number_of_relocations(&self, ushort v)
    => self.raw.number_of_relocations = v;

fn ushort VipeViewSection.get_number_of_linenumbers(&self)
    => self.raw.number_of_linenumbers;
fn void VipeViewSection.set_number_of_linenumbers(&self, ushort v)
    => self.raw.number_of_linenumbers = v;

fn uint VipeViewSection.get_characteristics(&self)
    => self.raw.characteristics;
fn void VipeViewSection.set_characteristics(&self, uint v)
    => self.raw.characteristics = v;

//
// Callbacks
//

alias VipeCallbackSection = fn bool(VipeViewSection*, any);
