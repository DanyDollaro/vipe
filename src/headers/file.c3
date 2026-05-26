module vipe::headers::file;
import vipe::common;

constdef VipeMachineType
{
    UNKNOWN = 0x0000,
    I386    = 0x014C,
    ARMNT   = 0x01C4,
    AMD64   = 0x8664,
    ARM64   = 0xAA64,
}

//
// Raw structures definition
//

struct VipeRawFileHeader @packed
{
    VipeMachineType machine;
    ushort number_of_sections;
    uint time_date_stamp;
    uint pointer_to_symbol_table;
    uint number_of_symbols;
    ushort size_of_optional_header;
    ushort characteristics;
}

//
// View structures definition
//

struct VipeViewFileHeader
{
    VipeRawFileHeader* raw;
}

fn VipeMachineType VipeViewFileHeader.get_machine(&self)
    => self.raw.machine;
fn void VipeViewFileHeader.set_machine(&self, VipeMachineType v)
    => self.raw.machine = v;

fn ushort VipeViewFileHeader.get_number_of_sections(&self)
    => self.raw.number_of_sections;
fn void VipeViewFileHeader.set_number_of_sections(&self, ushort v)
    => self.raw.number_of_sections = v;

fn uint VipeViewFileHeader.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewFileHeader.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn uint VipeViewFileHeader.get_pointer_to_symbol_table(&self)
    => self.raw.pointer_to_symbol_table;
fn void VipeViewFileHeader.set_pointer_to_symbol_table(&self, uint v)
    => self.raw.pointer_to_symbol_table = v;

fn uint VipeViewFileHeader.get_number_of_symbols(&self)
    => self.raw.number_of_symbols;
fn void VipeViewFileHeader.set_number_of_symbols(&self, uint v)
    => self.raw.number_of_symbols = v;

fn ushort VipeViewFileHeader.get_size_of_optional_header(&self)
    => self.raw.size_of_optional_header;
fn void VipeViewFileHeader.set_size_of_optional_header(&self, ushort v)
    => self.raw.size_of_optional_header = v;

fn ushort VipeViewFileHeader.get_characteristics(&self)
    => self.raw.characteristics;
fn void VipeViewFileHeader.set_characteristics(&self, ushort v)
    => self.raw.characteristics = v;
