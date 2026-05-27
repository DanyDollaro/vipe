module vipe::headers::file;
import vipe::common;

constdef VipeMachineType : ushort
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

macro VipeMachineType VipeViewFileHeader.machine(&self, VipeMachineType v = ...)
    => common::@exchange(self.raw.machine, v);

macro ushort VipeViewFileHeader.number_of_sections(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_sections, v);

macro uint VipeViewFileHeader.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro uint VipeViewFileHeader.pointer_to_symbol_table(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_symbol_table, v);

macro uint VipeViewFileHeader.number_of_symbols(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_symbols, v);

macro ushort VipeViewFileHeader.size_of_optional_header(&self, ushort v = ...)
    => common::@exchange(self.raw.size_of_optional_header, v);

macro ushort VipeViewFileHeader.characteristics(&self, ushort v = ...)
    => common::@exchange(self.raw.characteristics, v);
