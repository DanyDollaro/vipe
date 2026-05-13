module ope::headers::file;
import ope::common;

constdef OpeMachineType
{
    UNKNOWN = 0x0000,
    I386    = 0x014C,
    ARMNT   = 0x01C4,
    AMD64   = 0x8664,
    ARM64   = 0xAA64,
}

struct OpeRawFileHeader @packed
{
    ushort machine;
    ushort number_of_sections;
    uint   time_date_stamp;
    uint   pointer_to_symbol_table;
    uint   number_of_symbols;
    ushort size_of_optional_header;
    ushort characteristics;
}

struct OpeViewFileHeader
{
    OpeRawFileHeader* raw;
}

macro OpeMachineType OpeViewFileHeader.machine(&self, OpeMachineType v = ...)
    => common::@exchange((OpeMachineType)self.raw.machine, v);

macro ushort OpeViewFileHeader.number_of_sections(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_sections, v);

macro uint OpeViewFileHeader.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro uint OpeViewFileHeader.pointer_to_symbol_table(&self, uint v = ...)
    => common::@exchange(self.raw.pointer_to_symbol_table, v);

macro uint OpeViewFileHeader.number_of_symbols(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_symbols, v);

macro ushort OpeViewFileHeader.size_of_optional_header(&self, ushort v = ...)
    => common::@exchange(self.raw.size_of_optional_header, v);

macro ushort OpeViewFileHeader.characteristics(&self, ushort v = ...)
    => common::@exchange(self.raw.characteristics, v);
