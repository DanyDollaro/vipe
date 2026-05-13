module ope::relocs;
import ope::common;

struct OpeRawBaseRelocation @packed
{
    uint virtual_address;
    uint size_of_block;
}

bitstruct OpeRawBaseRelocationEntry : ushort
{
    ushort offset : 0..11;
    ushort type   : 12..15;
}

struct OpeRawDynamicRelocationTable @packed
{
    uint version;
    uint size;
}

struct OpeRawDynamicRelocation @packed
{
    uint symbol;
    uint base_reloc_size;
}

struct OpeRawDynamicRelocation2 @packed
{
    uint  header_size;
    uint  fixup_info_size;
    ulong symbol;
    uint  symbol_group;
    uint  flags;
}

struct OpeViewRelocation
{
    uint   rva;
    ushort type;
    ushort offset;
}

macro uint OpeViewRelocation.rva(&self, uint v = ...)
    => common::@exchange(self.rva, v);

macro ushort OpeViewRelocation.type(&self, ushort v = ...)
    => common::@exchange(self.type, v);

macro ushort OpeViewRelocation.offset(&self, ushort v = ...)
    => common::@exchange(self.offset, v);

alias OpeRelocationCallback = fn bool(OpeViewRelocation*);
