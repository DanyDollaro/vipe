module vipe::relocs;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawBaseRelocation @packed
{
    uint virtual_address;
    uint size_of_block;
}

bitstruct VipeRawBaseRelocationEntry : ushort
{
    ushort offset : 0..11;
    ushort type   : 12..15;
}

struct VipeRawDynamicRelocationTable @packed
{
    uint version;
    uint size;
}

struct VipeRawDynamicRelocation @packed
{
    uint symbol;
    uint base_reloc_size;
}

struct VipeRawDynamicRelocation2 @packed
{
    uint header_size;
    uint fixup_info_size;
    ulong symbol;
    uint symbol_group;
    uint flags;
}

//
// View structures definition
//

struct VipeViewRelocation
{
    uint rva;
    ushort type;
    ushort offset;
}

macro uint VipeViewRelocation.rva(&self)
    => self.rva;
macro ushort VipeViewRelocation.type(&self)
    => self.type;
macro ushort VipeViewRelocation.offset(&self)
    => self.offset;

//
// Callbacks
//

alias VipeCallbackRelocation = fn void?(VipeViewRelocation*, any);
