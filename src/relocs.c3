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

fn uint VipeViewRelocation.get_rva(&self)    => self.rva;
fn ushort VipeViewRelocation.get_type(&self)   => self.type;
fn ushort VipeViewRelocation.get_offset(&self) => self.offset;

//
// Callbacks
//

alias VipeCallbackRelocation = fn bool(VipeViewRelocation*, any);
