module vipe::exceptions;
import vipe::common;
import vipe::sections;

constdef VipeUnwindInfoFlag
{
    NHANDLER  = 0x0,
    EHANDLER  = 0x1,
    UHANDLER  = 0x2,
    CHAININFO = 0x4
}

//
// Raw structures definition
//

struct VipeRawRuntimeFunction @packed
{
    uint begin_address;
    uint end_address;
    uint unwind_info_address;
}

struct VipeRawArmRuntimeFunction @packed
{
    uint begin_address;
    union
    {
        uint unwind_data;
        uint packed_unwind;
    }
}

bitstruct VipeRawUnwindCode : ushort
{
    char code_offset    : 0..7;
    char unwind_op      : 8..11;
    char operation_info : 12..15;
}

bitstruct VipeRawUnwindInfoFlags : char
{
    char version : 0..2;
    char flags   : 3..7;
}

struct VipeRawUnwindInfo @packed
{
    VipeRawUnwindInfoFlags version_flags;
    char size_of_prolog;
    char count_of_codes;
    char frame_register_offset;
}

struct VipeRawScopeTableEntry32 @packed
{
    uint begin_address;
    uint end_address;
    uint handler_address;
    uint jump_target;
}

struct VipeRawExceptionRegistration32 @packed
{
    uint next;
    uint handler;
}

//
// View structures definition
//

struct VipeViewUnwindInfo
{
    VipeRawUnwindInfo*      raw;
    VipeRawUnwindCode[]     unwind_codes;
    uint                    handler_rva;
    VipeRawRuntimeFunction* chained_entry;
}

fn char VipeViewUnwindInfo.get_version(&self)        => self.raw.version_flags.version;
fn char VipeViewUnwindInfo.get_flags(&self)          => self.raw.version_flags.flags;
fn char VipeViewUnwindInfo.get_size_of_prolog(&self) => self.raw.size_of_prolog;
fn char VipeViewUnwindInfo.get_frame_register(&self) => self.raw.frame_register_offset & 0x0F;
fn char VipeViewUnwindInfo.get_frame_offset(&self)   => (self.raw.frame_register_offset >> 4) & 0x0F;

struct VipeExceptionX64
{
    VipeRawRuntimeFunction* raw;
    VipeViewUnwindInfo      unwind_info;
}

fn uint VipeExceptionX64.get_begin_address(&self)   => self.raw.begin_address;
fn void VipeExceptionX64.set_begin_address(&self, uint v) => self.raw.begin_address = v;

fn uint VipeExceptionX64.get_end_address(&self)     => self.raw.end_address;
fn void VipeExceptionX64.set_end_address(&self, uint v) => self.raw.end_address = v;

fn uint VipeExceptionX64.get_unwind_info_rva(&self) => self.raw.unwind_info_address;
fn void VipeExceptionX64.set_unwind_info_rva(&self, uint v) => self.raw.unwind_info_address = v;

struct VipeExceptionArm
{
    VipeRawArmRuntimeFunction* raw;
    bool                       is_packed;
}

fn uint VipeExceptionArm.get_begin_address(&self) => self.raw.begin_address;
fn void VipeExceptionArm.set_begin_address(&self, uint v) => self.raw.begin_address = v;

fn uint VipeExceptionArm.get_xdata_rva(&self)     => self.raw.unwind_data;
fn void VipeExceptionArm.set_xdata_rva(&self, uint v) => self.raw.unwind_data = v;

fn uint VipeExceptionArm.get_packed_unwind(&self) => self.raw.packed_unwind;
fn void VipeExceptionArm.set_packed_unwind(&self, uint v) => self.raw.packed_unwind = v;

//
// Callbacks
//

alias VipeCallbackExceptionX64 = fn bool(VipeExceptionX64*, any);
alias VipeCallbackExceptionArm = fn bool(VipeExceptionArm*, any);

//
// Parsing
//

fn VipeViewUnwindInfo? parse_unwind_info(char[] buffer, VipeRawSectionHeader[] sections, uint ui_rva)
{
    usz ui_off = 0;
    foreach (s : sections)
    {
        if (ui_rva >= s.virtual_address && ui_rva < s.virtual_address + s.virtual_size)
        {
            ui_off = (usz)(ui_rva - s.virtual_address) + s.pointer_to_raw_data;
            break;
        }
    }
    if (ui_off == 0) return common::UNABLE_TO_RESOLVE~;
    if (ui_off + VipeRawUnwindInfo::size > buffer.len) return common::NOT_ENOUGH_DATA~;
    VipeRawUnwindInfo* ui = (VipeRawUnwindInfo*)&buffer[ui_off];

    usz codes_off   = ui_off + VipeRawUnwindInfo::size;
    usz code_count  = (usz)(char)ui.count_of_codes;
    usz codes_bytes = code_count * VipeRawUnwindCode::size;
    if (codes_off + codes_bytes > buffer.len) return common::NOT_ENOUGH_DATA~;

    VipeRawUnwindCode[] codes = ((VipeRawUnwindCode*)&buffer[codes_off])[0..code_count - 1];

    usz padded_count = (code_count + 1) & ~(usz)1;
    usz after_codes  = codes_off + padded_count * VipeRawUnwindCode::size;

    char flags = ui.version_flags.flags;
    uint handler_rva = 0;
    VipeRawRuntimeFunction* chained = null;

    if ((flags & (char)VipeUnwindInfoFlag.CHAININFO) != 0)
    {
        if (after_codes + VipeRawRuntimeFunction::size > buffer.len) return common::NOT_ENOUGH_DATA~;
        chained = (VipeRawRuntimeFunction*)&buffer[after_codes];
    }
    else if ((flags & ((char)VipeUnwindInfoFlag.EHANDLER | (char)VipeUnwindInfoFlag.UHANDLER)) != 0)
    {
        if (after_codes + 4 > buffer.len) return common::NOT_ENOUGH_DATA~;
        handler_rva = *(uint*)&buffer[after_codes];
    }

    return {
        .raw           = ui,
        .unwind_codes  = codes,
        .handler_rva   = handler_rva,
        .chained_entry = chained,
    };
}
