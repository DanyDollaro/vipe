module ope::exceptions;
import ope::common;
import ope::sections;

constdef OpeUnwindInfoFlag
{
    NHANDLER  = 0x0,
    EHANDLER  = 0x1,
    UHANDLER  = 0x2,
    CHAININFO = 0x4,
}

struct OpeRawRuntimeFunction @packed
{
    uint begin_address;
    uint end_address;
    uint unwind_info_address;
}

struct OpeRawArmRuntimeFunction @packed
{
    uint begin_address;
    union
    {
        uint unwind_data;
        uint packed_unwind;
    }
}

bitstruct OpeRawUnwindCode : ushort
{
    char code_offset    : 0..7;
    char unwind_op      : 8..11;
    char operation_info : 12..15;
}

bitstruct OpeRawUnwindInfoFlags : char
{
    char version : 0..2;
    char flags   : 3..7;
}

struct OpeRawUnwindInfo @packed
{
    OpeRawUnwindInfoFlags version_flags;
    char size_of_prolog;
    char count_of_codes;
    char frame_register_offset;
}

struct OpeRawScopeTableEntry32 @packed
{
    uint begin_address;
    uint end_address;
    uint handler_address;
    uint jump_target;
}

struct OpeRawExceptionRegistration32 @packed
{
    uint next;
    uint handler;
}

struct OpeViewUnwindInfo
{
    OpeRawUnwindInfo*      raw;
    OpeRawUnwindCode[]     unwind_codes;
    uint                   handler_rva;
    OpeRawRuntimeFunction* chained_entry;
}

fn char OpeViewUnwindInfo.version(&self)        => self.raw.version_flags.version;
fn char OpeViewUnwindInfo.flags(&self)          => self.raw.version_flags.flags;
fn char OpeViewUnwindInfo.size_of_prolog(&self) => self.raw.size_of_prolog;
fn char OpeViewUnwindInfo.frame_register(&self) => self.raw.frame_register_offset & 0x0F;
fn char OpeViewUnwindInfo.frame_offset(&self)   => (self.raw.frame_register_offset >> 4) & 0x0F;

struct OpeX64Exception
{
    OpeRawRuntimeFunction* raw;
    OpeViewUnwindInfo      unwind_info;
}

fn uint OpeX64Exception.begin_address(&self)   => self.raw.begin_address;
fn uint OpeX64Exception.end_address(&self)     => self.raw.end_address;
fn uint OpeX64Exception.unwind_info_rva(&self) => self.raw.unwind_info_address;

struct OpeArmException
{
    OpeRawArmRuntimeFunction* raw;
    bool                      is_packed;
}

fn uint OpeArmException.begin_address(&self) => self.raw.begin_address;
fn uint OpeArmException.xdata_rva(&self)     => self.raw.unwind_data;
fn uint OpeArmException.packed_unwind(&self) => self.raw.packed_unwind;

alias OpeX64ExceptionCallback = fn bool(OpeX64Exception*);
alias OpeArmExceptionCallback = fn bool(OpeArmException*);

fn OpeViewUnwindInfo? parse_unwind_info(char[] buffer, OpeRawSectionHeader[] sections, uint ui_rva)
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
    if (ui_off + OpeRawUnwindInfo::size > buffer.len) return common::TRUNCATED_DATA~;
    OpeRawUnwindInfo* ui = (OpeRawUnwindInfo*)&buffer[ui_off];

    usz codes_off   = ui_off + OpeRawUnwindInfo::size;
    usz code_count  = (usz)(char)ui.count_of_codes;
    usz codes_bytes = code_count * OpeRawUnwindCode::size;
    if (codes_off + codes_bytes > buffer.len) return common::TRUNCATED_DATA~;

    OpeRawUnwindCode[] codes = ((OpeRawUnwindCode*)&buffer[codes_off])[0..code_count - 1];

    usz padded_count = (code_count + 1) & ~(usz)1;
    usz after_codes  = codes_off + padded_count * OpeRawUnwindCode::size;

    char flags = ui.version_flags.flags;
    uint handler_rva = 0;
    OpeRawRuntimeFunction* chained = null;

    if ((flags & (char)OpeUnwindInfoFlag.CHAININFO) != 0)
    {
        if (after_codes + OpeRawRuntimeFunction::size > buffer.len) return common::TRUNCATED_DATA~;
        chained = (OpeRawRuntimeFunction*)&buffer[after_codes];
    }
    else if ((flags & ((char)OpeUnwindInfoFlag.EHANDLER | (char)OpeUnwindInfoFlag.UHANDLER)) != 0)
    {
        if (after_codes + 4 > buffer.len) return common::TRUNCATED_DATA~;
        handler_rva = *(uint*)&buffer[after_codes];
    }

    return {
        .raw           = ui,
        .unwind_codes  = codes,
        .handler_rva   = handler_rva,
        .chained_entry = chained,
    };
}
