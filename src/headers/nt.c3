module ope::headers::nt;
import ope::common;
import ope::headers::file;
import ope::headers::optional;

struct OpeRawNtHeaders32 @packed
{
    uint                   signature;
    OpeRawFileHeader       file_header;
    OpeRawOptionalHeader32 optional_header;
}

struct OpeRawNtHeaders64 @packed
{
    uint                   signature;
    OpeRawFileHeader       file_header;
    OpeRawOptionalHeader64 optional_header;
}

struct OpeViewNtHeaders
{
    bool is64;
    union
    {
        OpeRawNtHeaders32* h32;
        OpeRawNtHeaders64* h64;
    }
}

macro uint OpeViewNtHeaders.signature(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.signature : self.h32.signature, v);

fn OpeViewFileHeader OpeViewNtHeaders.file_header(&self)
{
    if (self.is64) return { .raw = &self.h64.file_header };
    return             { .raw = &self.h32.file_header };
}

fn OpeViewOptionalHeader OpeViewNtHeaders.optional_header(&self)
{
    if (self.is64) return { .is64 = true,  .h64 = &self.h64.optional_header };
    return             { .is64 = false, .h32 = &self.h32.optional_header };
}
