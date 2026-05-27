module vipe::headers::nt;
import vipe::common;
import vipe::headers::file;
import vipe::headers::optional;

const uint PE_SIGNATURE = 0x00004550;

//
// Raw structures definition
//

struct VipeRawNtHeaders32 @packed
{
    uint signature;
    VipeRawFileHeader file_header;
    VipeRawOptionalHeader32 optional_header;
}

struct VipeRawNtHeaders64 @packed
{
    uint signature;
    VipeRawFileHeader file_header;
    VipeRawOptionalHeader64 optional_header;
}

//
// View structures definition
//

struct VipeViewNtHeaders
{
    bool is64;
    union
    {
        VipeRawNtHeaders32* h32;
        VipeRawNtHeaders64* h64;
    }
}

fn void VipeViewNtHeaders.set(&self, bool is64, void* nt_headers)
{
    *self = {
        .is64 = is64
    };
    if (is64)
    {
        self.h64 = nt_headers;
    }
    else
    {
        self.h32 = nt_headers;
    }
}

macro uint VipeViewNtHeaders.signature(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.h64.signature, self.h32.signature, v);

fn VipeViewFileHeader VipeViewNtHeaders.file_header(&self)
{
    return {
        .raw = self.is64
            ? &self.h64.file_header
            : &self.h32.file_header
    };
}

fn VipeViewOptionalHeader VipeViewNtHeaders.optional_header(&self)
{
    VipeViewOptionalHeader optional_header = {
        .is64 = self.is64
    };
    if (self.is64)
    {
        optional_header.h64 = &self.h64.optional_header;
    }
    else
    {
        optional_header.h32 = &self.h32.optional_header;
    }

    return optional_header;
}
