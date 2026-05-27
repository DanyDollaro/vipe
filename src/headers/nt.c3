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
        VipeRawNtHeaders32* raw32;
        VipeRawNtHeaders64* raw64;
    }
}

macro uint VipeViewNtHeaders.signature(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.signature, self.raw32.signature, v);

fn VipeViewFileHeader VipeViewNtHeaders.file_header(&self)
{
    return {
        .raw = self.is64
            ? &self.raw64.file_header
            : &self.raw32.file_header
    };
}

fn VipeViewOptionalHeader VipeViewNtHeaders.optional_header(&self)
{
    VipeViewOptionalHeader optional_header = {
        .is64 = self.is64
    };
    if (self.is64)
    {
        optional_header.raw64 = &self.raw64.optional_header;
    }
    else
    {
        optional_header.raw32 = &self.raw32.optional_header;
    }

    return optional_header;
}
