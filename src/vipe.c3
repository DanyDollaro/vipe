module vipe;
import vipe::common;
import vipe::headers::dos;
import vipe::headers::file;
import vipe::headers::optional;
import vipe::headers::nt;
import vipe::sections;
import vipe::imports;
import vipe::exports;
import vipe::exceptions;
import vipe::load_config;
import vipe::relocs;
import vipe::debug;
import vipe::tls;
import vipe::bound_imports;
import vipe::delay_imports;
import vipe::resources;
import vipe::certs;
import vipe::clr;

// TODO:
//
// - the NOT_ENOUGH_DATA could be completly removed interally handling the case where there are
//  remaining bytes that cannot be converted into the corresponding struct just by ignoring them.
//  EDIT: I actually realized that fault gets returned by extract_struct, it could not completly
//  removed but can be internally handled
//

struct VipeViewPe
{
    char[] buffer;
    VipeViewDosHeader dos;
    VipeViewNtHeaders nt;
    VipeRawSectionHeader[] sections_headers;
}

fn void? VipeViewPe.set(&self, char[] buffer)
{
    VipeRawDosHeader* dos_header = common::extract_struct(VipeRawDosHeader, buffer)!;
    if (dos_header.e_magic != dos::DOS_MAGIC)
    {
        return common::INVALID_PE~;
    }

    sz offset = dos_header.e_lfanew;
    sz nt_base = offset;

    uint* nt_headers_signature = common::extract_struct(uint, buffer[offset..])!;
    if (*nt_headers_signature != nt::PE_SIGNATURE)
    {
        return common::INVALID_PE~;
    }

    offset += uint::size;
    VipeRawFileHeader* file_header = common::extract_struct(VipeRawFileHeader, buffer[offset..])!;
    offset += VipeRawFileHeader::size;

    ushort* optional_header_magic =
        common::extract_struct(ushort, buffer[offset..])!;
    VipeViewNtHeaders nt_headers;
    switch (*optional_header_magic)
    {
        // TODO: write a function to do not manage these fields directly
        case optional::PE32_MAGIC:
            nt_headers = {
                .is64 = false,
                .raw32 = common::extract_struct(VipeRawNtHeaders32, buffer[nt_base..])!
            };
        case optional::PE32PLUS_MAGIC:
            nt_headers = {
                .is64 = true,
                .raw64 = common::extract_struct(VipeRawNtHeaders64, buffer[nt_base..])!
            };
        default:
            return common::INVALID_PE~;
    }
    offset += file_header.size_of_optional_header;

    // Handle the case where the PE has no sections
    VipeRawSectionHeader[] sections_headers;
    if (try v = common::extract_struct(VipeRawSectionHeader, buffer[offset..]))
    {
        sections_headers = v[0 : file_header.number_of_sections];
    }

    *self = {
        .buffer           = buffer,
        .dos              = { .raw = dos_header },
        .nt               = nt_headers,
        .sections_headers = sections_headers,
    };
}

fn uint? VipeViewPe.rva_to_offset(&self, uint rva)
{
    uint size_of_headers = self
        .optional_header()
        .size_of_headers();

    if (rva < size_of_headers)
    {
        return rva;
    }

    foreach (s : self.sections_headers)
    {
        if (rva >= s.virtual_address &&
            rva < s.virtual_address + s.virtual_size)
        {
            return rva - s.virtual_address + s.pointer_to_raw_data;
        }
    }

    return common::UNABLE_TO_RESOLVE~;
}

fn usz? VipeViewPe.offset_to_rva(&self, usz offset)
{
    ulong size_of_headers = self
        .optional_header()
        .size_of_headers();

    if (offset < size_of_headers)
    {
        return offset;
    }

    foreach (s : self.sections_headers)
    {
        if (offset >= (usz)s.pointer_to_raw_data &&
            offset <  (usz)s.pointer_to_raw_data + (usz)s.size_of_raw_data)
        {
            return (usz)(offset - s.pointer_to_raw_data) + s.virtual_address;
        }
    }

    return common::UNABLE_TO_RESOLVE~;
}

fn VipeViewDosHeader      VipeViewPe.dos_header(&self)      => self.dos;
fn VipeViewNtHeaders      VipeViewPe.nt_headers(&self)      => self.nt;
fn VipeViewFileHeader     VipeViewPe.file_header(&self)     => self.nt.file_header();
fn VipeViewOptionalHeader VipeViewPe.optional_header(&self) => self.nt.optional_header();

fn VipeRawDataDirectory*? VipeViewPe.get_raw_data_directory(&self, VipeDataDirectoryIndex i)
{
    VipeRawDataDirectory* data_directory = self
        .nt_headers()
        .optional_header()
        .data_directory(i);

    if (!data_directory.virtual_address || !data_directory.size)
    {
        return common::MISSING_RESOURCE~;
    }

    return data_directory;
}

fn void VipeViewPe.foreach_section(&self, VipeCallbackSection callback, any user_data)
{
    foreach (&s : self.sections_headers)
    {
        VipeViewSection section = {
            .raw  = s,
            .data = self.buffer[
                s.pointer_to_raw_data .. s.pointer_to_raw_data + s.size_of_raw_data - 1
            ]
        };

        if (!callback(&section, user_data))
        {
            break;
        }
    }
}

fn void? VipeViewPe.foreach_import_descriptor(&self, VipeCallbackImportDescriptor callback, any user_data)
{
    VipeRawDataDirectory* import_directory =
        self.get_raw_data_directory(VipeDataDirectoryIndex.IMPORT)!;

    usz offset = self.rva_to_offset(import_directory.virtual_address)!;

    while (offset < import_directory.size)
    {
        VipeRawImportDescriptor* r =
            common::extract_struct(VipeRawImportDescriptor, self.buffer[offset..])!;

        if (common::is_zero_struct(&r, VipeRawImportDescriptor::size))
        {
            break;
        }

        ZString name = (ZString)&self.buffer[self.rva_to_offset(r.name_rva)!];

        VipeViewImportDescriptor desc = {
            .raw = r,
            .name = name
        };

        if (!callback(&desc, user_data))
        {
            break;
        }

        offset += VipeRawImportDescriptor::size;
    }
}

fn void? VipeViewPe.foreach_import(&self, VipeCallbackImport callback, any user_data)
{

}

fn void? VipeViewPe.foreach_export(&self, VipeCallbackExport callback, any user_data)
{


}

fn void? VipeViewPe.foreach_tls_callback(&self, VipeCallbackTls callback, any user_data)
{

}

fn void? VipeViewPe.foreach_exception_x64(&self, VipeCallbackExceptionX64 callback, any user_data)
{

}

fn void? VipeViewPe.foreach_exception_arm(&self, VipeCallbackExceptionArm callback, any user_data)
{

}

fn void? VipeViewPe.foreach_delayed_import_descriptor(&self, VipeCallbackDelayedImportDescriptor callback, any user_data)
{

}

fn void? VipeViewPe.foreach_delayed_import(&self, VipeCallbackDelayedImport callback, any user_data)
{

}

fn void? VipeViewPe.foreach_bound_import(&self, VipeCallbackBoundImport callback, any user_data)
{

}

fn void? VipeViewPe.foreach_debug_entry(&self, VipeCallbackDebug callback, any user_data)
{

}

fn void? VipeViewPe.foreach_relocation(&self, VipeCallbackRelocation callback, any user_data)
{

}

fn void? VipeViewPe.foreach_resource(&self, VipeCallbackResource callback, any user_data)
{

}

fn void? VipeViewPe.foreach_certificate(&self, VipeCallbackCertificate callback, any user_data)
{

}

fn VipeViewCor20Header? VipeViewPe.cor20_header(&self)
{
    VipeRawDataDirectory* clr_directory =
        self.get_raw_data_directory(VipeDataDirectoryIndex.CLR_RUNTIME)!;

    usz offset = self.rva_to_offset(clr_directory.virtual_address)!;

    // TODO: finish this function
    return { };
}
