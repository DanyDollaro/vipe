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
    char[]                buffer;
    VipeViewDosHeader     dos;
    VipeViewNtHeaders     nt;
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

    ushort* optional_header_magic = common::extract_struct(ushort, buffer[offset..])!;
    VipeViewNtHeaders nt;
    switch (*optional_header_magic)
    {
        case optional::PE32_MAGIC:
            nt = {
                .is64 = false,
                .h32 = common::extract_struct(VipeRawNtHeaders32, buffer[nt_base..])!
            };
        case optional::PE32PLUS_MAGIC:
            nt = {
                .is64 = true,
                .h64 = common::extract_struct(VipeRawNtHeaders64, buffer[nt_base..])!
            };
        default:
            return common::INVALID_PE~;
    }
    offset += file_header.size_of_optional_header;

    // Handle the case where the PE has no sections
    VipeRawSectionHeader[] sections_headers;
    if (try v = common::extract_struct(VipeRawSectionHeader, buffer[offset..]))
    {
        sections_headers = v[0 .. file_header.number_of_sections - 1];
    }

    *self = {
        .buffer           = buffer,
        .dos              = { .raw = dos_header },
        .nt               = nt,
        .sections_headers = sections_headers,
    };
}

fn uint? VipeViewPe.rva_to_offset(&self, uint rva)
{
    uint size_of_headers = self
        .optional_header()
        .get_size_of_headers();

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
        .get_size_of_headers();

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

fn void? VipeViewPe.foreach_import_descriptor(&self, VipeImportDescriptorCallback callback, any user_data)
{
    VipeRawDataDirectory* import_directory =
        self.get_raw_data_directory(VipeDataDirectoryIndex.IMPORT)!;

    usz offset = self.rva_to_offset(import_directory.virtual_address)!;

    while (offset < import_directory.size)
    {
        VipeRawImportDescriptor* r =
            common::extract_struct(VipeRawImportDescriptor, self.buffer[offset..])!;

        if (common::is_zero_struct(r, VipeRawImportDescriptor::size))
        {
            break;
        }

        ZString dll = (ZString)&self.buffer[self.rva_to_offset(r.name_rva)!];

        VipeViewImportDescriptor desc = {
            .raw = r,
            .dll = dll
        };

        if (!callback(&desc, user_data))
        {
            break;
        }

        offset += VipeRawImportDescriptor::size;
    }
}

struct VipeImportCallbackData @local
{
    VipeImportCallback callback;
    VipeViewPe* pe;
    any user_data;
}

fn void? VipeViewPe.foreach_import(&self, VipeImportCallback callback, any user_data)
{
    any data = &&(VipeImportCallbackData){
        .callback  = callback,
        .pe        = self,
        .user_data = user_data
    };

    self.foreach_import_descriptor(fn bool (VipeViewImportDescriptor* descriptor, any data) {

        // The '!!' should never happen
        VipeImportCallbackData* callback_data = anycast(data, VipeImportCallbackData)!!;

        return true;
    }, data)!;
}

fn void? VipeViewPe.foreach_export(&self, VipeExportCallback callback, any user_data)
{

    // TODO: refactor this function using VipeViewExportDirectory

    VipeRawDataDirectory*  dir     = self.get_raw_data_directory(VipeDataDirectoryIndex.EXPORT)!;
    usz                    exp_off = self.rva_to_offset(dir.virtual_address)!;
    if (exp_off + VipeRawExportDirectory::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
    VipeRawExportDirectory* ed = (VipeRawExportDirectory*)&self.buffer[exp_off];
    uint export_dir_start = dir.virtual_address;
    uint export_dir_end   = dir.virtual_address + dir.size;
    usz  funcs_off = self.rva_to_offset(ed.address_of_functions)!;
    usz  names_off = self.rva_to_offset(ed.address_of_names)!;
    usz  ords_off  = self.rva_to_offset(ed.address_of_name_ordinals)!;
    for (uint i = 0; i < ed.number_of_functions; i++)
    {
        if (funcs_off + (usz)(i + 1) * 4 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        uint func_rva = *(uint*)&self.buffer[funcs_off + (usz)i * 4];
        if (func_rva == 0) continue;
        VipeViewExport entry;
        entry.ordinal = (ushort)(ed.base + i);
        entry.name    = null;
        for (uint ni = 0; ni < ed.number_of_names; ni++)
        {
            if (ords_off + (usz)(ni + 1) * 2 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
            ushort name_ord = *(ushort*)&self.buffer[ords_off + (usz)ni * 2];
            if (name_ord == i)
            {
                if (names_off + (usz)(ni + 1) * 4 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
                uint name_rva = *(uint*)&self.buffer[names_off + (usz)ni * 4];
                entry.name = (ZString)&self.buffer[self.rva_to_offset(name_rva)!];
                break;
            }
        }
        if (func_rva >= export_dir_start && func_rva < export_dir_end)
        {
            entry.is_forwarder = true;
            entry.forwarder    = (ZString)&self.buffer[self.rva_to_offset(func_rva)!];
        }
        else
        {
            entry.is_forwarder = false;
            entry.rva          = func_rva;
        }
        if (!callback(&entry, user_data)) break;
    }
}

fn void? VipeViewPe.foreach_tls_callback(&self, VipeCallbackTls callback, any user_data)
{
    VipeRawDataDirectory*  dir     = self.get_raw_data_directory(VipeDataDirectoryIndex.TLS)!;
    usz                    tls_off = self.rva_to_offset(dir.virtual_address)!;
    bool                   is64    = self.nt.is64;
    VipeViewOptionalHeader oh      = self.nt.optional_header();
    ulong                  ibase   = oh.get_image_base();

    VipeViewTlsDirectory tls_view;
    if (is64)
    {
        if (tls_off + VipeRawTlsDirectory64::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        tls_view = { .is64 = true, .tls64 = (VipeRawTlsDirectory64*)&self.buffer[tls_off] };
    }
    else
    {
        if (tls_off + VipeRawTlsDirectory32::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        tls_view = { .is64 = false, .tls32 = (VipeRawTlsDirectory32*)&self.buffer[tls_off] };
    }

    ulong callbacks_va = tls_view.get_address_of_callbacks();
    if (callbacks_va == 0) return;
    uint callbacks_rva = (uint)(callbacks_va - ibase);
    usz  cb_off        = self.rva_to_offset(callbacks_rva)!;
    while (true)
    {
        ulong fn_va;
        if (is64)
        {
            if (cb_off + 8 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
            fn_va   = *(ulong*)&self.buffer[cb_off];
            cb_off += 8;
        }
        else
        {
            if (cb_off + 4 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
            fn_va   = (ulong)(*(uint*)&self.buffer[cb_off]);
            cb_off += 4;
        }
        if (fn_va == 0) break;
        if (!callback(&tls_view, user_data)) break;
    }
}

fn void? VipeViewPe.foreach_exception_x64(&self, VipeCallbackExceptionX64 callback, any user_data)
{
    if (self.nt.file_header().get_machine() != VipeMachineType.AMD64) return common::UNABLE_TO_RESOLVE~;
    VipeRawDataDirectory* dir   = self.get_raw_data_directory(VipeDataDirectoryIndex.EXCEPTION)!;
    usz                   off   = self.rva_to_offset(dir.virtual_address)!;
    uint                  count = dir.size / (uint)VipeRawRuntimeFunction::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + VipeRawRuntimeFunction::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawRuntimeFunction* r  = (VipeRawRuntimeFunction*)&self.buffer[off];
        VipeViewUnwindInfo      ui = vipe::exceptions::parse_unwind_info(self.buffer, self.sections_headers, r.unwind_info_address)!;
        VipeExceptionX64 ex = { .raw = r, .unwind_info = ui };
        if (!callback(&ex, user_data)) break;
        off += VipeRawRuntimeFunction::size;
    }
}

fn void? VipeViewPe.foreach_exception_arm(&self, VipeCallbackExceptionArm callback, any user_data)
{
    VipeMachineType machine = self.nt.file_header().get_machine();
    if (machine != VipeMachineType.ARMNT && machine != VipeMachineType.ARM64) return common::UNABLE_TO_RESOLVE~;
    VipeRawDataDirectory* dir   = self.get_raw_data_directory(VipeDataDirectoryIndex.EXCEPTION)!;
    usz                   off   = self.rva_to_offset(dir.virtual_address)!;
    uint                  count = dir.size / (uint)VipeRawArmRuntimeFunction::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + VipeRawArmRuntimeFunction::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawArmRuntimeFunction* r  = (VipeRawArmRuntimeFunction*)&self.buffer[off];
        bool                       ip = (r.packed_unwind & 1) != 0;
        VipeExceptionArm ex = { .raw = r, .is_packed = ip };
        if (!callback(&ex, user_data)) break;
        off += VipeRawArmRuntimeFunction::size;
    }
}

fn void? VipeViewPe.foreach_delayed_import_descriptor(&self, VipeCallbackDelayedImportDescriptor callback, any user_data)
{
    VipeRawDataDirectory* dir = self.get_raw_data_directory(VipeDataDirectoryIndex.DELAY_IMPORT)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    while (true)
    {
        if (off + VipeRawDelayImportDescriptor::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawDelayImportDescriptor* r = (VipeRawDelayImportDescriptor*)&self.buffer[off];
        if (r.dll_name_rva == 0) break;
        ZString dll = (ZString)&self.buffer[self.rva_to_offset(r.dll_name_rva)!];
        VipeViewDelayedImportDescriptor desc = { .raw = r, .dll = dll };
        if (!callback(&desc, user_data)) break;
        off += VipeRawDelayImportDescriptor::size;
    }
}

fn void? VipeViewPe.foreach_delayed_import(&self, VipeCallbackDelayedImport callback, any user_data)
{
    VipeRawDataDirectory* dir      = self.get_raw_data_directory(VipeDataDirectoryIndex.DELAY_IMPORT)!;
    usz                   desc_off = self.rva_to_offset(dir.virtual_address)!;
    bool                  is64     = self.nt.is64;
    while (true)
    {
        if (desc_off + VipeRawDelayImportDescriptor::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawDelayImportDescriptor* r = (VipeRawDelayImportDescriptor*)&self.buffer[desc_off];
        if (r.dll_name_rva == 0) break;
        usz  ilt_off   = self.rva_to_offset(r.ilt_rva)!;
        uint entry_idx = 0;
        while (true)
        {
            ulong thunk;
            if (is64)
            {
                if (ilt_off + 8 > self.buffer.len) break;
                thunk = *(ulong*)&self.buffer[ilt_off];
                if (thunk == 0) break;
                ilt_off += 8;
            }
            else
            {
                if (ilt_off + 4 > self.buffer.len) break;
                thunk = (ulong)(*(uint*)&self.buffer[ilt_off]);
                if (thunk == 0) break;
                ilt_off += 4;
            }
            uint cur_iat_rva = r.iat_rva + entry_idx * (is64 ? 8u : 4u);
            bool is_ord      = is64 ? ((thunk >> 63) != 0) : ((thunk >> 31) != 0);
            VipeViewDelayedImport imp;
            imp.iat_entry_rva = cur_iat_rva;
            if (is_ord)
            {
                imp.is_ordinal = true;
                imp.ordinal    = (ushort)(thunk & 0xFFFF);
                imp.name       = (ZString)(char*)null;
                imp.hint       = 0;
            }
            else
            {
                uint name_rva = (uint)(thunk & 0x7FFFFFFF);
                usz  name_off = self.rva_to_offset(name_rva)!;
                if (name_off + 2 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
                imp.hint       = *(ushort*)&self.buffer[name_off];
                imp.name       = (ZString)&self.buffer[name_off + 2];
                imp.ordinal    = 0;
                imp.is_ordinal = false;
            }
            if (!callback(&imp, user_data)) return;
            entry_idx++;
        }
        desc_off += VipeRawDelayImportDescriptor::size;
    }
}

fn void? VipeViewPe.foreach_bound_import(&self, VipeCallbackBoundImport callback, any user_data)
{
    VipeRawDataDirectory* dir      = self.get_raw_data_directory(VipeDataDirectoryIndex.BOUND_IMPORT)!;
    usz                   base_off = (usz)dir.virtual_address;
    usz                   off      = base_off;
    while (true)
    {
        if (off + VipeRawBoundImportDescriptor::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawBoundImportDescriptor* r = (VipeRawBoundImportDescriptor*)&self.buffer[off];
        if (r.time_date_stamp == 0 && r.offset_module_name == 0) break;
        usz name_off = base_off + (usz)r.offset_module_name;
        if (name_off >= self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeViewBoundImportDescriptor desc = { .raw = r, .dll = (ZString)&self.buffer[name_off] };
        if (!callback(&desc, user_data)) break;
        off += VipeRawBoundImportDescriptor::size;
    }
}

fn void? VipeViewPe.foreach_debug_entry(&self, VipeCallbackDebug callback, any user_data)
{
    VipeRawDataDirectory* dir   = self.get_raw_data_directory(VipeDataDirectoryIndex.DEBUG)!;
    usz                   off   = self.rva_to_offset(dir.virtual_address)!;
    uint                  count = dir.size / (uint)VipeRawDebugDirectory::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + VipeRawDebugDirectory::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawDebugDirectory* r = (VipeRawDebugDirectory*)&self.buffer[off];
        char[] data;
        if (r.size_of_data > 0 && r.pointer_to_raw_data > 0)
        {
            usz d_off = (usz)r.pointer_to_raw_data;
            if (d_off + r.size_of_data <= self.buffer.len)
            {
                data = self.buffer[d_off..d_off + r.size_of_data - 1];
            }
        }
        VipeViewDebug entry = { .raw = r, .data = data };
        if (!callback(&entry, user_data)) break;
        off += VipeRawDebugDirectory::size;
    }
}

fn void? VipeViewPe.foreach_relocation(&self, VipeCallbackRelocation callback, any user_data)
{
    VipeRawDataDirectory* dir = self.get_raw_data_directory(VipeDataDirectoryIndex.BASERELOC)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    usz end = off + (usz)dir.size;
    while (off < end)
    {
        if (off + VipeRawBaseRelocation::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawBaseRelocation* block = (VipeRawBaseRelocation*)&self.buffer[off];
        if (block.size_of_block < VipeRawBaseRelocation::size) return common::NOT_ENOUGH_DATA~;
        uint page_rva  = block.virtual_address;
        uint entries   = (block.size_of_block - (uint)VipeRawBaseRelocation::size) / 2;
        usz  entry_off = off + VipeRawBaseRelocation::size;
        for (uint i = 0; i < entries; i++)
        {
            if (entry_off + 2 > self.buffer.len) return common::NOT_ENOUGH_DATA~;
            VipeRawBaseRelocationEntry e = *(VipeRawBaseRelocationEntry*)&self.buffer[entry_off];
            VipeViewRelocation rel = { .rva = page_rva + e.offset, .type = e.type, .offset = e.offset };
            if (!callback(&rel, user_data)) return;
            entry_off += 2;
        }
        off += (usz)block.size_of_block;
    }
}

fn bool? VipeViewPe.walk_resource_dir(
    &self, usz res_base, usz dir_off, uint depth,
    uint type_id, uint name_id, VipeCallbackResource callback, any user_data)
{
    if (dir_off + VipeRawResourceDirectory::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
    VipeRawResourceDirectory* dir = (VipeRawResourceDirectory*)&self.buffer[dir_off];
    uint total     = (uint)dir.number_of_named_entries + (uint)dir.number_of_id_entries;
    usz  entry_off = dir_off + VipeRawResourceDirectory::size;
    for (uint i = 0; i < total; i++)
    {
        if (entry_off + VipeRawResourceDirectoryEntry::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawResourceDirectoryEntry* e = (VipeRawResourceDirectoryEntry*)&self.buffer[entry_off];
        entry_off += VipeRawResourceDirectoryEntry::size;
        uint id            = e.name_or_id & 0x7FFFFFFF;
        uint child_off_raw = e.offset_to_data_or_directory;
        bool is_dir        = (child_off_raw >> 31) != 0;
        usz  child_off     = res_base + (usz)(child_off_raw & 0x7FFFFFFF);
        if (is_dir)
        {
            uint next_type = depth == 0 ? id : type_id;
            uint next_name = depth == 1 ? id : name_id;
            bool cont = self.walk_resource_dir(res_base, child_off, depth + 1, next_type, next_name, callback, user_data)!;
            if (!cont) return false;
        }
        else
        {
            if (child_off + VipeRawResourceDataEntry::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
            VipeRawResourceDataEntry* de = (VipeRawResourceDataEntry*)&self.buffer[child_off];
            usz data_off = self.rva_to_offset(de.offset_to_data)!;
            char[] data;
            if (data_off + de.size <= self.buffer.len)
            {
                data = self.buffer[data_off..data_off + de.size - 1];
            }
            VipeViewResource leaf = {
                .raw         = de,
                .type_id     = type_id,
                .name_id     = name_id,
                .language_id = id,
                .data        = data,
            };
            if (!callback(&leaf, user_data)) return false;
        }
    }
    return true;
}

fn void? VipeViewPe.foreach_resource(&self, VipeCallbackResource callback, any user_data)
{
    VipeRawDataDirectory* dir      = self.get_raw_data_directory(VipeDataDirectoryIndex.RESOURCE)!;
    usz                   res_base = self.rva_to_offset(dir.virtual_address)!;
    self.walk_resource_dir(res_base, res_base, 0, 0, 0, callback, user_data)!;
}

fn void? VipeViewPe.foreach_certificate(&self, VipeCallbackCertificate callback, any user_data)
{
    VipeRawDataDirectory* dir = self.get_raw_data_directory(VipeDataDirectoryIndex.CERTIFICATE)!;
    usz off = (usz)dir.virtual_address;
    usz end = off + (usz)dir.size;
    while (off < end)
    {
        if (off + VipeRawWinCertificate::size > self.buffer.len) return common::NOT_ENOUGH_DATA~;
        VipeRawWinCertificate* r = (VipeRawWinCertificate*)&self.buffer[off];
        if (r.length < VipeRawWinCertificate::size) return common::NOT_ENOUGH_DATA~;
        usz data_len = (usz)r.length - VipeRawWinCertificate::size;
        char[] data;
        if (data_len > 0 && off + VipeRawWinCertificate::size + data_len <= self.buffer.len)
        {
            data = self.buffer[off + VipeRawWinCertificate::size..off + VipeRawWinCertificate::size + data_len - 1];
        }
        VipeViewCertificate cert = { .raw = r, .data = data };
        if (!callback(&cert, user_data)) break;
        usz aligned = ((usz)r.length + 7) & ~(usz)7u;
        off += aligned;
    }
}

fn VipeViewCor20Header? VipeViewPe.cor20_header(&self)
{
    VipeRawDataDirectory* clr_directory =
        self.get_raw_data_directory(VipeDataDirectoryIndex.CLR_RUNTIME)!;

    usz offset = self.rva_to_offset(clr_directory.virtual_address)!;

    return {
        .raw = common::extract_struct(VipeRawCor20Header, &self.buffer[offset..])
    };
}
