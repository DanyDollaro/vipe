module ope;
import ope::common;
import ope::headers::dos;
import ope::headers::file;
import ope::headers::optional;
import ope::headers::nt;
import ope::sections;
import ope::imports;
import ope::exports;
import ope::exceptions;
import ope::load_config;
import ope::relocs;
import ope::debug;
import ope::tls;
import ope::bound_imports;
import ope::delay_imports;
import ope::resources;
import ope::certs;
import ope::clr;

struct OpeViewPe
{
    char[]                buffer;
    OpeViewDosHeader      dos;
    OpeViewNtHeaders      nt;
    OpeRawSectionHeader[] section_headers;
}

fn void? OpeViewPe.init(&self, char[] buffer)
{
    OpeRawDosHeader* dos = common::extract_struct(OpeRawDosHeader, buffer)!;
    if (dos.e_magic != dos::DOS_MAGIC) return common::SIGNATURE_MISMATCH~;

    usz nt_off = (usz)dos.e_lfanew;
    if (nt_off + 4 > buffer.len) return common::TRUNCATED_DATA~;
    uint sig = *(uint*)&buffer[nt_off];
    if (sig != dos::PE_SIGNATURE) return common::SIGNATURE_MISMATCH~;

    usz fh_off = nt_off + 4;
    if (fh_off + OpeRawFileHeader::size > buffer.len) return common::TRUNCATED_DATA~;
    OpeRawFileHeader* fh = (OpeRawFileHeader*)&buffer[fh_off];

    usz oh_off = fh_off + OpeRawFileHeader::size;
    if (oh_off + 2 > buffer.len) return common::TRUNCATED_DATA~;
    ushort magic = *(ushort*)&buffer[oh_off];

    OpeViewNtHeaders nt;
    switch (magic)
    {
        case optional::PE32_MAGIC:
            if (oh_off + OpeRawNtHeaders32::size > buffer.len) return common::TRUNCATED_DATA~;
            nt = { .is64 = false, .h32 = (OpeRawNtHeaders32*)&buffer[nt_off] };
        case optional::PE32PLUS_MAGIC:
            if (oh_off + OpeRawNtHeaders64::size > buffer.len) return common::TRUNCATED_DATA~;
            nt = { .is64 = true, .h64 = (OpeRawNtHeaders64*)&buffer[nt_off] };
        default:
            return common::UNABLE_TO_RESOLVE~;
    }

    usz sec_off   = oh_off + fh.size_of_optional_header;
    usz sec_count = fh.number_of_sections;
    if (sec_off + sec_count * OpeRawSectionHeader::size > buffer.len) return common::TRUNCATED_DATA~;
    OpeRawSectionHeader* sec_ptr = (OpeRawSectionHeader*)&buffer[sec_off];

    *self = {
        .buffer          = buffer,
        .dos             = { .raw = dos },
        .nt              = nt,
        .section_headers = sec_ptr[0..sec_count - 1],
    };
}

fn usz? OpeViewPe.rva_to_offset(&self, uint rva)
{
    foreach (s : self.section_headers)
    {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
        {
            return (usz)(rva - s.virtual_address) + s.pointer_to_raw_data;
        }
    }
    return common::UNABLE_TO_RESOLVE~;
}

fn usz? OpeViewPe.offset_to_rva(&self, usz offset)
{
    foreach (s : self.section_headers)
    {
        if (offset >= (usz)s.pointer_to_raw_data &&
            offset <  (usz)s.pointer_to_raw_data + (usz)s.size_of_raw_data)
        {
            return (usz)(offset - s.pointer_to_raw_data) + s.virtual_address;
        }
    }
    return common::UNABLE_TO_RESOLVE~;
}

fn OpeViewDosHeader      OpeViewPe.dos_header(&self)      => self.dos;
fn OpeViewNtHeaders      OpeViewPe.nt_headers(&self)      => self.nt;
fn OpeViewFileHeader     OpeViewPe.file_header(&self)     => self.nt.file_header();
fn OpeViewOptionalHeader OpeViewPe.optional_header(&self) => self.nt.optional_header();

fn OpeRawDataDirectory? OpeViewPe.get_data_directory_as_data(&self, OpeDataDirectoryIndex i)
{
    OpeViewOptionalHeader oh  = self.nt.optional_header();
    OpeRawDataDirectory   dir = oh.data_directory(i);
    if (dir.virtual_address == 0 || dir.size == 0) return common::MISSING_RESOURCE~;
    return dir;
}

fn void? OpeViewPe.foreach_section(&self, OpeSectionCallback cb)
{
    foreach (&r : self.section_headers)
    {
        char[] data;
        if (r.pointer_to_raw_data > 0 && r.size_of_raw_data > 0)
        {
            usz ds = (usz)r.pointer_to_raw_data;
            usz de = ds + (usz)r.size_of_raw_data;
            if (de > self.buffer.len) return common::TRUNCATED_DATA~;
            data = self.buffer[ds..de - 1];
        }
        OpeViewSection sec = { .raw = r, .data = data };
        if (!cb(&sec)) break;
    }
}

fn void? OpeViewPe.foreach_import_descriptor(&self, OpeImportDescriptorCallback cb)
{
    OpeRawDataDirectory dir = self.get_data_directory_as_data(OpeDataDirectoryIndex.IMPORT)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    while (true)
    {
        if (off + OpeRawImportDescriptor::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawImportDescriptor* r = (OpeRawImportDescriptor*)&self.buffer[off];
        if (r.original_first_thunk == 0 && r.first_thunk == 0) break;
        ZString dll = (ZString)&self.buffer[self.rva_to_offset(r.name_rva)!];
        OpeViewImportDescriptor desc = { .raw = r, .dll = dll };
        if (!cb(&desc)) break;
        off += OpeRawImportDescriptor::size;
    }
}

fn void? OpeViewPe.foreach_import(&self, OpeImportCallback cb)
{
    OpeRawDataDirectory dir      = self.get_data_directory_as_data(OpeDataDirectoryIndex.IMPORT)!;
    usz                 desc_off = self.rva_to_offset(dir.virtual_address)!;
    bool                is64     = self.nt.is64;
    while (true)
    {
        if (desc_off + OpeRawImportDescriptor::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawImportDescriptor* r = (OpeRawImportDescriptor*)&self.buffer[desc_off];
        if (r.original_first_thunk == 0 && r.first_thunk == 0) break;
        uint ilt_rva   = r.original_first_thunk != 0 ? r.original_first_thunk : r.first_thunk;
        uint iat_rva   = r.first_thunk;
        usz  ilt_off   = self.rva_to_offset(ilt_rva)!;
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
            uint cur_iat_rva = iat_rva + entry_idx * (is64 ? 8u : 4u);
            bool is_ord      = is64 ? ((thunk >> 63) != 0) : ((thunk >> 31) != 0);
            OpeViewImport imp;
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
                if (name_off + 2 > self.buffer.len) return common::TRUNCATED_DATA~;
                imp.hint       = *(ushort*)&self.buffer[name_off];
                imp.name       = (ZString)&self.buffer[name_off + 2];
                imp.ordinal    = 0;
                imp.is_ordinal = false;
            }
            if (!cb(&imp)) return;
            entry_idx++;
        }
        desc_off += OpeRawImportDescriptor::size;
    }
}

fn void? OpeViewPe.foreach_export(&self, OpeExportCallback cb)
{
    OpeRawDataDirectory    dir     = self.get_data_directory_as_data(OpeDataDirectoryIndex.EXPORT)!;
    usz                    exp_off = self.rva_to_offset(dir.virtual_address)!;
    if (exp_off + OpeRawExportDirectory::size > self.buffer.len) return common::TRUNCATED_DATA~;
    OpeRawExportDirectory* ed = (OpeRawExportDirectory*)&self.buffer[exp_off];
    uint export_dir_start = dir.virtual_address;
    uint export_dir_end   = dir.virtual_address + dir.size;
    usz  funcs_off = self.rva_to_offset(ed.address_of_functions)!;
    usz  names_off = self.rva_to_offset(ed.address_of_names)!;
    usz  ords_off  = self.rva_to_offset(ed.address_of_name_ordinals)!;
    for (uint i = 0; i < ed.number_of_functions; i++)
    {
        if (funcs_off + (usz)(i + 1) * 4 > self.buffer.len) return common::TRUNCATED_DATA~;
        uint func_rva = *(uint*)&self.buffer[funcs_off + (usz)i * 4];
        if (func_rva == 0) continue;
        OpeViewExport entry;
        entry.ordinal = (ushort)(ed.base + i);
        entry.name    = null;
        for (uint ni = 0; ni < ed.number_of_names; ni++)
        {
            if (ords_off + (usz)(ni + 1) * 2 > self.buffer.len) return common::TRUNCATED_DATA~;
            ushort name_ord = *(ushort*)&self.buffer[ords_off + (usz)ni * 2];
            if (name_ord == i)
            {
                if (names_off + (usz)(ni + 1) * 4 > self.buffer.len) return common::TRUNCATED_DATA~;
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
        if (!cb(&entry)) break;
    }
}

fn void? OpeViewPe.foreach_tls_callback(&self, OpeTlsCallback cb)
{
    OpeRawDataDirectory   dir     = self.get_data_directory_as_data(OpeDataDirectoryIndex.TLS)!;
    usz                   tls_off = self.rva_to_offset(dir.virtual_address)!;
    bool                  is64    = self.nt.is64;
    OpeViewOptionalHeader oh      = self.nt.optional_header();
    ulong                 ibase   = oh.image_base();

    OpeViewTlsDirectory tls_view;
    if (is64)
    {
        if (tls_off + OpeRawTlsDirectory64::size > self.buffer.len) return common::TRUNCATED_DATA~;
        tls_view = { .is64 = true, .tls64 = (OpeRawTlsDirectory64*)&self.buffer[tls_off] };
    }
    else
    {
        if (tls_off + OpeRawTlsDirectory32::size > self.buffer.len) return common::TRUNCATED_DATA~;
        tls_view = { .is64 = false, .tls32 = (OpeRawTlsDirectory32*)&self.buffer[tls_off] };
    }

    ulong callbacks_va = tls_view.address_of_callbacks();
    if (callbacks_va == 0) return;
    uint callbacks_rva = (uint)(callbacks_va - ibase);
    usz  cb_off        = self.rva_to_offset(callbacks_rva)!;
    while (true)
    {
        ulong fn_va;
        if (is64)
        {
            if (cb_off + 8 > self.buffer.len) return common::TRUNCATED_DATA~;
            fn_va   = *(ulong*)&self.buffer[cb_off];
            cb_off += 8;
        }
        else
        {
            if (cb_off + 4 > self.buffer.len) return common::TRUNCATED_DATA~;
            fn_va   = (ulong)(*(uint*)&self.buffer[cb_off]);
            cb_off += 4;
        }
        if (fn_va == 0) break;
        if (!cb(&tls_view)) break;
    }
}

fn void? OpeViewPe.foreach_exception_x64(&self, OpeX64ExceptionCallback cb)
{
    if (self.nt.file_header().machine() != OpeMachineType.AMD64) return common::UNABLE_TO_RESOLVE~;
    OpeRawDataDirectory dir   = self.get_data_directory_as_data(OpeDataDirectoryIndex.EXCEPTION)!;
    usz                 off   = self.rva_to_offset(dir.virtual_address)!;
    uint                count = dir.size / (uint)OpeRawRuntimeFunction::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + OpeRawRuntimeFunction::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawRuntimeFunction* r  = (OpeRawRuntimeFunction*)&self.buffer[off];
        OpeViewUnwindInfo      ui = ope::exceptions::parse_unwind_info(self.buffer, self.section_headers, r.unwind_info_address)!;
        OpeX64Exception ex = { .raw = r, .unwind_info = ui };
        if (!cb(&ex)) break;
        off += OpeRawRuntimeFunction::size;
    }
}

fn void? OpeViewPe.foreach_exception_arm(&self, OpeArmExceptionCallback cb)
{
    OpeMachineType machine = self.nt.file_header().machine();
    if (machine != OpeMachineType.ARMNT && machine != OpeMachineType.ARM64) return common::UNABLE_TO_RESOLVE~;
    OpeRawDataDirectory dir   = self.get_data_directory_as_data(OpeDataDirectoryIndex.EXCEPTION)!;
    usz                 off   = self.rva_to_offset(dir.virtual_address)!;
    uint                count = dir.size / (uint)OpeRawArmRuntimeFunction::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + OpeRawArmRuntimeFunction::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawArmRuntimeFunction* r  = (OpeRawArmRuntimeFunction*)&self.buffer[off];
        bool                      ip = (r.packed_unwind & 1) != 0;
        OpeArmException ex = { .raw = r, .is_packed = ip };
        if (!cb(&ex)) break;
        off += OpeRawArmRuntimeFunction::size;
    }
}

fn void? OpeViewPe.foreach_delayed_import_descriptor(&self, OpeDelayedImportDescriptorCallback cb)
{
    OpeRawDataDirectory dir = self.get_data_directory_as_data(OpeDataDirectoryIndex.DELAY_IMPORT)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    while (true)
    {
        if (off + OpeRawDelayImportDescriptor::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawDelayImportDescriptor* r = (OpeRawDelayImportDescriptor*)&self.buffer[off];
        if (r.dll_name_rva == 0) break;
        ZString dll = (ZString)&self.buffer[self.rva_to_offset(r.dll_name_rva)!];
        OpeViewDelayedImportDescriptor desc = { .raw = r, .dll = dll };
        if (!cb(&desc)) break;
        off += OpeRawDelayImportDescriptor::size;
    }
}

fn void? OpeViewPe.foreach_delayed_import(&self, OpeDelayedImportCallback cb)
{
    OpeRawDataDirectory dir      = self.get_data_directory_as_data(OpeDataDirectoryIndex.DELAY_IMPORT)!;
    usz                 desc_off = self.rva_to_offset(dir.virtual_address)!;
    bool                is64     = self.nt.is64;
    while (true)
    {
        if (desc_off + OpeRawDelayImportDescriptor::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawDelayImportDescriptor* r = (OpeRawDelayImportDescriptor*)&self.buffer[desc_off];
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
            OpeViewDelayedImport imp;
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
                if (name_off + 2 > self.buffer.len) return common::TRUNCATED_DATA~;
                imp.hint       = *(ushort*)&self.buffer[name_off];
                imp.name       = (ZString)&self.buffer[name_off + 2];
                imp.ordinal    = 0;
                imp.is_ordinal = false;
            }
            if (!cb(&imp)) return;
            entry_idx++;
        }
        desc_off += OpeRawDelayImportDescriptor::size;
    }
}

fn void? OpeViewPe.foreach_bound_import(&self, OpeBoundImportCallback cb)
{
    OpeRawDataDirectory dir      = self.get_data_directory_as_data(OpeDataDirectoryIndex.BOUND_IMPORT)!;
    usz                 base_off = (usz)dir.virtual_address;
    usz                 off      = base_off;
    while (true)
    {
        if (off + OpeRawBoundImportDescriptor::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawBoundImportDescriptor* r = (OpeRawBoundImportDescriptor*)&self.buffer[off];
        if (r.time_date_stamp == 0 && r.offset_module_name == 0) break;
        usz name_off = base_off + (usz)r.offset_module_name;
        if (name_off >= self.buffer.len) return common::TRUNCATED_DATA~;
        OpeViewBoundImportDescriptor desc = { .raw = r, .dll = (ZString)&self.buffer[name_off] };
        if (!cb(&desc)) break;
        off += OpeRawBoundImportDescriptor::size;
    }
}

fn void? OpeViewPe.foreach_debug_entry(&self, OpeDebugCallback cb)
{
    OpeRawDataDirectory dir   = self.get_data_directory_as_data(OpeDataDirectoryIndex.DEBUG)!;
    usz                 off   = self.rva_to_offset(dir.virtual_address)!;
    uint                count = dir.size / (uint)OpeRawDebugDirectory::size;
    for (uint i = 0; i < count; i++)
    {
        if (off + OpeRawDebugDirectory::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawDebugDirectory* r = (OpeRawDebugDirectory*)&self.buffer[off];
        char[] data;
        if (r.size_of_data > 0 && r.pointer_to_raw_data > 0)
        {
            usz d_off = (usz)r.pointer_to_raw_data;
            if (d_off + r.size_of_data <= self.buffer.len)
            {
                data = self.buffer[d_off..d_off + r.size_of_data - 1];
            }
        }
        OpeViewDebug entry = { .raw = r, .data = data };
        if (!cb(&entry)) break;
        off += OpeRawDebugDirectory::size;
    }
}

fn void? OpeViewPe.foreach_relocation(&self, OpeRelocationCallback cb)
{
    OpeRawDataDirectory dir = self.get_data_directory_as_data(OpeDataDirectoryIndex.BASERELOC)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    usz end = off + (usz)dir.size;
    while (off < end)
    {
        if (off + OpeRawBaseRelocation::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawBaseRelocation* block = (OpeRawBaseRelocation*)&self.buffer[off];
        if (block.size_of_block < OpeRawBaseRelocation::size) return common::TRUNCATED_DATA~;
        uint page_rva  = block.virtual_address;
        uint entries   = (block.size_of_block - (uint)OpeRawBaseRelocation::size) / 2;
        usz  entry_off = off + OpeRawBaseRelocation::size;
        for (uint i = 0; i < entries; i++)
        {
            if (entry_off + 2 > self.buffer.len) return common::TRUNCATED_DATA~;
            OpeRawBaseRelocationEntry e = *(OpeRawBaseRelocationEntry*)&self.buffer[entry_off];
            OpeViewRelocation rel = { .rva = page_rva + e.offset, .type = e.type, .offset = e.offset };
            if (!cb(&rel)) return;
            entry_off += 2;
        }
        off += (usz)block.size_of_block;
    }
}

fn bool? OpeViewPe.walk_resource_dir(
    &self, usz res_base, usz dir_off, uint depth,
    uint type_id, uint name_id, OpeResourceCallback cb)
{
    if (dir_off + OpeRawResourceDirectory::size > self.buffer.len) return common::TRUNCATED_DATA~;
    OpeRawResourceDirectory* dir = (OpeRawResourceDirectory*)&self.buffer[dir_off];
    uint total     = (uint)dir.number_of_named_entries + (uint)dir.number_of_id_entries;
    usz  entry_off = dir_off + OpeRawResourceDirectory::size;
    for (uint i = 0; i < total; i++)
    {
        if (entry_off + OpeRawResourceDirectoryEntry::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawResourceDirectoryEntry* e = (OpeRawResourceDirectoryEntry*)&self.buffer[entry_off];
        entry_off += OpeRawResourceDirectoryEntry::size;
        uint id            = e.name_or_id & 0x7FFFFFFF;
        uint child_off_raw = e.offset_to_data_or_directory;
        bool is_dir        = (child_off_raw >> 31) != 0;
        usz  child_off     = res_base + (usz)(child_off_raw & 0x7FFFFFFF);
        if (is_dir)
        {
            uint next_type = depth == 0 ? id : type_id;
            uint next_name = depth == 1 ? id : name_id;
            bool cont = self.walk_resource_dir(res_base, child_off, depth + 1, next_type, next_name, cb)!;
            if (!cont) return false;
        }
        else
        {
            if (child_off + OpeRawResourceDataEntry::size > self.buffer.len) return common::TRUNCATED_DATA~;
            OpeRawResourceDataEntry* de = (OpeRawResourceDataEntry*)&self.buffer[child_off];
            usz data_off = self.rva_to_offset(de.offset_to_data)!;
            char[] data;
            if (data_off + de.size <= self.buffer.len)
            {
                data = self.buffer[data_off..data_off + de.size - 1];
            }
            OpeViewResource leaf = {
                .raw         = de,
                .type_id     = type_id,
                .name_id     = name_id,
                .language_id = id,
                .data        = data,
            };
            if (!cb(&leaf)) return false;
        }
    }
    return true;
}

fn void? OpeViewPe.foreach_resource(&self, OpeResourceCallback cb)
{
    OpeRawDataDirectory dir      = self.get_data_directory_as_data(OpeDataDirectoryIndex.RESOURCE)!;
    usz                 res_base = self.rva_to_offset(dir.virtual_address)!;
    self.walk_resource_dir(res_base, res_base, 0, 0, 0, cb)!;
}

fn void? OpeViewPe.foreach_certificate(&self, OpeCertificateCallback cb)
{
    OpeRawDataDirectory dir = self.get_data_directory_as_data(OpeDataDirectoryIndex.CERTIFICATE)!;
    usz off = (usz)dir.virtual_address;
    usz end = off + (usz)dir.size;
    while (off < end)
    {
        if (off + OpeRawWinCertificate::size > self.buffer.len) return common::TRUNCATED_DATA~;
        OpeRawWinCertificate* r = (OpeRawWinCertificate*)&self.buffer[off];
        if (r.length < OpeRawWinCertificate::size) return common::TRUNCATED_DATA~;
        usz data_len = (usz)r.length - OpeRawWinCertificate::size;
        char[] data;
        if (data_len > 0 && off + OpeRawWinCertificate::size + data_len <= self.buffer.len)
        {
            data = self.buffer[off + OpeRawWinCertificate::size..off + OpeRawWinCertificate::size + data_len - 1];
        }
        OpeViewCertificate cert = { .raw = r, .data = data };
        if (!cb(&cert)) break;
        usz aligned = ((usz)r.length + 7) & ~(usz)7u;
        off += aligned;
    }
}

fn OpeViewCor20Header? OpeViewPe.cor20_header(&self)
{
    OpeRawDataDirectory dir = self.get_data_directory_as_data(OpeDataDirectoryIndex.CLR_RUNTIME)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    if (off + OpeRawCor20Header::size > self.buffer.len) return common::TRUNCATED_DATA~;
    return { .raw = (OpeRawCor20Header*)&self.buffer[off] };
}
