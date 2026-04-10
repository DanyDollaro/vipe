module ope::parser;

//
// Faults
//

faultdef
    PARSER_MISMATCHING_DOS_SIGNATURE,
    PARSER_MISMATCHING_PE_SIGNATURE,
    PARSER_MISSING_DATA_DIRECTORY,
    PARSER_MALFORMED_STRUCTURE,
    PARSER_FIELD_NOT_AVAILABLE,
    PARSER_EXPORTED_BY_ORDINAL,
    PARSER_OUT_OF_BOUNDS;

//
// Constants
//

const ushort DOS_MAGIC      = 0x5A4D;
const uint   PE_SIGNATURE   = 0x00004550;
const ushort PE32_MAGIC     = 0x010B;
const ushort PE32PLUS_MAGIC = 0x020B;

const uint DATA_DIR_EXPORT       = 0;
const uint DATA_DIR_IMPORT       = 1;
const uint DATA_DIR_RESOURCE     = 2;
const uint DATA_DIR_EXCEPTION    = 3;
const uint DATA_DIR_CERTIFICATE  = 4;
const uint DATA_DIR_BASERELOC    = 5;
const uint DATA_DIR_DEBUG        = 6;
const uint DATA_DIR_TLS          = 9;
const uint DATA_DIR_LOAD_CONFIG  = 10;
const uint DATA_DIR_BOUND_IMPORT = 11;
const uint DATA_DIR_IAT          = 12;
const uint DATA_DIR_DELAY_IMPORT = 13;
const uint DATA_DIR_CLR_RUNTIME  = 14;

const uint NUM_DATA_DIRECTORIES = 16;
const uint SECTION_NAME_SIZE    = 8;

//
// Macro: unified getter/setter for header fields
//

<*
 Set or exchange a field value.
 If `val` is provided the old value is returned and the field is updated.
 If `val` is omitted the current value is returned unchanged.
*>
macro ope_set_or_exchange(self, val = ...) @private
{
    $if $defined(val):
        var old = self;
        self = val;
        return old;
    $else
        return self;
    $endif
}

//
// Raw PE structures (packed, zero-copy views into the buffer)
//

struct OpeRawDosHeader @packed
{
    ushort    e_magic;
    ushort    e_cblp;
    ushort    e_cp;
    ushort    e_crsym;
    ushort    e_cparhdr;
    ushort    e_minalloc;
    ushort    e_maxalloc;
    ushort    e_ss;
    ushort    e_sp;
    ushort    e_csum;
    ushort    e_ip;
    ushort    e_cs;
    ushort    e_lfarlc;
    ushort    e_ovno;
    ushort[4] e_res;
    ushort    e_oemid;
    ushort    e_oeminfo;
    ushort[10] e_res2;
    int       e_lfanew;
}

struct OpeRawFileHeader @packed
{
    ushort machine;
    ushort number_of_sections;
    uint   time_date_stamp;
    uint   pointer_to_symbol_table;
    uint   number_of_symbols;
    ushort size_of_optional_header;
    ushort characteristics;
}

struct OpeRawDataDirectory @packed
{
    uint virtual_address;
    uint size;
}

struct OpeRawOptionalHeader32 @packed
{
    ushort magic;
    char   major_linker_version;
    char   minor_linker_version;
    uint   size_of_code;
    uint   size_of_initialized_data;
    uint   size_of_uninitialized_data;
    uint   address_of_entry_point;
    uint   base_of_code;
    uint   base_of_data;
    uint   image_base;
    uint   section_alignment;
    uint   file_alignment;
    ushort major_operating_system_version;
    ushort minor_operating_system_version;
    ushort major_image_version;
    ushort minor_image_version;
    ushort major_subsystem_version;
    ushort minor_subsystem_version;
    uint   win32_version_value;
    uint   size_of_image;
    uint   size_of_headers;
    uint   check_sum;
    ushort subsystem;
    ushort dll_characteristics;
    uint   size_of_stack_reserve;
    uint   size_of_stack_commit;
    uint   size_of_heap_reserve;
    uint   size_of_heap_commit;
    uint   loader_flags;
    uint   number_of_rva_and_sizes;
    OpeRawDataDirectory[NUM_DATA_DIRECTORIES] data_directory;
}

struct OpeRawOptionalHeader64 @packed
{
    ushort magic;
    char   major_linker_version;
    char   minor_linker_version;
    uint   size_of_code;
    uint   size_of_initialized_data;
    uint   size_of_uninitialized_data;
    uint   address_of_entry_point;
    uint   base_of_code;
    ulong  image_base;
    uint   section_alignment;
    uint   file_alignment;
    ushort major_operating_system_version;
    ushort minor_operating_system_version;
    ushort major_image_version;
    ushort minor_image_version;
    ushort major_subsystem_version;
    ushort minor_subsystem_version;
    uint   win32_version_value;
    uint   size_of_image;
    uint   size_of_headers;
    uint   check_sum;
    ushort subsystem;
    ushort dll_characteristics;
    ulong  size_of_stack_reserve;
    ulong  size_of_stack_commit;
    ulong  size_of_heap_reserve;
    ulong  size_of_heap_commit;
    uint   loader_flags;
    uint   number_of_rva_and_sizes;
    OpeRawDataDirectory[NUM_DATA_DIRECTORIES] data_directory;
}

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

struct OpeRawSectionHeader @packed
{
    char[SECTION_NAME_SIZE] name;
    uint   virtual_size;
    uint   virtual_address;
    uint   size_of_raw_data;
    uint   pointer_to_raw_data;
    uint   pointer_to_relocations;
    uint   pointer_to_linenumbers;
    ushort number_of_relocations;
    ushort number_of_linenumbers;
    uint   characteristics;
}

struct OpeRawImportDescriptor @packed
{
    uint original_first_thunk;
    uint time_date_stamp;
    uint forwarder_chain;
    uint name_rva;
    uint first_thunk;
}

struct OpeRawExportDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   name_rva;
    uint   base;
    uint   number_of_functions;
    uint   number_of_names;
    uint   address_of_functions;
    uint   address_of_names;
    uint   address_of_name_ordinals;
}

struct OpeRawTlsDirectory32 @packed
{
    uint raw_data_start_va;
    uint raw_data_end_va;
    uint address_of_index;
    uint address_of_callbacks;
    uint size_of_zero_fill;
    uint characteristics;
}

struct OpeRawTlsDirectory64 @packed
{
    ulong raw_data_start_va;
    ulong raw_data_end_va;
    ulong address_of_index;
    ulong address_of_callbacks;
    uint  size_of_zero_fill;
    uint  characteristics;
}

struct OpeRawRuntimeFunction @packed
{
    uint begin_address;
    uint end_address;
    uint unwind_info_address;
}

// ARM/ARM64 packed unwind: bit 0 of the second word discriminates
// between an .xdata RVA (bit 0 = 0) and inline packed unwind (bit 0 = 1)
struct OpeRawArmRuntimeFunction @packed
{
    uint begin_address;
    union {
        uint unwind_data;
        uint packed_unwind;
    }
}

struct OpeRawDebugDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   type;
    uint   size_of_data;
    uint   address_of_raw_data;
    uint   pointer_to_raw_data;
}

// CodeView NB10 record (PDB 2.0)
struct OpeRawCvInfoPdb20 @packed
{
    uint cv_signature;  // 'NB10'
    uint offset;
    uint signature;
    uint age;
    char pdb_file_name; // first byte; use (ZString)&pdb_file_name
}

// CodeView RSDS record (PDB 7.0)
struct OpeRawCvInfoPdb70 @packed
{
    uint     cv_signature;  // 'RSDS'
    char[16] signature;     // GUID bytes, little-endian
    uint     age;
    char     pdb_file_name; // first byte; use (ZString)&pdb_file_name
}

struct OpeRawBaseRelocation @packed
{
    uint virtual_address;
    uint size_of_block;
}

// Each entry in a base relocation block: upper 4 bits = type, lower 12 = page offset
bitstruct OpeRawBaseRelocationEntry : ushort
{
    ushort offset : 0..11;
    ushort type   : 12..15;
}

struct OpeRawDelayImportDescriptor @packed
{
    uint attributes;
    uint dll_name_rva;
    uint module_handle_rva;
    uint iat_rva;
    uint ilt_rva;
    uint bound_iat_rva;
    uint unload_iat_rva;
    uint timestamp;
}

struct OpeRawBoundImportDescriptor @packed
{
    uint   time_date_stamp;
    ushort offset_module_name;
    ushort number_of_module_forwarder_refs;
}

struct OpeRawCor20Header @packed
{
    uint   cb;
    ushort major_runtime_version;
    ushort minor_runtime_version;
    OpeRawDataDirectory meta_data;
    uint   flags;
    uint   entry_point_token_or_rva;
    OpeRawDataDirectory resources;
    OpeRawDataDirectory strong_name_signature;
    OpeRawDataDirectory code_manager_table;
    OpeRawDataDirectory vtable_fixups;
    OpeRawDataDirectory export_address_table_jumps;
    OpeRawDataDirectory managed_native_header;
}

struct OpeRawResourceDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    ushort number_of_named_entries;
    ushort number_of_id_entries;
}

// Upper bit of name_or_id: 1 = named entry (offset to OpeRawResourceDirString),
//                           0 = integer ID
// Upper bit of offset_to_data_or_directory: 1 = subdirectory, 0 = data entry
struct OpeRawResourceDirectoryEntry @packed
{
    uint name_or_id;
    uint offset_to_data_or_directory;
}

struct OpeRawResourceDataEntry @packed
{
    uint offset_to_data;
    uint size;
    uint code_page;
    uint reserved;
}

// Inline UTF-16LE string used for named resource directory entries
struct OpeRawResourceDirString @packed
{
    ushort length;      // character count, not byte count
    ushort name_string; // first element of the inline UTF-16LE array
}

// Thunk data: a single IAT/ILT slot (union; ordinal bit = bit 31 / bit 63)
union OpeRawThunkData32 @packed
{
    uint forwarder_string;
    uint function_ptr;
    uint ordinal;
    uint address_of_data;
}

union OpeRawThunkData64 @packed
{
    ulong forwarder_string;
    ulong function_ptr;
    ulong ordinal;
    ulong address_of_data;
}

// Hint + name record pointed to by a named thunk entry
struct OpeRawImportByName @packed
{
    ushort hint;
    char   name; // use (ZString)&name
}

// x86-only SEH registration record (stored on the stack, fs:[0] chain)
struct OpeRawExceptionRegistration32 @packed
{
    uint next;    // pointer to next record in chain
    uint handler; // pointer to __except_handler
}

// MSVC x86 SEH scope table entry (/EHa, 32-bit only)
struct OpeRawScopeTableEntry32 @packed
{
    uint begin_address;
    uint end_address;
    uint handler_address;
    uint jump_target;
}

//
// Load configuration directory (pointer-sized fields differ between 32/64)
//

struct OpeRawLoadConfig32 @packed
{
    uint   size;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   global_flags_clear;
    uint   global_flags_set;
    uint   critical_section_default_timeout;
    uint   de_commit_free_block_threshold;
    uint   de_commit_total_free_threshold;
    uint   lock_prefix_table;
    uint   maximum_allocation_size;
    uint   virtual_memory_threshold;
    uint   process_affinity_mask;
    uint   process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    uint   edit_list;
    uint   security_cookie;
    uint   se_handler_table;
    uint   se_handler_count;
    uint   guard_cf_check_function_pointer;
    uint   guard_cf_dispatch_function_pointer;
    uint   guard_cf_function_table;
    uint   guard_cf_function_count;
    uint   guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint   ci_catalog_offset;
    uint   ci_reserved;
    uint   guard_address_taken_iat_entry_table;
    uint   guard_address_taken_iat_entry_count;
    uint   guard_long_jump_target_table;
    uint   guard_long_jump_target_count;
    uint   dynamic_value_reloc_table;
    uint   chpe_metadata_pointer;
    uint   guard_rf_failure_routine;
    uint   guard_rf_failure_routine_function_pointer;
    uint   dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    uint   guard_rf_verify_stack_pointer_function_pointer;
    uint   hot_patch_table_offset;
    uint   reserved3;
    uint   enclave_configuration_pointer;
    uint   volatile_metadata_pointer;
    uint   guard_eh_continuation_table;
    uint   guard_eh_continuation_count;
    uint   guard_xfg_check_function_pointer;
    uint   guard_xfg_dispatch_function_pointer;
    uint   guard_xfg_table_dispatch_function_pointer;
    uint   cast_guard_os_determined_failure_mode;
    uint   guard_memcpy_function_pointer;
}

struct OpeRawLoadConfig64 @packed
{
    uint   size;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   global_flags_clear;
    uint   global_flags_set;
    uint   critical_section_default_timeout;
    ulong  de_commit_free_block_threshold;
    ulong  de_commit_total_free_threshold;
    ulong  lock_prefix_table;
    ulong  maximum_allocation_size;
    ulong  virtual_memory_threshold;
    ulong  process_affinity_mask;
    uint   process_heap_flags;
    ushort csd_version;
    ushort dependent_load_flags;
    ulong  edit_list;
    ulong  security_cookie;
    ulong  se_handler_table;
    ulong  se_handler_count;
    ulong  guard_cf_check_function_pointer;
    ulong  guard_cf_dispatch_function_pointer;
    ulong  guard_cf_function_table;
    ulong  guard_cf_function_count;
    uint   guard_flags;
    ushort ci_flags;
    ushort ci_catalog;
    uint   ci_catalog_offset;
    uint   ci_reserved;
    ulong  guard_address_taken_iat_entry_table;
    ulong  guard_address_taken_iat_entry_count;
    ulong  guard_long_jump_target_table;
    ulong  guard_long_jump_target_count;
    ulong  dynamic_value_reloc_table;
    ulong  chpe_metadata_pointer;
    ulong  guard_rf_failure_routine;
    ulong  guard_rf_failure_routine_function_pointer;
    uint   dynamic_value_reloc_table_offset;
    ushort dynamic_value_reloc_table_section;
    ushort reserved2;
    ulong  guard_rf_verify_stack_pointer_function_pointer;
    uint   hot_patch_table_offset;
    uint   reserved3;
    ulong  enclave_configuration_pointer;
    ulong  volatile_metadata_pointer;
    ulong  guard_eh_continuation_table;
    ulong  guard_eh_continuation_count;
    ulong  guard_xfg_check_function_pointer;
    ulong  guard_xfg_dispatch_function_pointer;
    ulong  guard_xfg_table_dispatch_function_pointer;
    ulong  cast_guard_os_determined_failure_mode;
    ulong  guard_memcpy_function_pointer;
}

//
// Synthetic structures
//

struct OpeDataDirectory
{
    uint virtual_address;
    uint size;
}

struct OpeSection
{
    char[] name;
    uint   virtual_size;
    uint   virtual_address;
    uint   size_of_raw_data;
    uint   pointer_to_raw_data;
    uint   pointer_to_relocations;
    uint   pointer_to_linenumbers;
    ushort number_of_relocations;
    ushort number_of_linenumbers;
    uint   characteristics;
}

struct OpeImportDescriptor
{
    ZString dll;
    uint    original_first_thunk;
    uint    time_date_stamp;
    uint    forwarder_chain;
    uint    name_rva;
    uint    first_thunk;
}

struct OpeImport
{
    ZString name;
    ushort  hint;
    ushort  ordinal;
    bool    is_ordinal;
    uint    iat_entry_rva;
}

// name.len == 0 means the export was by ordinal only
struct OpeExportEntry
{
    ZString name;
    ushort  ordinal;
    bool    is_forwarder;
    union {
        uint    rva;
        ZString forwarder;
    }
}

struct OpeDelayedImportDescriptor
{
    ZString dll;
    uint    attributes;
    uint    module_handle_rva;
    uint    iat_rva;
    uint    ilt_rva;
    uint    bound_iat_rva;
    uint    unload_iat_rva;
    uint    timestamp;
}

struct OpeDelayedImport
{
    ZString name;
    ushort  hint;
    ushort  ordinal;
    bool    is_ordinal;
    uint    iat_entry_rva;
}

struct OpeBoundImportDescriptor
{
    ZString dll;
    uint    time_date_stamp;
    ushort  number_of_module_forwarder_refs;
}

struct OpeTlsCallback
{
    ulong address;
}

struct OpeException
{
    uint begin_address;
    uint end_address;
    uint unwind_info_rva;
}

struct OpeDebugEntry
{
    uint   type;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   rva;
    uint   file_offset;
    uint   size;
    char[] data;
}

struct OpeCertificate
{
    uint   length;
    ushort revision;
    ushort certificate_type;
    char[] data;
}

struct OpeRelocation
{
    uint   rva;
    ushort type;
    ushort offset;
}

struct OpeResourceEntry
{
    uint   rva;
    uint   size;
    uint   code_page;
    uint   reserved;
    uint   type_id;
    uint   name_id;
    uint   language_id;
    char[] data;
}

struct OpeCor20Header
{
    uint             cb;
    ushort           major_runtime_version;
    ushort           minor_runtime_version;
    OpeDataDirectory meta_data;
    uint             flags;
    uint             entry_point_token_or_rva;
    OpeDataDirectory resources;
    OpeDataDirectory strong_name_signature;
    OpeDataDirectory code_manager_table;
    OpeDataDirectory vtable_fixups;
    OpeDataDirectory export_address_table_jumps;
    OpeDataDirectory managed_native_header;
}

//
// Callback aliases
//

alias OpeImportDescriptorCallback        = fn bool(OpeImportDescriptor*);
alias OpeImportCallback                  = fn bool(OpeImport*);
alias OpeExportCallback                  = fn bool(OpeExportEntry*);
alias OpeDelayedImportDescriptorCallback = fn bool(OpeDelayedImportDescriptor*);
alias OpeDelayedImportCallback           = fn bool(OpeDelayedImport*);
alias OpeBoundImportCallback             = fn bool(OpeBoundImportDescriptor*);
alias OpeTlsCallbackCb                   = fn bool(OpeTlsCallback*);
alias OpeExceptionCallback               = fn bool(OpeException*);
alias OpeDebugEntryCallback              = fn bool(OpeDebugEntry*);
alias OpeRelocationCallback              = fn bool(OpeRelocation*);
alias OpeResourceCallback                = fn bool(OpeResourceEntry*);
alias OpeCertificateCallback             = fn bool(OpeCertificate*);

//
// Header type aliases
// typedef creates a distinct type; explicit cast required to convert back to raw
//

typedef OpeDosHeader  = OpeRawDosHeader;
typedef OpeFileHeader = OpeRawFileHeader;

//
// Wrapper: optional header (PE32 / PE32+ transparent)
// Kept as a struct because it holds two nullable pointers, not one raw pointer
//

struct OpeOptionalHeader
{
    OpeRawOptionalHeader32* raw32;
    OpeRawOptionalHeader64* raw64;
}

<*
 @require self != null
 @ensure self.raw32 != null || self.raw64 != null
*>
fn bool OpeOptionalHeader.is_pe32plus(&self) => self.raw64 != null;

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ushort OpeOptionalHeader.magic(&self)
    => self.raw64 != null ? self.raw64.magic : self.raw32.magic;

<*
 Returns the image base, widened to ulong for both PE32 and PE32+.
 @require self != null && (self.raw32 != null || self.raw64 != null)
*>
macro ulong OpeOptionalHeader.image_base(&self, ulong image_base = ...)
{
    $if $defined(image_base):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.image_base;
            self.raw64.image_base = image_base;
            return old;
        }
        ulong old = (ulong)self.raw32.image_base;
        self.raw32.image_base = (uint)image_base;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.image_base
            : (ulong)self.raw32.image_base;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.address_of_entry_point(&self, uint address_of_entry_point = ...)
{
    $if $defined(address_of_entry_point):
        if (self.raw64 != null)
        {
            uint old = self.raw64.address_of_entry_point;
            self.raw64.address_of_entry_point = address_of_entry_point;
            return old;
        }
        uint old = self.raw32.address_of_entry_point;
        self.raw32.address_of_entry_point = address_of_entry_point;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.address_of_entry_point
            : self.raw32.address_of_entry_point;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.base_of_code(&self, uint base_of_code = ...)
{
    $if $defined(base_of_code):
        if (self.raw64 != null)
        {
            uint old = self.raw64.base_of_code;
            self.raw64.base_of_code = base_of_code;
            return old;
        }
        uint old = self.raw32.base_of_code;
        self.raw32.base_of_code = base_of_code;
        return old;
    $else
        return self.raw64 != null ? self.raw64.base_of_code : self.raw32.base_of_code;
    $endif
}

<*
 Only available in PE32 images. Returns PARSER_FIELD_NOT_AVAILABLE for PE32+.
 @require self != null && (self.raw32 != null || self.raw64 != null)
 @return? PARSER_FIELD_NOT_AVAILABLE
*>
macro uint? OpeOptionalHeader.base_of_data(&self, uint base_of_data = ...)
{
    if (self.raw64 != null) return PARSER_FIELD_NOT_AVAILABLE~;
    $if $defined(base_of_data):
        uint old = self.raw32.base_of_data;
        self.raw32.base_of_data = base_of_data;
        return old;
    $else
        return self.raw32.base_of_data;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.size_of_image(&self, uint size_of_image = ...)
{
    $if $defined(size_of_image):
        if (self.raw64 != null)
        {
            uint old = self.raw64.size_of_image;
            self.raw64.size_of_image = size_of_image;
            return old;
        }
        uint old = self.raw32.size_of_image;
        self.raw32.size_of_image = size_of_image;
        return old;
    $else
        return self.raw64 != null ? self.raw64.size_of_image : self.raw32.size_of_image;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.size_of_headers(&self, uint size_of_headers = ...)
{
    $if $defined(size_of_headers):
        if (self.raw64 != null)
        {
            uint old = self.raw64.size_of_headers;
            self.raw64.size_of_headers = size_of_headers;
            return old;
        }
        uint old = self.raw32.size_of_headers;
        self.raw32.size_of_headers = size_of_headers;
        return old;
    $else
        return self.raw64 != null ? self.raw64.size_of_headers : self.raw32.size_of_headers;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.check_sum(&self, uint check_sum = ...)
{
    $if $defined(check_sum):
        if (self.raw64 != null)
        {
            uint old = self.raw64.check_sum;
            self.raw64.check_sum = check_sum;
            return old;
        }
        uint old = self.raw32.check_sum;
        self.raw32.check_sum = check_sum;
        return old;
    $else
        return self.raw64 != null ? self.raw64.check_sum : self.raw32.check_sum;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ushort OpeOptionalHeader.subsystem(&self, ushort subsystem = ...)
{
    $if $defined(subsystem):
        if (self.raw64 != null)
        {
            ushort old = self.raw64.subsystem;
            self.raw64.subsystem = subsystem;
            return old;
        }
        ushort old = self.raw32.subsystem;
        self.raw32.subsystem = subsystem;
        return old;
    $else
        return self.raw64 != null ? self.raw64.subsystem : self.raw32.subsystem;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ushort OpeOptionalHeader.dll_characteristics(&self, ushort dll_characteristics = ...)
{
    $if $defined(dll_characteristics):
        if (self.raw64 != null)
        {
            ushort old = self.raw64.dll_characteristics;
            self.raw64.dll_characteristics = dll_characteristics;
            return old;
        }
        ushort old = self.raw32.dll_characteristics;
        self.raw32.dll_characteristics = dll_characteristics;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.dll_characteristics
            : self.raw32.dll_characteristics;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.section_alignment(&self, uint section_alignment = ...)
{
    $if $defined(section_alignment):
        if (self.raw64 != null)
        {
            uint old = self.raw64.section_alignment;
            self.raw64.section_alignment = section_alignment;
            return old;
        }
        uint old = self.raw32.section_alignment;
        self.raw32.section_alignment = section_alignment;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.section_alignment
            : self.raw32.section_alignment;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.file_alignment(&self, uint file_alignment = ...)
{
    $if $defined(file_alignment):
        if (self.raw64 != null)
        {
            uint old = self.raw64.file_alignment;
            self.raw64.file_alignment = file_alignment;
            return old;
        }
        uint old = self.raw32.file_alignment;
        self.raw32.file_alignment = file_alignment;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.file_alignment
            : self.raw32.file_alignment;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeOptionalHeader.number_of_rva_and_sizes(&self, uint number_of_rva_and_sizes = ...)
{
    $if $defined(number_of_rva_and_sizes):
        if (self.raw64 != null)
        {
            uint old = self.raw64.number_of_rva_and_sizes;
            self.raw64.number_of_rva_and_sizes = number_of_rva_and_sizes;
            return old;
        }
        uint old = self.raw32.number_of_rva_and_sizes;
        self.raw32.number_of_rva_and_sizes = number_of_rva_and_sizes;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.number_of_rva_and_sizes
            : self.raw32.number_of_rva_and_sizes;
    $endif
}

<*
 Widens stack/heap fields to ulong for both PE32 and PE32+.
 @require self != null && (self.raw32 != null || self.raw64 != null)
*>
macro ulong OpeOptionalHeader.size_of_stack_reserve(&self, ulong size_of_stack_reserve = ...)
{
    $if $defined(size_of_stack_reserve):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.size_of_stack_reserve;
            self.raw64.size_of_stack_reserve = size_of_stack_reserve;
            return old;
        }
        ulong old = (ulong)self.raw32.size_of_stack_reserve;
        self.raw32.size_of_stack_reserve = (uint)size_of_stack_reserve;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.size_of_stack_reserve
            : (ulong)self.raw32.size_of_stack_reserve;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeOptionalHeader.size_of_stack_commit(&self, ulong size_of_stack_commit = ...)
{
    $if $defined(size_of_stack_commit):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.size_of_stack_commit;
            self.raw64.size_of_stack_commit = size_of_stack_commit;
            return old;
        }
        ulong old = (ulong)self.raw32.size_of_stack_commit;
        self.raw32.size_of_stack_commit = (uint)size_of_stack_commit;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.size_of_stack_commit
            : (ulong)self.raw32.size_of_stack_commit;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeOptionalHeader.size_of_heap_reserve(&self, ulong size_of_heap_reserve = ...)
{
    $if $defined(size_of_heap_reserve):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.size_of_heap_reserve;
            self.raw64.size_of_heap_reserve = size_of_heap_reserve;
            return old;
        }
        ulong old = (ulong)self.raw32.size_of_heap_reserve;
        self.raw32.size_of_heap_reserve = (uint)size_of_heap_reserve;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.size_of_heap_reserve
            : (ulong)self.raw32.size_of_heap_reserve;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeOptionalHeader.size_of_heap_commit(&self, ulong size_of_heap_commit = ...)
{
    $if $defined(size_of_heap_commit):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.size_of_heap_commit;
            self.raw64.size_of_heap_commit = size_of_heap_commit;
            return old;
        }
        ulong old = (ulong)self.raw32.size_of_heap_commit;
        self.raw32.size_of_heap_commit = (uint)size_of_heap_commit;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.size_of_heap_commit
            : (ulong)self.raw32.size_of_heap_commit;
    $endif
}

<*
 @require self != null && (self.raw32 != null || self.raw64 != null)
 @require idx < NUM_DATA_DIRECTORIES
*>
fn OpeDataDirectory OpeOptionalHeader.data_directory(&self, uint idx)
{
    OpeRawDataDirectory raw = self.raw64 != null
        ? self.raw64.data_directory[idx]
        : self.raw32.data_directory[idx];
    return { .virtual_address = raw.virtual_address, .size = raw.size };
}

//
// Wrapper: NT headers
// Kept as a struct because it composes the two sub-wrappers
//

struct OpeNtHeaders
{
    uint              signature;
    OpeFileHeader*    fh;
    OpeOptionalHeader oh;
}

<* @require self != null *>
fn OpeFileHeader* OpeNtHeaders.file_header(&self) => self.fh;

<* @require self != null *>
fn OpeOptionalHeader* OpeNtHeaders.optional_header(&self) => &self.oh;

//
// Wrapper: load configuration directory (transparent 32/64)
//

struct OpeLoadConfigHeader
{
    OpeRawLoadConfig32* raw32;
    OpeRawLoadConfig64* raw64;
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
fn bool OpeLoadConfigHeader.is_pe32plus(&self) => self.raw64 != null;

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeLoadConfigHeader.size(&self, uint size = ...)
{
    $if $defined(size):
        if (self.raw64 != null) { uint old = self.raw64.size; self.raw64.size = size; return old; }
        uint old = self.raw32.size; self.raw32.size = size; return old;
    $else
        return self.raw64 != null ? self.raw64.size : self.raw32.size;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeLoadConfigHeader.security_cookie(&self, ulong security_cookie = ...)
{
    $if $defined(security_cookie):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.security_cookie;
            self.raw64.security_cookie = security_cookie;
            return old;
        }
        ulong old = (ulong)self.raw32.security_cookie;
        self.raw32.security_cookie = (uint)security_cookie;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.security_cookie
            : (ulong)self.raw32.security_cookie;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeLoadConfigHeader.guard_cf_check_function_pointer(&self, ulong v = ...)
{
    $if $defined(v):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.guard_cf_check_function_pointer;
            self.raw64.guard_cf_check_function_pointer = v;
            return old;
        }
        ulong old = (ulong)self.raw32.guard_cf_check_function_pointer;
        self.raw32.guard_cf_check_function_pointer = (uint)v;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.guard_cf_check_function_pointer
            : (ulong)self.raw32.guard_cf_check_function_pointer;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro ulong OpeLoadConfigHeader.guard_cf_dispatch_function_pointer(&self, ulong v = ...)
{
    $if $defined(v):
        if (self.raw64 != null)
        {
            ulong old = self.raw64.guard_cf_dispatch_function_pointer;
            self.raw64.guard_cf_dispatch_function_pointer = v;
            return old;
        }
        ulong old = (ulong)self.raw32.guard_cf_dispatch_function_pointer;
        self.raw32.guard_cf_dispatch_function_pointer = (uint)v;
        return old;
    $else
        return self.raw64 != null
            ? self.raw64.guard_cf_dispatch_function_pointer
            : (ulong)self.raw32.guard_cf_dispatch_function_pointer;
    $endif
}

<* @require self != null && (self.raw32 != null || self.raw64 != null) *>
macro uint OpeLoadConfigHeader.guard_flags(&self, uint guard_flags = ...)
{
    $if $defined(guard_flags):
        if (self.raw64 != null) { uint old = self.raw64.guard_flags; self.raw64.guard_flags = guard_flags; return old; }
        uint old = self.raw32.guard_flags; self.raw32.guard_flags = guard_flags; return old;
    $else
        return self.raw64 != null ? self.raw64.guard_flags : self.raw32.guard_flags;
    $endif
}

//
// Core view
//

struct OpePeView
{
    char[]                buffer;
    OpeRawDosHeader*      dos;
    OpeNtHeaders          nt;
    OpeRawSectionHeader[] sections;
}

//
// Internal helpers
//

<*
 @require self != null
 @require self.buffer.len > 0
 @return? PARSER_OUT_OF_BOUNDS
*>
fn char*? OpePeView._at(&self, usz offset)
{
    if (offset >= self.buffer.len) return PARSER_OUT_OF_BOUNDS~;
    return &self.buffer[offset];
}

<*
 @require self != null
 @require self.buffer.len > 0
 @require size > 0
 @return? PARSER_OUT_OF_BOUNDS
*>
fn char*? OpePeView._at_size(&self, usz offset, usz size)
{
    if (offset + size > self.buffer.len) return PARSER_OUT_OF_BOUNDS~;
    return &self.buffer[offset];
}

<*
 Translates an RVA to a file offset by walking the section table.
 @require self != null
 @return? PARSER_MALFORMED_STRUCTURE : "RVA does not fall within any known section"
*>
fn usz? OpePeView.rva_to_offset(&self, uint rva)
{
    foreach (s : self.sections)
    {
        if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
        {
            return (usz)(rva - s.virtual_address) + s.pointer_to_raw_data;
        }
    }
    return PARSER_MALFORMED_STRUCTURE~;
}

<*
 @require self != null
 @return? PARSER_MALFORMED_STRUCTURE, PARSER_OUT_OF_BOUNDS
*>
fn char*? OpePeView._rva_ptr(&self, uint rva)
{
    usz off = self.rva_to_offset(rva)!;
    return self._at(off)!;
}

<*
 @require self != null
 @require size > 0
 @return? PARSER_MALFORMED_STRUCTURE, PARSER_OUT_OF_BOUNDS
*>
fn char*? OpePeView._rva_ptr_size(&self, uint rva, usz size)
{
    usz off = self.rva_to_offset(rva)!;
    return self._at_size(off, size)!;
}

//
// init
//

<*
 Attach the view to a raw PE image buffer.
 @param [&inout] self
 @param [in] buffer : "Raw bytes of the PE image"
 @require self != null
 @require buffer.len >= OpeRawDosHeader.sizeof : "Buffer too small to contain a DOS header"
 @return? PARSER_MISMATCHING_DOS_SIGNATURE
 @return? PARSER_MISMATCHING_PE_SIGNATURE
 @return? PARSER_MALFORMED_STRUCTURE
*>
fn void? OpePeView.init(&self, char[] buffer)
{
    // Validate DOS header
    if (buffer.len < OpeRawDosHeader.sizeof) return PARSER_MALFORMED_STRUCTURE~;
    OpeRawDosHeader* dos = (OpeRawDosHeader*)&buffer[0];
    if (dos.e_magic != DOS_MAGIC) return PARSER_MISMATCHING_DOS_SIGNATURE~;

    // Validate PE signature
    usz nt_off = (usz)dos.e_lfanew;
    if (nt_off + 4 > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
    uint sig = *(uint*)&buffer[nt_off];
    if (sig != PE_SIGNATURE) return PARSER_MISMATCHING_PE_SIGNATURE~;

    // Validate and locate file header
    usz fh_off = nt_off + 4;
    if (fh_off + OpeRawFileHeader.sizeof > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
    OpeRawFileHeader* fh = (OpeRawFileHeader*)&buffer[fh_off];

    // Validate and locate optional header; discriminate PE32 vs PE32+
    usz oh_off = fh_off + OpeRawFileHeader.sizeof;
    if (oh_off + 2 > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
    ushort magic = *(ushort*)&buffer[oh_off];

    OpeRawOptionalHeader32* oh32 = null;
    OpeRawOptionalHeader64* oh64 = null;
    switch (magic)
    {
        case PE32_MAGIC:
            if (oh_off + OpeRawOptionalHeader32.sizeof > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            oh32 = (OpeRawOptionalHeader32*)&buffer[oh_off];
        case PE32PLUS_MAGIC:
            if (oh_off + OpeRawOptionalHeader64.sizeof > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            oh64 = (OpeRawOptionalHeader64*)&buffer[oh_off];
        default:
            return PARSER_MALFORMED_STRUCTURE~;
    }

    // Validate and locate section table
    usz sec_off   = oh_off + fh.size_of_optional_header;
    usz sec_count = fh.number_of_sections;
    if (sec_off + sec_count * OpeRawSectionHeader.sizeof > buffer.len) return PARSER_MALFORMED_STRUCTURE~;
    OpeRawSectionHeader* sec_ptr = (OpeRawSectionHeader*)&buffer[sec_off];

    *self = {
        .buffer   = buffer,
        .dos      = dos,
        .nt       = {
            .signature = sig,
            .fh        = (OpeFileHeader*)fh,
            .oh        = { .raw32 = oh32, .raw64 = oh64 },
        },
        .sections = sec_ptr[0..sec_count - 1],
    };
}

//
// Header accessors
//

<* @require self != null && self.dos != null *>
fn OpeDosHeader* OpePeView.dos_header(&self) => (OpeDosHeader*)self.dos;

<* @require self != null *>
fn OpeNtHeaders* OpePeView.nt_headers(&self) => &self.nt;

<* @require self != null *>
fn OpeFileHeader* OpePeView.file_header(&self) => self.nt.fh;

<* @require self != null *>
fn OpeOptionalHeader* OpePeView.optional_header(&self) => &self.nt.oh;

//
// Sections (zero-copy slice)
//

<*
 Returns a slice of OpeSection built from the section table.
 Section names are zero-copy slices into the buffer.
 @require self != null
*>
fn OpeSection[] OpePeView.sectionss(&self)
{
    OpeSection[] result = mem::new_array(OpeSection, self.sections.len);
    foreach (i, &r : self.sections)
    {
        usz name_len = SECTION_NAME_SIZE;
        for (usz j = 0; j < SECTION_NAME_SIZE; j++)
        {
            if (r.name[j] == 0) { name_len = j; break; }
        }
        result[i] = {
            .name                   = r.name[0..name_len - 1],
            .virtual_size           = r.virtual_size,
            .virtual_address        = r.virtual_address,
            .size_of_raw_data       = r.size_of_raw_data,
            .pointer_to_raw_data    = r.pointer_to_raw_data,
            .pointer_to_relocations = r.pointer_to_relocations,
            .pointer_to_linenumbers = r.pointer_to_linenumbers,
            .number_of_relocations  = r.number_of_relocations,
            .number_of_linenumbers  = r.number_of_linenumbers,
            .characteristics        = r.characteristics,
        };
    }
    return result;
}

//
// Data directories (zero-copy)
//

<*
 @require self != null
*>
fn OpeDataDirectory[] OpePeView.data_directories(&self)
{
    uint n = self.nt.oh.number_of_rva_and_sizes();
    OpeDataDirectory[] result = mem::new_array(OpeDataDirectory, n);
    for (uint i = 0; i < n; i++)
    {
        result[i] = self.nt.oh.data_directory(i);
    }
    return result;
}

<*
 @require self != null
 @require idx < NUM_DATA_DIRECTORIES
 @return? PARSER_MISSING_DATA_DIRECTORY
*>
fn OpeDataDirectory? OpePeView._require_dir(&self, uint idx)
{
    OpeDataDirectory dir = self.nt.oh.data_directory(idx);
    if (dir.virtual_address == 0 || dir.size == 0) return PARSER_MISSING_DATA_DIRECTORY~;
    return dir;
}

//
// foreach_import_descriptor
//

<*
 Iterates over all IMAGE_IMPORT_DESCRIPTOR entries.
 Callback receives a pointer to a pre-filled OpeImportDescriptor.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each import descriptor"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_import_descriptor(&self, OpeImportDescriptorCallback cb)
{
    OpeDataDirectory dir = self._require_dir(DATA_DIR_IMPORT)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;

    while (true)
    {
        if (off + OpeRawImportDescriptor.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawImportDescriptor* r = (OpeRawImportDescriptor*)&self.buffer[off];
        if (r.original_first_thunk == 0 && r.first_thunk == 0) break;

        ZString dll = (ZString)self._rva_ptr(r.name_rva)!;
        OpeImportDescriptor desc = {
            .dll                  = dll,
            .original_first_thunk = r.original_first_thunk,
            .time_date_stamp      = r.time_date_stamp,
            .forwarder_chain      = r.forwarder_chain,
            .name_rva             = r.name_rva,
            .first_thunk          = r.first_thunk,
        };

        if (!cb(&desc)) break;
        off += OpeRawImportDescriptor.sizeof;
    }
}

//
// foreach_import
//

<*
 Iterates over all thunk entries across every import descriptor.
 Callback receives a pointer to a pre-filled OpeImport.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each imported symbol"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_import(&self, OpeImportCallback cb)
{
    OpeDataDirectory dir  = self._require_dir(DATA_DIR_IMPORT)!;
    usz  desc_off         = self.rva_to_offset(dir.virtual_address)!;
    bool is64             = self.nt.oh.is_pe32plus();

    while (true)
    {
        if (desc_off + OpeRawImportDescriptor.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
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
                thunk    = *(ulong*)&self.buffer[ilt_off];
                if (thunk == 0) break;
                ilt_off += 8;
            }
            else
            {
                if (ilt_off + 4 > self.buffer.len) break;
                thunk    = (ulong)(*(uint*)&self.buffer[ilt_off]);
                if (thunk == 0) break;
                ilt_off += 4;
            }

            uint cur_iat_rva = iat_rva + entry_idx * (is64 ? 8u : 4u);
            bool is_ord      = is64 ? ((thunk >> 63) != 0) : ((thunk >> 31) != 0);

            OpeImport imp;
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
                if (name_off + 2 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
                imp.hint       = *(ushort*)&self.buffer[name_off];
                imp.name       = (ZString)&self.buffer[name_off + 2];
                imp.ordinal    = 0;
                imp.is_ordinal = false;
            }

            if (!cb(&imp)) return;
            entry_idx++;
        }

        desc_off += OpeRawImportDescriptor.sizeof;
    }
}

//
// foreach_export
//

<*
 Iterates over all entries in the export address table.
 Forwarded exports have is_forwarder set and the forwarder field populated.
 Ordinal-only exports have name == null.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each exported symbol"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_export(&self, OpeExportCallback cb)
{
    OpeDataDirectory dir     = self._require_dir(DATA_DIR_EXPORT)!;
    usz              exp_off = self.rva_to_offset(dir.virtual_address)!;
    if (exp_off + OpeRawExportDirectory.sizeof > self.buffer.len)
    {
        return PARSER_MALFORMED_STRUCTURE~;
    }
    OpeRawExportDirectory* ed = (OpeRawExportDirectory*)&self.buffer[exp_off];

    uint export_dir_start = dir.virtual_address;
    uint export_dir_end   = dir.virtual_address + dir.size;

    usz funcs_off = self.rva_to_offset(ed.address_of_functions)!;
    usz names_off = self.rva_to_offset(ed.address_of_names)!;
    usz ords_off  = self.rva_to_offset(ed.address_of_name_ordinals)!;

    for (uint i = 0; i < ed.number_of_functions; i++)
    {
        if (funcs_off + (usz)(i + 1) * 4 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
        uint func_rva = *(uint*)&self.buffer[funcs_off + (usz)i * 4];
        if (func_rva == 0) continue;

        OpeExportEntry entry;
        entry.ordinal = (ushort)(ed.base + i);
        entry.name    = null;

        for (uint ni = 0; ni < ed.number_of_names; ni++)
        {
            if (ords_off + (usz)(ni + 1) * 2 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            ushort name_ord = *(ushort*)&self.buffer[ords_off + (usz)ni * 2];
            if (name_ord == i)
            {
                if (names_off + (usz)(ni + 1) * 4 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
                uint name_rva = *(uint*)&self.buffer[names_off + (usz)ni * 4];
                usz  name_off = self.rva_to_offset(name_rva)!;
                entry.name    = (ZString)&self.buffer[name_off];
                break;
            }
        }

        if (func_rva >= export_dir_start && func_rva < export_dir_end)
        {
            entry.is_forwarder = true;
            usz fwd_off        = self.rva_to_offset(func_rva)!;
            entry.forwarder    = (ZString)&self.buffer[fwd_off];
        }
        else
        {
            entry.is_forwarder = false;
            entry.rva          = func_rva;
        }

        if (!cb(&entry)) break;
    }
}

//
// foreach_tls_callback
//

<*
 Iterates over all TLS callback VAs in the TLS callback array.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each TLS callback entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_tls_callback(&self, OpeTlsCallbackCb cb)
{
    OpeDataDirectory dir     = self._require_dir(DATA_DIR_TLS)!;
    usz              tls_off = self.rva_to_offset(dir.virtual_address)!;
    bool             is64    = self.nt.oh.is_pe32plus();
    ulong            ibase   = self.nt.oh.image_base();

    ulong callbacks_va;
    if (is64)
    {
        if (tls_off + OpeRawTlsDirectory64.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        callbacks_va = ((OpeRawTlsDirectory64*)&self.buffer[tls_off]).address_of_callbacks;
    }
    else
    {
        if (tls_off + OpeRawTlsDirectory32.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        callbacks_va = (ulong)((OpeRawTlsDirectory32*)&self.buffer[tls_off]).address_of_callbacks;
    }

    if (callbacks_va == 0) return;
    uint callbacks_rva = (uint)(callbacks_va - ibase);
    usz  cb_off        = self.rva_to_offset(callbacks_rva)!;

    while (true)
    {
        ulong fn_va;
        if (is64)
        {
            if (cb_off + 8 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            fn_va   = *(ulong*)&self.buffer[cb_off];
            cb_off += 8;
        }
        else
        {
            if (cb_off + 4 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            fn_va   = (ulong)(*(uint*)&self.buffer[cb_off]);
            cb_off += 4;
        }
        if (fn_va == 0) break;
        OpeTlsCallback tcb = { .address = fn_va };
        if (!cb(&tcb)) break;
    }
}

//
// foreach_delayed_import_descriptor
//

<*
 Iterates over all ImgDelayDescr entries (new linker format, RVA-based).
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each delayed import descriptor"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_delayed_import_descriptor(&self, OpeDelayedImportDescriptorCallback cb)
{
    OpeDataDirectory dir = self._require_dir(DATA_DIR_DELAY_IMPORT)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;

    while (true)
    {
        if (off + OpeRawDelayImportDescriptor.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawDelayImportDescriptor* r = (OpeRawDelayImportDescriptor*)&self.buffer[off];
        if (r.dll_name_rva == 0) break;

        ZString dll = (ZString)self._rva_ptr(r.dll_name_rva)!;
        OpeDelayedImportDescriptor desc = {
            .dll               = dll,
            .attributes        = r.attributes,
            .module_handle_rva = r.module_handle_rva,
            .iat_rva           = r.iat_rva,
            .ilt_rva           = r.ilt_rva,
            .bound_iat_rva     = r.bound_iat_rva,
            .unload_iat_rva    = r.unload_iat_rva,
            .timestamp         = r.timestamp,
        };

        if (!cb(&desc)) break;
        off += OpeRawDelayImportDescriptor.sizeof;
    }
}

//
// foreach_delayed_import
//

<*
 Iterates over all thunk entries across every delayed import descriptor.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each delayed import symbol"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_delayed_import(&self, OpeDelayedImportCallback cb)
{
    OpeDataDirectory dir      = self._require_dir(DATA_DIR_DELAY_IMPORT)!;
    usz              desc_off = self.rva_to_offset(dir.virtual_address)!;
    bool             is64     = self.nt.oh.is_pe32plus();

    while (true)
    {
        if (desc_off + OpeRawDelayImportDescriptor.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
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
                thunk    = *(ulong*)&self.buffer[ilt_off];
                if (thunk == 0) break;
                ilt_off += 8;
            }
            else
            {
                if (ilt_off + 4 > self.buffer.len) break;
                thunk    = (ulong)(*(uint*)&self.buffer[ilt_off]);
                if (thunk == 0) break;
                ilt_off += 4;
            }

            uint cur_iat_rva = r.iat_rva + entry_idx * (is64 ? 8u : 4u);
            bool is_ord      = is64 ? ((thunk >> 63) != 0) : ((thunk >> 31) != 0);

            OpeDelayedImport imp;
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
                if (name_off + 2 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
                imp.hint       = *(ushort*)&self.buffer[name_off];
                imp.name       = (ZString)&self.buffer[name_off + 2];
                imp.ordinal    = 0;
                imp.is_ordinal = false;
            }

            if (!cb(&imp)) return;
            entry_idx++;
        }

        desc_off += OpeRawDelayImportDescriptor.sizeof;
    }
}

//
// foreach_bound_import
//

<*
 Iterates over all IMAGE_BOUND_IMPORT_DESCRIPTOR entries.
 Note: the bound import directory is addressed by file offset, not RVA.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each bound import descriptor"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
*>
fn void? OpePeView.foreach_bound_import(&self, OpeBoundImportCallback cb)
{
    OpeDataDirectory dir      = self._require_dir(DATA_DIR_BOUND_IMPORT)!;
    usz              base_off = (usz)dir.virtual_address;
    usz              off      = base_off;

    while (true)
    {
        if (off + OpeRawBoundImportDescriptor.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawBoundImportDescriptor* r = (OpeRawBoundImportDescriptor*)&self.buffer[off];
        if (r.time_date_stamp == 0 && r.offset_module_name == 0) break;

        usz name_off = base_off + (usz)r.offset_module_name;
        if (name_off >= self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;

        OpeBoundImportDescriptor desc = {
            .dll                             = (ZString)&self.buffer[name_off],
            .time_date_stamp                 = r.time_date_stamp,
            .number_of_module_forwarder_refs = r.number_of_module_forwarder_refs,
        };

        if (!cb(&desc)) break;
        off += OpeRawBoundImportDescriptor.sizeof;
    }
}

//
// foreach_exception
//

<*
 Iterates over all RUNTIME_FUNCTION entries in the exception directory.
 Only meaningful for x64/ARM images.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each exception entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_exception(&self, OpeExceptionCallback cb)
{
    OpeDataDirectory dir   = self._require_dir(DATA_DIR_EXCEPTION)!;
    usz              off   = self.rva_to_offset(dir.virtual_address)!;
    uint             count = dir.size / (uint)OpeRawRuntimeFunction.sizeof;

    for (uint i = 0; i < count; i++)
    {
        if (off + OpeRawRuntimeFunction.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawRuntimeFunction* r = (OpeRawRuntimeFunction*)&self.buffer[off];
        OpeException ex = {
            .begin_address   = r.begin_address,
            .end_address     = r.end_address,
            .unwind_info_rva = r.unwind_info_address,
        };
        if (!cb(&ex)) break;
        off += OpeRawRuntimeFunction.sizeof;
    }
}

//
// foreach_debug_entry
//

<*
 Iterates over all IMAGE_DEBUG_DIRECTORY entries.
 The data slice in each entry is zero-copy from the buffer at the file offset.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each debug directory entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_debug_entry(&self, OpeDebugEntryCallback cb)
{
    OpeDataDirectory dir   = self._require_dir(DATA_DIR_DEBUG)!;
    usz              off   = self.rva_to_offset(dir.virtual_address)!;
    uint             count = dir.size / (uint)OpeRawDebugDirectory.sizeof;

    for (uint i = 0; i < count; i++)
    {
        if (off + OpeRawDebugDirectory.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawDebugDirectory* r = (OpeRawDebugDirectory*)&self.buffer[off];

        char[] data;
        if (r.size_of_data > 0 && r.pointer_to_raw_data > 0)
        {
            usz d_off = (usz)r.pointer_to_raw_data;
            if (d_off + r.size_of_data <= self.buffer.len)
            {
                data = self.buffer[d_off .. d_off + r.size_of_data];
            }
        }

        OpeDebugEntry entry = {
            .type            = r.type,
            .time_date_stamp = r.time_date_stamp,
            .major_version   = r.major_version,
            .minor_version   = r.minor_version,
            .rva             = r.address_of_raw_data,
            .file_offset     = r.pointer_to_raw_data,
            .size            = r.size_of_data,
            .data            = data,
        };
        if (!cb(&entry)) break;
        off += OpeRawDebugDirectory.sizeof;
    }
}

//
// foreach_relocation
//

<*
 Iterates over all base relocation entries, with the page RVA already applied.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each relocation entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_relocation(&self, OpeRelocationCallback cb)
{
    OpeDataDirectory dir = self._require_dir(DATA_DIR_BASERELOC)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    usz end = off + (usz)dir.size;

    while (off < end)
    {
        if (off + OpeRawBaseRelocation.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawBaseRelocation* block = (OpeRawBaseRelocation*)&self.buffer[off];
        if (block.size_of_block < OpeRawBaseRelocation.sizeof)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }

        uint page_rva  = block.virtual_address;
        uint entries   = (block.size_of_block - (uint)OpeRawBaseRelocation.sizeof) / 2;
        usz  entry_off = off + OpeRawBaseRelocation.sizeof;

        for (uint i = 0; i < entries; i++)
        {
            if (entry_off + 2 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
            OpeRawBaseRelocationEntry e = *(OpeRawBaseRelocationEntry*)&self.buffer[entry_off];

            OpeRelocation rel = {
                .rva    = page_rva + e.offset,
                .type   = e.type,
                .offset = e.offset,
            };
            if (!cb(&rel)) return;
            entry_off += 2;
        }

        off += (usz)block.size_of_block;
    }
}

//
// foreach_resource (flat leaf walk over the 3-level Type/Name/Language tree)
//

<*
 Internal recursive walker for the resource directory tree.
 @param [&in] self
 @param res_base : "File offset of the root resource directory"
 @param dir_off  : "File offset of the current directory node"
 @param depth    : "Current tree depth: 0=Type 1=Name 2=Language"
 @require self != null
 @require depth <= 2 : "Resource directory tree must not exceed 3 levels"
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn bool? OpePeView._walk_resource_dir(
    &self,
    usz  res_base,
    usz  dir_off,
    uint depth,
    uint type_id,
    uint name_id,
    OpeResourceCallback cb)
{
    if (dir_off + OpeRawResourceDirectory.sizeof > self.buffer.len)
    {
        return PARSER_MALFORMED_STRUCTURE~;
    }
    OpeRawResourceDirectory* dir = (OpeRawResourceDirectory*)&self.buffer[dir_off];
    uint total     = (uint)dir.number_of_named_entries + (uint)dir.number_of_id_entries;
    usz  entry_off = dir_off + OpeRawResourceDirectory.sizeof;

    for (uint i = 0; i < total; i++)
    {
        if (entry_off + OpeRawResourceDirectoryEntry.sizeof > self.buffer.len)
        {
            return PARSER_MALFORMED_STRUCTURE~;
        }
        OpeRawResourceDirectoryEntry* e = (OpeRawResourceDirectoryEntry*)&self.buffer[entry_off];
        entry_off += OpeRawResourceDirectoryEntry.sizeof;

        uint id            = e.name_or_id & 0x7FFFFFFF;
        uint child_off_raw = e.offset_to_data_or_directory;
        bool is_dir        = (child_off_raw >> 31) != 0;
        usz  child_off     = res_base + (usz)(child_off_raw & 0x7FFFFFFF);

        if (is_dir)
        {
            uint next_type = depth == 0 ? id : type_id;
            uint next_name = depth == 1 ? id : name_id;
            bool cont      = self._walk_resource_dir(res_base, child_off, depth + 1,
                                                     next_type, next_name, cb)!;
            if (!cont) return false;
        }
        else
        {
            if (child_off + OpeRawResourceDataEntry.sizeof > self.buffer.len)
            {
                return PARSER_MALFORMED_STRUCTURE~;
            }
            OpeRawResourceDataEntry* de = (OpeRawResourceDataEntry*)&self.buffer[child_off];

            usz    data_off = self.rva_to_offset(de.offset_to_data)!;
            char[] data;
            if (data_off + de.size <= self.buffer.len)
            {
                data = self.buffer[data_off .. data_off + de.size];
            }

            OpeResourceEntry leaf = {
                .rva         = de.offset_to_data,
                .size        = de.size,
                .code_page   = de.code_page,
                .reserved    = de.reserved,
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

<*
 Iterates over all leaf resource data entries, flattening the 3-level tree.
 Each entry has type_id, name_id and language_id pre-filled.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each resource leaf entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn void? OpePeView.foreach_resource(&self, OpeResourceCallback cb)
{
    OpeDataDirectory dir      = self._require_dir(DATA_DIR_RESOURCE)!;
    usz              res_base = self.rva_to_offset(dir.virtual_address)!;
    self._walk_resource_dir(res_base, res_base, 0, 0, 0, cb)!;
}

//
// foreach_certificate (file-offset based, not RVA)
//

<*
 Iterates over all WIN_CERTIFICATE entries in the security directory.
 Note: the certificate table uses file offsets, not RVAs.
 The data slice is zero-copy from the buffer.
 Returning false from the callback stops iteration.
 @param [&in] self
 @param cb : "Callback invoked for each certificate entry"
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
*>
fn void? OpePeView.foreach_certificate(&self, OpeCertificateCallback cb)
{
    OpeDataDirectory dir = self._require_dir(DATA_DIR_CERTIFICATE)!;
    usz off = (usz)dir.virtual_address;
    usz end = off + (usz)dir.size;

    while (off < end)
    {
        if (off + 8 > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
        uint   length    = *(uint*)  &self.buffer[off];
        ushort rev       = *(ushort*)&self.buffer[off + 4];
        ushort cert_type = *(ushort*)&self.buffer[off + 6];

        if (length < 8) return PARSER_MALFORMED_STRUCTURE~;
        usz data_len = (usz)length - 8;

        char[] data;
        if (data_len > 0 && off + 8 + data_len <= self.buffer.len)
        {
            data = self.buffer[off + 8 .. off + 8 + data_len];
        }

        OpeCertificate cert = {
            .length           = length,
            .revision         = rev,
            .certificate_type = cert_type,
            .data             = data,
        };
        if (!cb(&cert)) break;

        usz aligned = ((usz)length + (usz)7) & ~(usz)7;
        off += aligned;
    }
}

//
// cor20_header
//

fn OpeDataDirectory cvt_data_dir(OpeRawDataDirectory raw) @local
{
    return { .virtual_address = raw.virtual_address, .size = raw.size };
}

<*
 Returns the COR20 (.NET) header if present.
 Returns PARSER_MISSING_DATA_DIRECTORY if the CLR runtime header directory is absent.
 @param [&in] self
 @require self != null
 @return? PARSER_MISSING_DATA_DIRECTORY
 @return? PARSER_MALFORMED_STRUCTURE
 @return? PARSER_OUT_OF_BOUNDS
*>
fn OpeCor20Header? OpePeView.cor20_header(&self)
{
    OpeDataDirectory dir = self._require_dir(DATA_DIR_CLR_RUNTIME)!;
    usz off = self.rva_to_offset(dir.virtual_address)!;
    if (off + OpeRawCor20Header.sizeof > self.buffer.len) return PARSER_MALFORMED_STRUCTURE~;
    OpeRawCor20Header* r = (OpeRawCor20Header*)&self.buffer[off];

    return {
        .cb                         = r.cb,
        .major_runtime_version      = r.major_runtime_version,
        .minor_runtime_version      = r.minor_runtime_version,
        .meta_data                  = cvt_data_dir(r.meta_data),
        .flags                      = r.flags,
        .entry_point_token_or_rva   = r.entry_point_token_or_rva,
        .resources                  = cvt_data_dir(r.resources),
        .strong_name_signature      = cvt_data_dir(r.strong_name_signature),
        .code_manager_table         = cvt_data_dir(r.code_manager_table),
        .vtable_fixups              = cvt_data_dir(r.vtable_fixups),
        .export_address_table_jumps = cvt_data_dir(r.export_address_table_jumps),
        .managed_native_header      = cvt_data_dir(r.managed_native_header),
    };
}
