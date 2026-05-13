module ope::headers::optional;
import ope::common;

const ushort PE32_MAGIC           = 0x010B;
const ushort PE32PLUS_MAGIC       = 0x020B;
const uint   NUM_DATA_DIRECTORIES = 16;

constdef OpeDataDirectoryIndex
{
    EXPORT,
    IMPORT,
    RESOURCE,
    EXCEPTION,
    CERTIFICATE,
    BASERELOC,
    DEBUG,
    TLS = 9,
    LOAD_CONFIG,
    BOUND_IMPORT,
    IAT,
    DELAY_IMPORT,
    CLR_RUNTIME,
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

struct OpeViewOptionalHeader
{
    bool is64;
    union
    {
        OpeRawOptionalHeader32* h32;
        OpeRawOptionalHeader64* h64;
    }
}

macro ushort OpeViewOptionalHeader.magic(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.magic : self.h32.magic, v);

macro char OpeViewOptionalHeader.major_linker_version(&self, char v = ...)
    => common::@exchange(self.is64 ? self.h64.major_linker_version : self.h32.major_linker_version, v);

macro char OpeViewOptionalHeader.minor_linker_version(&self, char v = ...)
    => common::@exchange(self.is64 ? self.h64.minor_linker_version : self.h32.minor_linker_version, v);

macro uint OpeViewOptionalHeader.size_of_code(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_code : self.h32.size_of_code, v);

macro uint OpeViewOptionalHeader.size_of_initialized_data(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_initialized_data : self.h32.size_of_initialized_data, v);

macro uint OpeViewOptionalHeader.size_of_uninitialized_data(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_uninitialized_data : self.h32.size_of_uninitialized_data, v);

macro uint OpeViewOptionalHeader.address_of_entry_point(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.address_of_entry_point : self.h32.address_of_entry_point, v);

macro uint OpeViewOptionalHeader.base_of_code(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.base_of_code : self.h32.base_of_code, v);

macro uint? OpeViewOptionalHeader.base_of_data(&self, uint v = ...)
{
    if (self.is64) return common::UNABLE_TO_RESOLVE~;
    return common::@exchange(self.h32.base_of_data, v);
}

macro ulong OpeViewOptionalHeader.image_base(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.image_base : (ulong)self.h32.image_base, self.is64 ? v : (uint)v);

macro uint OpeViewOptionalHeader.section_alignment(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.section_alignment : self.h32.section_alignment, v);

macro uint OpeViewOptionalHeader.file_alignment(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.file_alignment : self.h32.file_alignment, v);

macro ushort OpeViewOptionalHeader.major_operating_system_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.major_operating_system_version : self.h32.major_operating_system_version, v);

macro ushort OpeViewOptionalHeader.minor_operating_system_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.minor_operating_system_version : self.h32.minor_operating_system_version, v);

macro ushort OpeViewOptionalHeader.major_image_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.major_image_version : self.h32.major_image_version, v);

macro ushort OpeViewOptionalHeader.minor_image_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.minor_image_version : self.h32.minor_image_version, v);

macro ushort OpeViewOptionalHeader.major_subsystem_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.major_subsystem_version : self.h32.major_subsystem_version, v);

macro ushort OpeViewOptionalHeader.minor_subsystem_version(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.minor_subsystem_version : self.h32.minor_subsystem_version, v);

macro uint OpeViewOptionalHeader.win32_version_value(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.win32_version_value : self.h32.win32_version_value, v);

macro uint OpeViewOptionalHeader.size_of_image(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_image : self.h32.size_of_image, v);

macro uint OpeViewOptionalHeader.size_of_headers(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_headers : self.h32.size_of_headers, v);

macro uint OpeViewOptionalHeader.check_sum(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.check_sum : self.h32.check_sum, v);

macro ushort OpeViewOptionalHeader.subsystem(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.subsystem : self.h32.subsystem, v);

macro ushort OpeViewOptionalHeader.dll_characteristics(&self, ushort v = ...)
    => common::@exchange(self.is64 ? self.h64.dll_characteristics : self.h32.dll_characteristics, v);

macro ulong OpeViewOptionalHeader.size_of_stack_reserve(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_stack_reserve : (ulong)self.h32.size_of_stack_reserve, self.is64 ? v : (uint)v);

macro ulong OpeViewOptionalHeader.size_of_stack_commit(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_stack_commit : (ulong)self.h32.size_of_stack_commit, self.is64 ? v : (uint)v);

macro ulong OpeViewOptionalHeader.size_of_heap_reserve(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_heap_reserve : (ulong)self.h32.size_of_heap_reserve, self.is64 ? v : (uint)v);

macro ulong OpeViewOptionalHeader.size_of_heap_commit(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.h64.size_of_heap_commit : (ulong)self.h32.size_of_heap_commit, self.is64 ? v : (uint)v);

macro uint OpeViewOptionalHeader.loader_flags(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.loader_flags : self.h32.loader_flags, v);

macro uint OpeViewOptionalHeader.number_of_rva_and_sizes(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.h64.number_of_rva_and_sizes : self.h32.number_of_rva_and_sizes, v);

fn OpeRawDataDirectory OpeViewOptionalHeader.data_directory(&self, OpeDataDirectoryIndex i)
    => self.is64 ? self.h64.data_directory[(uint)i] : self.h32.data_directory[(uint)i];
