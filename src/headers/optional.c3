module vipe::headers::optional;
import vipe::common;

const ushort PE32_MAGIC           = 0x010B;
const ushort PE32PLUS_MAGIC       = 0x020B;
const uint   NUM_DATA_DIRECTORIES = 16;

constdef VipeDataDirectoryIndex
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

//
// Raw structures definition
//

struct VipeRawDataDirectory @packed
{
    uint virtual_address;
    uint size;
}

struct VipeRawOptionalHeader32 @packed
{
    ushort magic;
    char major_linker_version;
    char minor_linker_version;
    uint size_of_code;
    uint size_of_initialized_data;
    uint size_of_uninitialized_data;
    uint address_of_entry_point;
    uint base_of_code;
    uint base_of_data;
    uint image_base;
    uint section_alignment;
    uint file_alignment;
    ushort major_operating_system_version;
    ushort minor_operating_system_version;
    ushort major_image_version;
    ushort minor_image_version;
    ushort major_subsystem_version;
    ushort minor_subsystem_version;
    uint win32_version_value;
    uint size_of_image;
    uint size_of_headers;
    uint check_sum;
    ushort subsystem;
    ushort dll_characteristics;
    uint size_of_stack_reserve;
    uint size_of_stack_commit;
    uint size_of_heap_reserve;
    uint size_of_heap_commit;
    uint loader_flags;
    uint number_of_rva_and_sizes;
    VipeRawDataDirectory[NUM_DATA_DIRECTORIES] data_directory;
}

struct VipeRawOptionalHeader64 @packed
{
    ushort magic;
    char major_linker_version;
    char minor_linker_version;
    uint size_of_code;
    uint size_of_initialized_data;
    uint size_of_uninitialized_data;
    uint address_of_entry_point;
    uint base_of_code;
    ulong image_base;
    uint section_alignment;
    uint file_alignment;
    ushort major_operating_system_version;
    ushort minor_operating_system_version;
    ushort major_image_version;
    ushort minor_image_version;
    ushort major_subsystem_version;
    ushort minor_subsystem_version;
    uint win32_version_value;
    uint size_of_image;
    uint size_of_headers;
    uint check_sum;
    ushort subsystem;
    ushort dll_characteristics;
    ulong size_of_stack_reserve;
    ulong size_of_stack_commit;
    ulong size_of_heap_reserve;
    ulong size_of_heap_commit;
    uint loader_flags;
    uint number_of_rva_and_sizes;
    VipeRawDataDirectory[NUM_DATA_DIRECTORIES] data_directory;
}

//
// View structures definition
//

struct VipeViewOptionalHeader
{
    bool is64;
    union
    {
        VipeRawOptionalHeader32* raw32;
        VipeRawOptionalHeader64* raw64;
    }
}

macro ushort VipeViewOptionalHeader.magic(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.magic, self.raw32.magic, v);

macro char VipeViewOptionalHeader.major_linker_version(&self, char v = ...)
    => common::@select_exchange(self.is64, self.raw64.major_linker_version, self.raw32.major_linker_version, v);

macro char VipeViewOptionalHeader.minor_linker_version(&self, char v = ...)
    => common::@select_exchange(self.is64, self.raw64.minor_linker_version, self.raw32.minor_linker_version, v);

macro uint VipeViewOptionalHeader.size_of_code(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_code, self.raw32.size_of_code, v);

macro uint VipeViewOptionalHeader.size_of_initialized_data(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_initialized_data, self.raw32.size_of_initialized_data, v);

macro uint VipeViewOptionalHeader.size_of_uninitialized_data(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_uninitialized_data, self.raw32.size_of_uninitialized_data, v);

macro uint VipeViewOptionalHeader.address_of_entry_point(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.address_of_entry_point, self.raw32.address_of_entry_point, v);

macro uint VipeViewOptionalHeader.base_of_code(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.base_of_code, self.raw32.base_of_code, v);

macro uint? VipeViewOptionalHeader.base_of_data(&self, uint v = ...)
    => self.is64
        ? common::MISSING_RESOURCE~
        : common::@exchange(self.raw32.base_of_data, v);

macro ulong VipeViewOptionalHeader.image_base(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.image_base, v)
        : common::@exchange(self.raw32.image_base, (uint)v);

macro uint VipeViewOptionalHeader.section_alignment(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.section_alignment, self.raw32.section_alignment, v);

macro uint VipeViewOptionalHeader.file_alignment(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.file_alignment, self.raw32.file_alignment, v);

macro ushort VipeViewOptionalHeader.major_operating_system_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.major_operating_system_version, self.raw32.major_operating_system_version, v);

macro ushort VipeViewOptionalHeader.minor_operating_system_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.minor_operating_system_version, self.raw32.minor_operating_system_version, v);

macro ushort VipeViewOptionalHeader.major_image_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.major_image_version, self.raw32.major_image_version, v);

macro ushort VipeViewOptionalHeader.minor_image_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.minor_image_version, self.raw32.minor_image_version, v);

macro ushort VipeViewOptionalHeader.major_subsystem_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.major_subsystem_version, self.raw32.major_subsystem_version, v);

macro ushort VipeViewOptionalHeader.minor_subsystem_version(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.minor_subsystem_version, self.raw32.minor_subsystem_version, v);

macro uint VipeViewOptionalHeader.win32_version_value(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.win32_version_value, self.raw32.win32_version_value, v);

macro uint VipeViewOptionalHeader.size_of_image(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_image, self.raw32.size_of_image, v);

macro uint VipeViewOptionalHeader.size_of_headers(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_headers, self.raw32.size_of_headers, v);

macro uint VipeViewOptionalHeader.check_sum(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.check_sum, self.raw32.check_sum, v);

macro ushort VipeViewOptionalHeader.subsystem(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.subsystem, self.raw32.subsystem, v);

macro ushort VipeViewOptionalHeader.dll_characteristics(&self, ushort v = ...)
    => common::@select_exchange(self.is64, self.raw64.dll_characteristics, self.raw32.dll_characteristics, v);

macro ulong VipeViewOptionalHeader.size_of_stack_reserve(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.size_of_stack_reserve, v)
        : common::@exchange(self.raw32.size_of_stack_reserve, (uint)v);

macro ulong VipeViewOptionalHeader.size_of_stack_commit(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.size_of_stack_commit, v)
        : common::@exchange(self.raw32.size_of_stack_commit, (uint)v);

macro ulong VipeViewOptionalHeader.size_of_heap_reserve(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.size_of_heap_reserve, v)
        : common::@exchange(self.raw32.size_of_heap_reserve, (uint)v);

macro ulong VipeViewOptionalHeader.size_of_heap_commit(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.size_of_heap_commit, v)
        : common::@exchange(self.raw32.size_of_heap_commit, (uint)v);

macro uint VipeViewOptionalHeader.loader_flags(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.loader_flags, self.raw32.loader_flags, v);

macro uint VipeViewOptionalHeader.number_of_rva_and_sizes(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.number_of_rva_and_sizes, self.raw32.number_of_rva_and_sizes, v);

// TODO: add index checking
fn VipeRawDataDirectory* VipeViewOptionalHeader.data_directory(&self, VipeDataDirectoryIndex i)
    => self.is64
        ? &self.raw64.data_directory[(int)i]
        : &self.raw32.data_directory[(int)i];
