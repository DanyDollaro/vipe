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
        VipeRawOptionalHeader32* h32;
        VipeRawOptionalHeader64* h64;
    }
}

fn ushort VipeViewOptionalHeader.get_magic(&self)
    => self.is64 ? self.h64.magic : self.h32.magic;
fn void VipeViewOptionalHeader.set_magic(&self, ushort v)
{
    if (self.is64) { self.h64.magic = v; }
    else           { self.h32.magic = v; }
}

fn char VipeViewOptionalHeader.get_major_linker_version(&self)
    => self.is64 ? self.h64.major_linker_version : self.h32.major_linker_version;
fn void VipeViewOptionalHeader.set_major_linker_version(&self, char v)
{
    if (self.is64) { self.h64.major_linker_version = v; }
    else           { self.h32.major_linker_version = v; }
}

fn char VipeViewOptionalHeader.get_minor_linker_version(&self)
    => self.is64 ? self.h64.minor_linker_version : self.h32.minor_linker_version;
fn void VipeViewOptionalHeader.set_minor_linker_version(&self, char v)
{
    if (self.is64) { self.h64.minor_linker_version = v; }
    else           { self.h32.minor_linker_version = v; }
}

fn uint VipeViewOptionalHeader.get_size_of_code(&self)
    => self.is64 ? self.h64.size_of_code : self.h32.size_of_code;
fn void VipeViewOptionalHeader.set_size_of_code(&self, uint v)
{
    if (self.is64) { self.h64.size_of_code = v; }
    else           { self.h32.size_of_code = v; }
}

fn uint VipeViewOptionalHeader.get_size_of_initialized_data(&self)
    => self.is64 ? self.h64.size_of_initialized_data : self.h32.size_of_initialized_data;
fn void VipeViewOptionalHeader.set_size_of_initialized_data(&self, uint v)
{
    if (self.is64) { self.h64.size_of_initialized_data = v; }
    else           { self.h32.size_of_initialized_data = v; }
}

fn uint VipeViewOptionalHeader.get_size_of_uninitialized_data(&self)
    => self.is64 ? self.h64.size_of_uninitialized_data : self.h32.size_of_uninitialized_data;
fn void VipeViewOptionalHeader.set_size_of_uninitialized_data(&self, uint v)
{
    if (self.is64) { self.h64.size_of_uninitialized_data = v; }
    else           { self.h32.size_of_uninitialized_data = v; }
}

fn uint VipeViewOptionalHeader.get_address_of_entry_point(&self)
    => self.is64 ? self.h64.address_of_entry_point : self.h32.address_of_entry_point;
fn void VipeViewOptionalHeader.set_address_of_entry_point(&self, uint v)
{
    if (self.is64) { self.h64.address_of_entry_point = v; }
    else           { self.h32.address_of_entry_point = v; }
}

fn uint VipeViewOptionalHeader.get_base_of_code(&self)
    => self.is64 ? self.h64.base_of_code : self.h32.base_of_code;
fn void VipeViewOptionalHeader.set_base_of_code(&self, uint v)
{
    if (self.is64) { self.h64.base_of_code = v; }
    else           { self.h32.base_of_code = v; }
}

fn uint? VipeViewOptionalHeader.get_base_of_data(&self)
{
    if (self.is64) return common::UNABLE_TO_RESOLVE~;
    return self.h32.base_of_data;
}
fn void VipeViewOptionalHeader.set_base_of_data(&self, uint v)
{
    if (!self.is64) { self.h32.base_of_data = v; }
}

fn ulong VipeViewOptionalHeader.get_image_base(&self)
    => self.is64 ? self.h64.image_base : (ulong)self.h32.image_base;
fn void VipeViewOptionalHeader.set_image_base(&self, ulong v)
{
    if (self.is64) { self.h64.image_base = v; }
    else           { self.h32.image_base = (uint)v; }
}

fn uint VipeViewOptionalHeader.get_section_alignment(&self)
    => self.is64 ? self.h64.section_alignment : self.h32.section_alignment;
fn void VipeViewOptionalHeader.set_section_alignment(&self, uint v)
{
    if (self.is64) { self.h64.section_alignment = v; }
    else           { self.h32.section_alignment = v; }
}

fn uint VipeViewOptionalHeader.get_file_alignment(&self)
    => self.is64 ? self.h64.file_alignment : self.h32.file_alignment;
fn void VipeViewOptionalHeader.set_file_alignment(&self, uint v)
{
    if (self.is64) { self.h64.file_alignment = v; }
    else           { self.h32.file_alignment = v; }
}

fn ushort VipeViewOptionalHeader.get_major_operating_system_version(&self)
    => self.is64 ? self.h64.major_operating_system_version : self.h32.major_operating_system_version;
fn void VipeViewOptionalHeader.set_major_operating_system_version(&self, ushort v)
{
    if (self.is64) { self.h64.major_operating_system_version = v; }
    else           { self.h32.major_operating_system_version = v; }
}

fn ushort VipeViewOptionalHeader.get_minor_operating_system_version(&self)
    => self.is64 ? self.h64.minor_operating_system_version : self.h32.minor_operating_system_version;
fn void VipeViewOptionalHeader.set_minor_operating_system_version(&self, ushort v)
{
    if (self.is64) { self.h64.minor_operating_system_version = v; }
    else           { self.h32.minor_operating_system_version = v; }
}

fn ushort VipeViewOptionalHeader.get_major_image_version(&self)
    => self.is64 ? self.h64.major_image_version : self.h32.major_image_version;
fn void VipeViewOptionalHeader.set_major_image_version(&self, ushort v)
{
    if (self.is64) { self.h64.major_image_version = v; }
    else           { self.h32.major_image_version = v; }
}

fn ushort VipeViewOptionalHeader.get_minor_image_version(&self)
    => self.is64 ? self.h64.minor_image_version : self.h32.minor_image_version;
fn void VipeViewOptionalHeader.set_minor_image_version(&self, ushort v)
{
    if (self.is64) { self.h64.minor_image_version = v; }
    else           { self.h32.minor_image_version = v; }
}

fn ushort VipeViewOptionalHeader.get_major_subsystem_version(&self)
    => self.is64 ? self.h64.major_subsystem_version : self.h32.major_subsystem_version;
fn void VipeViewOptionalHeader.set_major_subsystem_version(&self, ushort v)
{
    if (self.is64) { self.h64.major_subsystem_version = v; }
    else           { self.h32.major_subsystem_version = v; }
}

fn ushort VipeViewOptionalHeader.get_minor_subsystem_version(&self)
    => self.is64 ? self.h64.minor_subsystem_version : self.h32.minor_subsystem_version;
fn void VipeViewOptionalHeader.set_minor_subsystem_version(&self, ushort v)
{
    if (self.is64) { self.h64.minor_subsystem_version = v; }
    else           { self.h32.minor_subsystem_version = v; }
}

fn uint VipeViewOptionalHeader.get_win32_version_value(&self)
    => self.is64 ? self.h64.win32_version_value : self.h32.win32_version_value;
fn void VipeViewOptionalHeader.set_win32_version_value(&self, uint v)
{
    if (self.is64) { self.h64.win32_version_value = v; }
    else           { self.h32.win32_version_value = v; }
}

fn uint VipeViewOptionalHeader.get_size_of_image(&self)
    => self.is64 ? self.h64.size_of_image : self.h32.size_of_image;
fn void VipeViewOptionalHeader.set_size_of_image(&self, uint v)
{
    if (self.is64) { self.h64.size_of_image = v; }
    else           { self.h32.size_of_image = v; }
}

fn uint VipeViewOptionalHeader.get_size_of_headers(&self)
    => self.is64 ? self.h64.size_of_headers : self.h32.size_of_headers;
fn void VipeViewOptionalHeader.set_size_of_headers(&self, uint v)
{
    if (self.is64) { self.h64.size_of_headers = v; }
    else           { self.h32.size_of_headers = v; }
}

fn uint VipeViewOptionalHeader.get_check_sum(&self)
    => self.is64 ? self.h64.check_sum : self.h32.check_sum;
fn void VipeViewOptionalHeader.set_check_sum(&self, uint v)
{
    if (self.is64) { self.h64.check_sum = v; }
    else           { self.h32.check_sum = v; }
}

fn ushort VipeViewOptionalHeader.get_subsystem(&self)
    => self.is64 ? self.h64.subsystem : self.h32.subsystem;
fn void VipeViewOptionalHeader.set_subsystem(&self, ushort v)
{
    if (self.is64) { self.h64.subsystem = v; }
    else           { self.h32.subsystem = v; }
}

fn ushort VipeViewOptionalHeader.get_dll_characteristics(&self)
    => self.is64 ? self.h64.dll_characteristics : self.h32.dll_characteristics;
fn void VipeViewOptionalHeader.set_dll_characteristics(&self, ushort v)
{
    if (self.is64) { self.h64.dll_characteristics = v; }
    else           { self.h32.dll_characteristics = v; }
}

fn ulong VipeViewOptionalHeader.get_size_of_stack_reserve(&self)
    => self.is64 ? self.h64.size_of_stack_reserve : (ulong)self.h32.size_of_stack_reserve;
fn void VipeViewOptionalHeader.set_size_of_stack_reserve(&self, ulong v)
{
    if (self.is64) { self.h64.size_of_stack_reserve = v; }
    else           { self.h32.size_of_stack_reserve = (uint)v; }
}

fn ulong VipeViewOptionalHeader.get_size_of_stack_commit(&self)
    => self.is64 ? self.h64.size_of_stack_commit : (ulong)self.h32.size_of_stack_commit;
fn void VipeViewOptionalHeader.set_size_of_stack_commit(&self, ulong v)
{
    if (self.is64) { self.h64.size_of_stack_commit = v; }
    else           { self.h32.size_of_stack_commit = (uint)v; }
}

fn ulong VipeViewOptionalHeader.get_size_of_heap_reserve(&self)
    => self.is64 ? self.h64.size_of_heap_reserve : (ulong)self.h32.size_of_heap_reserve;
fn void VipeViewOptionalHeader.set_size_of_heap_reserve(&self, ulong v)
{
    if (self.is64) { self.h64.size_of_heap_reserve = v; }
    else           { self.h32.size_of_heap_reserve = (uint)v; }
}

fn ulong VipeViewOptionalHeader.get_size_of_heap_commit(&self)
    => self.is64 ? self.h64.size_of_heap_commit : (ulong)self.h32.size_of_heap_commit;
fn void VipeViewOptionalHeader.set_size_of_heap_commit(&self, ulong v)
{
    if (self.is64) { self.h64.size_of_heap_commit = v; }
    else           { self.h32.size_of_heap_commit = (uint)v; }
}

fn uint VipeViewOptionalHeader.get_loader_flags(&self)
    => self.is64 ? self.h64.loader_flags : self.h32.loader_flags;
fn void VipeViewOptionalHeader.set_loader_flags(&self, uint v)
{
    if (self.is64) { self.h64.loader_flags = v; }
    else           { self.h32.loader_flags = v; }
}

fn uint VipeViewOptionalHeader.get_number_of_rva_and_sizes(&self)
    => self.is64 ? self.h64.number_of_rva_and_sizes : self.h32.number_of_rva_and_sizes;
fn void VipeViewOptionalHeader.set_number_of_rva_and_sizes(&self, uint v)
{
    if (self.is64) { self.h64.number_of_rva_and_sizes = v; }
    else           { self.h32.number_of_rva_and_sizes = v; }
}

// TODO: add index checking
fn VipeRawDataDirectory* VipeViewOptionalHeader.data_directory(&self, VipeDataDirectoryIndex i)
    => self.is64
        ? &self.h64.data_directory[(uint)i]
        : &self.h32.data_directory[(uint)i];
