module test::common;

import std::collections::object;
import std::encoding::json;
import std::collections::list;
import std::io;
import vipe;

fn char[] load_file(String path) @private
{
    return file::load_buffer(path, mem::new_array(char, file::get_size(path)))!!;
}

fn char[] load_binary_by_name(String name) => @pool()
{
    String path = string::tformat("./vipe-test-data/%s.bin", name);
    return file::load_buffer(path, mem::new_array(char, file::get_size(path)))!!;
}

fn char[] load_json_by_name(String name) => @pool()
{
    String path = string::tformat("./vipe-test-data/%s.json", name);
    return common::load_file(path);
}

fn void test_dos_header_equivalence(Object* json_dos_header, VipeViewDosHeader dos_header)
{
    test::eq(json_dos_header.get_ushort("e_magic")!!, dos_header.e_magic());
    test::eq(json_dos_header.get_ushort("e_cblp")!!, dos_header.e_cblp());
    test::eq(json_dos_header.get_ushort("e_cp")!!, dos_header.e_cp());
    test::eq(json_dos_header.get_ushort("e_crlc")!!, dos_header.e_crsym());
    test::eq(json_dos_header.get_ushort("e_cparhdr")!!, dos_header.e_cparhdr());
    test::eq(json_dos_header.get_ushort("e_minalloc")!!, dos_header.e_minalloc());
    test::eq(json_dos_header.get_ushort("e_maxalloc")!!, dos_header.e_maxalloc());
    test::eq(json_dos_header.get_ushort("e_ss")!!, dos_header.e_ss());
    test::eq(json_dos_header.get_ushort("e_sp")!!, dos_header.e_sp());
    test::eq(json_dos_header.get_ushort("e_csum")!!, dos_header.e_csum());
    test::eq(json_dos_header.get_ushort("e_ip")!!, dos_header.e_ip());
    test::eq(json_dos_header.get_ushort("e_cs")!!, dos_header.e_cs());
    test::eq(json_dos_header.get_ushort("e_lfarlc")!!, dos_header.e_lfarlc());
    test::eq(json_dos_header.get_ushort("e_ovno")!!, dos_header.e_ovno());
    test::eq(json_dos_header.get_ushort("e_oemid")!!, dos_header.e_oemid());
    test::eq(json_dos_header.get_ushort("e_oeminfo")!!, dos_header.e_oeminfo());
    test::eq(json_dos_header.get_int("e_lfanew")!!, dos_header.e_lfanew());
    // TODO: missing e_res and e_res2
}

fn void test_file_header_equivalence(Object* json_file_header, VipeViewFileHeader file_header)
{
    test::eq((ushort)json_file_header.get_ushort("Machine")!!,      (ushort)file_header.machine());
    test::eq(json_file_header.get_ushort("NumberOfSections")!!,     file_header.number_of_sections());
    test::eq(json_file_header.get_uint("TimeDateStamp")!!,          file_header.time_date_stamp());
    test::eq(json_file_header.get_uint("PointerToSymbolTable")!!,   file_header.pointer_to_symbol_table());
    test::eq(json_file_header.get_uint("NumberOfSymbols")!!,        file_header.number_of_symbols());
    test::eq(json_file_header.get_ushort("SizeOfOptionalHeader")!!, file_header.size_of_optional_header());
    test::eq(json_file_header.get_ushort("Characteristics")!!,      file_header.characteristics());
}

fn void test_optional_header_equivalence(Object* json_opt_header, VipeViewOptionalHeader opt_header)
{
    test::eq(json_opt_header.get_ushort("Magic")!!,                       opt_header.magic());
    test::eq((char)json_opt_header.get_char("MajorLinkerVersion")!!,      opt_header.major_linker_version());
    test::eq((char)json_opt_header.get_char("MinorLinkerVersion")!!,      opt_header.minor_linker_version());
    test::eq(json_opt_header.get_uint("SizeOfCode")!!,                    opt_header.size_of_code());
    test::eq(json_opt_header.get_uint("SizeOfInitializedData")!!,         opt_header.size_of_initialized_data());
    test::eq(json_opt_header.get_uint("SizeOfUninitializedData")!!,       opt_header.size_of_uninitialized_data());
    test::eq(json_opt_header.get_uint("AddressOfEntryPoint")!!,           opt_header.address_of_entry_point());
    test::eq(json_opt_header.get_uint("BaseOfCode")!!,                    opt_header.base_of_code());
    test::eq(json_opt_header.get_ulong("ImageBase")!!,                    opt_header.image_base());
    test::eq(json_opt_header.get_uint("SectionAlignment")!!,              opt_header.section_alignment());
    test::eq(json_opt_header.get_uint("FileAlignment")!!,                 opt_header.file_alignment());
    test::eq(json_opt_header.get_ushort("MajorOperatingSystemVersion")!!, opt_header.major_operating_system_version());
    test::eq(json_opt_header.get_ushort("MinorOperatingSystemVersion")!!, opt_header.minor_operating_system_version());
    test::eq(json_opt_header.get_ushort("MajorImageVersion")!!,           opt_header.major_image_version());
    test::eq(json_opt_header.get_ushort("MinorImageVersion")!!,           opt_header.minor_image_version());
    test::eq(json_opt_header.get_ushort("MajorSubsystemVersion")!!,       opt_header.major_subsystem_version());
    test::eq(json_opt_header.get_ushort("MinorSubsystemVersion")!!,       opt_header.minor_subsystem_version());
    test::eq(json_opt_header.get_uint("SizeOfImage")!!,                   opt_header.size_of_image());
    test::eq(json_opt_header.get_uint("SizeOfHeaders")!!,                 opt_header.size_of_headers());
    test::eq(json_opt_header.get_uint("CheckSum")!!,                      opt_header.check_sum());
    test::eq(json_opt_header.get_ushort("Subsystem")!!,                   opt_header.subsystem());
    test::eq(json_opt_header.get_ushort("DllCharacteristics")!!,          opt_header.dll_characteristics());
    test::eq(json_opt_header.get_ulong("SizeOfStackReserve")!!,           opt_header.size_of_stack_reserve());
    test::eq(json_opt_header.get_ulong("SizeOfStackCommit")!!,            opt_header.size_of_stack_commit());
    test::eq(json_opt_header.get_ulong("SizeOfHeapReserve")!!,            opt_header.size_of_heap_reserve());
    test::eq(json_opt_header.get_ulong("SizeOfHeapCommit")!!,             opt_header.size_of_heap_commit());
    test::eq(json_opt_header.get_uint("LoaderFlags")!!,                   opt_header.loader_flags());
    test::eq(json_opt_header.get_uint("NumberOfRvaAndSizes")!!,           opt_header.number_of_rva_and_sizes());
}

fn void test_pe_equivalence(String name) => @pool()
{
    char[] binary = common::load_binary_by_name(name);
    defer free(binary);
    char[] json = common::load_json_by_name(name);
    defer free(json);

    VipeViewPe view;
    view.set(binary)!!;

    Object* parsed_pe = json::tparse((String)json)!!;
    defer parsed_pe.free();

    // dos header
    test_dos_header_equivalence(parsed_pe.get("DOS_HEADER")!!, view.dos_header());

    // nt header signature
    test::eq(parsed_pe.get("NT_HEADERS").get_uint("Signature")!!, view.nt_headers().signature());

    // file header
    test_file_header_equivalence(parsed_pe.get("FILE_HEADER")!!, view.file_header());

    // optional header
    test_optional_header_equivalence(parsed_pe.get("OPTIONAL_HEADER")!!, view.optional_header());

    // Checks sections
    Object* sections = parsed_pe.get("SECTIONS")!!;

    List{VipeViewSection} sections_views;
    sections_views.init(mem);
    defer sections_views.free();

    /*
    view.foreach_section(fn (VipeViewSection* section, any user_data) {
        List{VipeViewSection}* sv = anycast(user_data, List{VipeViewSection})!!;
        sv.push(*section);
        return true;
    }, &sections_views)!!;
    assert(sections.get_len() == sections_views.len(), "The count of sections does not match");

    for (sz i = 0; i < sections.get_len(); i++)
    {
        Object* s = sections.get_at(i);
        test::eq(s.get_int("Misc")!!, );
        s.get("NumberOfLinenumbers")!!;
        s.get("PointerToLinenumbers")!!;
        s.get("Characteristics")!!;
        s.get("PointerToRelocations")!!;
        s.get("PointerToRawData")!!;
        s.get("VirtualAddress")!!;
        s.get("NumberOfRelocations")!!;
        s.get("Name")!!;
        s.get("SizeOfRawData")!!;
    }
    */

}

