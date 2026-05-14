module test::common;

import std::collections::object;
import std::encoding::json;
import std::io;
import ope;

fn char[] load_file(String path) @private
{
    return file::load_buffer(path, mem::new_array(char, file::get_size(path)))!!;
}

fn char[] load_binary_by_name(String name) => @pool()
{
    String path = string::tformat("./ope-test-data/%s.bin", name);
    return file::load_buffer(path, mem::new_array(char, file::get_size(path)))!!;
}

fn char[] load_json_by_name(String name) => @pool()
{
    String path = string::tformat("./ope-test-data/%s.json", name);
    return common::load_file(path);
}

fn void test_dos_header_equivalence(Object* json_dos_header, OpeViewDosHeader dos_header)
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

fn void test_nt_header_equivalence(Object* json_dos_header, OpeViewDosHeader dos_header)
{
}

fn void test_file_header_equivalence(Object* json_dos_header, OpeViewDosHeader dos_header)
{
}

fn void test_optional_header_equivalence(Object* json_dos_header, OpeViewDosHeader dos_header)
{
}

fn void test_pe_equivalence(String name) => @pool()
{
    char[] binary = common::load_binary_by_name(name);
    defer free(binary);
    char[] json = common::load_json_by_name(name);
    defer free(json);

    OpeViewPe view;
    view.init(binary)!!;

    Object* parsed_pe = json::tparse((String)json)!!;
    defer parsed_pe.free();

    test_dos_header_equivalence(parsed_pe.get("DOS_HEADER")!!, view.dos_header());

}
