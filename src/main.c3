module main;

import std::io;
import ope;

fn void main(String[] args) => @pool()
{
    String target = args[1];

    char[] buffer = io::file::load_buffer(target,
        mem::new_array(char, io::file::get_size(target)))!!;

    OpeViewPe pe;
    pe.init(buffer)!!; // attach to the image

    OpeViewOptionalHeader opt_hdr = pe
        .nt_headers()
        .optional_header();

    ulong base = opt_hdr.image_base(0x1000);
}

