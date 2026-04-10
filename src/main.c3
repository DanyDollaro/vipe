module main;

import std::io;
import ope::parser;

fn void main(String[] args) => @pool()
{
    String target = args[1];

    char[] buffer = io::file::load_buffer(target,
        mem::new_array(char, io::file::get_size(target)))!!;

    OpePeView pe;
    pe.init(buffer)!!; // attach to the image

    usz old_image_base = pe.optional_header().image_base(0x1000);
    io::printfn("new image base %s, old %s",
        pe.optional_header().image_base(), old_image_base);

    OpeSection[]? sections = pe.sectionss();
    if (try sections)
    {
        foreach (&sec : sections)
        {
            io::printfn("%s", sec.name);
        }
    }

    foreach (&dir : pe.data_directories())
    {
        io::printfn("%s", dir.virtual_address);
    }

    // Syntethic imports descriptor
    if (catch err = pe.foreach_import_descriptor(fn (i) {
        io::printn(i.dll);
        return true;
    }))
    {
        io::printn("Missing import directory");
    }

    // Syntethic imports
    if (catch err = pe.foreach_import(fn (i) {
        io::printn(i.name);
        return true;
    }))
    {
        io::printn("Missing import directory");
    }

    // Syntethic exports
    if (catch err = pe.foreach_export(fn (i) {
        io::printn(i.name);
        return true;
    }))
    {
        io::printn("Missing export directory");
    }

    // Syntethic tls
    if (catch err = pe.foreach_tls_callback(fn (i) {
        io::printn(i.address);
        return true;
    }))
    {
        io::printn("Missing TLS directory");
    }

    // Syntethic delayed import
    if (catch err = pe.foreach_delayed_import(fn (i) {
        io::printn(i.name);
        return true;
    }))
    {
        io::printn("Missing delayed import directory");
    }

    // Syntethic delayed import descriptor
    if (catch err = pe.foreach_delayed_import_descriptor(fn (i) {
        io::printn(i);
        return true;
    }))
    {
        io::printn("Missing delayed import directory");
    }

    // Syntethic bound import
    if (catch err = pe.foreach_delayed_import_descriptor(fn (i) {
        io::printn(i);
        return true;
    }))
    {
        io::printn("Missing bound import directory");
    }

    // Syntethic exceptions
    if (catch err = pe.foreach_exception(fn (i) {
        io::printn(i);
        return true;
    }))
    {
        io::printn("Missing exception directory");
    }
}
