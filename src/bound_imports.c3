module vipe::bound_imports;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawBoundImportDescriptor @packed
{
    uint time_date_stamp;
    ushort offset_module_name;
    ushort number_of_module_forwarder_refs;
}

//
// View structures definition
//

struct VipeViewBoundImportDescriptor
{
    VipeRawBoundImportDescriptor* raw;
    ZString dll;
}

macro uint   VipeViewBoundImportDescriptor.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);
macro ushort VipeViewBoundImportDescriptor.number_of_module_forwarder_refs(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_module_forwarder_refs, v);

struct VipeViewBoundImport
{
    ZString dll;
    uint time_date_stamp;
    ushort number_of_module_forwarder_refs;
}

macro ZString VipeViewBoundImport.dll(&self)
    => self.dll;
macro uint    VipeViewBoundImport.time_date_stamp(&self)
    => self.time_date_stamp;
macro ushort  VipeViewBoundImport.number_of_module_forwarder_refs(&self)
    => self.number_of_module_forwarder_refs;

//
// Callbacks
//

alias VipeCallbackBoundImport = fn void?(VipeViewBoundImportDescriptor* entry, any user_data = null);
