module ope::bound_imports;
import ope::common;

struct OpeRawBoundImportDescriptor @packed
{
    uint   time_date_stamp;
    ushort offset_module_name;
    ushort number_of_module_forwarder_refs;
}

struct OpeViewBoundImportDescriptor
{
    OpeRawBoundImportDescriptor* raw;
    ZString                      dll;
}

macro uint OpeViewBoundImportDescriptor.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro ushort OpeViewBoundImportDescriptor.number_of_module_forwarder_refs(&self, ushort v = ...)
    => common::@exchange(self.raw.number_of_module_forwarder_refs, v);

struct OpeViewBoundImport
{
    ZString dll;
    uint    time_date_stamp;
    ushort  number_of_module_forwarder_refs;
}

macro ZString OpeViewBoundImport.dll(&self, ZString v = ...)
    => common::@exchange(self.dll, v);

macro uint OpeViewBoundImport.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.time_date_stamp, v);

macro ushort OpeViewBoundImport.number_of_module_forwarder_refs(&self, ushort v = ...)
    => common::@exchange(self.number_of_module_forwarder_refs, v);

alias OpeBoundImportCallback = fn bool(OpeViewBoundImportDescriptor*);
