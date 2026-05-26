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

fn uint VipeViewBoundImportDescriptor.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewBoundImportDescriptor.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn ushort VipeViewBoundImportDescriptor.get_number_of_module_forwarder_refs(&self)
    => self.raw.number_of_module_forwarder_refs;
fn void VipeViewBoundImportDescriptor.set_number_of_module_forwarder_refs(&self, ushort v)
    => self.raw.number_of_module_forwarder_refs = v;

struct VipeViewBoundImport
{
    ZString dll;
    uint time_date_stamp;
    ushort number_of_module_forwarder_refs;
}

fn ZString VipeViewBoundImport.get_dll(&self) => self.dll;
fn uint VipeViewBoundImport.get_time_date_stamp(&self) => self.time_date_stamp;
fn ushort VipeViewBoundImport.get_number_of_module_forwarder_refs(&self) => self.number_of_module_forwarder_refs;

//
// Callbacks
//

alias VipeCallbackBoundImport = fn bool(VipeViewBoundImportDescriptor*, any);
