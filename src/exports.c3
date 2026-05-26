module vipe::exports;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawExportDirectory @packed
{
    uint characteristics;
    uint time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint name_rva;
    uint base;
    uint number_of_functions;
    uint number_of_names;
    uint address_of_functions;
    uint address_of_names;
    uint address_of_name_ordinals;
}

//
// View structures definition
//

struct VipeViewExportDirectory
{
    VipeRawExportDirectory* raw;
}

fn uint VipeViewExportDirectory.get_characteristics(&self)
    => self.raw.characteristics;
fn void VipeViewExportDirectory.set_characteristics(&self, uint v)
    => self.raw.characteristics = v;

fn uint VipeViewExportDirectory.get_time_date_stamp(&self)
    => self.raw.time_date_stamp;
fn void VipeViewExportDirectory.set_time_date_stamp(&self, uint v)
    => self.raw.time_date_stamp = v;

fn ushort VipeViewExportDirectory.get_major_version(&self)
    => self.raw.major_version;
fn void VipeViewExportDirectory.set_major_version(&self, ushort v)
    => self.raw.major_version = v;

fn ushort VipeViewExportDirectory.get_minor_version(&self)
    => self.raw.minor_version;
fn void VipeViewExportDirectory.set_minor_version(&self, ushort v)
    => self.raw.minor_version = v;

fn uint VipeViewExportDirectory.get_name_rva(&self)
    => self.raw.name_rva;
fn void VipeViewExportDirectory.set_name_rva(&self, uint v)
    => self.raw.name_rva = v;

fn uint VipeViewExportDirectory.get_base(&self)
    => self.raw.base;
fn void VipeViewExportDirectory.set_base(&self, uint v)
    => self.raw.base = v;

fn uint VipeViewExportDirectory.get_number_of_functions(&self)
    => self.raw.number_of_functions;
fn void VipeViewExportDirectory.set_number_of_functions(&self, uint v)
    => self.raw.number_of_functions = v;

fn uint VipeViewExportDirectory.get_number_of_names(&self)
    => self.raw.number_of_names;
fn void VipeViewExportDirectory.set_number_of_names(&self, uint v)
    => self.raw.number_of_names = v;

fn uint VipeViewExportDirectory.get_address_of_functions(&self)
    => self.raw.address_of_functions;
fn void VipeViewExportDirectory.set_address_of_functions(&self, uint v)
    => self.raw.address_of_functions = v;

fn uint VipeViewExportDirectory.get_address_of_names(&self)
    => self.raw.address_of_names;
fn void VipeViewExportDirectory.set_address_of_names(&self, uint v)
    => self.raw.address_of_names = v;

fn uint VipeViewExportDirectory.get_address_of_name_ordinals(&self)
    => self.raw.address_of_name_ordinals;
fn void VipeViewExportDirectory.set_address_of_name_ordinals(&self, uint v)
    => self.raw.address_of_name_ordinals = v;

struct VipeViewExport
{
    ZString name;
    ushort ordinal;
    bool is_forwarder;
    union
    {
        uint rva;
        ZString forwarder;
    }
}

fn ZString VipeViewExport.get_name(&self)
    => self.name;

fn ushort VipeViewExport.get_ordinal(&self)
    => self.ordinal;
fn void VipeViewExport.set_ordinal(&self, ushort v)
    => self.ordinal = v;

fn bool VipeViewExport.is_forwarder(&self)
    => self.is_forwarder;

fn uint VipeViewExport.get_rva(&self)
    => self.rva;
fn void VipeViewExport.set_rva(&self, uint v)
    => self.rva = v;

fn ZString VipeViewExport.get_forwarder(&self)
    => self.forwarder;
fn void VipeViewExport.set_forwarder(&self, ZString v)
    => self.forwarder = v;

//
// Callbacks
//

alias VipeCallbackExport = fn bool(VipeViewExport*, any);
