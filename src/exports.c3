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

macro uint   VipeViewExportDirectory.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);
macro uint   VipeViewExportDirectory.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);
macro ushort VipeViewExportDirectory.major_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_version, v);
macro ushort VipeViewExportDirectory.minor_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_version, v);
macro uint   VipeViewExportDirectory.name_rva(&self, uint v = ...)
    => common::@exchange(self.raw.name_rva, v);
macro uint   VipeViewExportDirectory.base(&self, uint v = ...)
    => common::@exchange(self.raw.base, v);
macro uint   VipeViewExportDirectory.number_of_functions(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_functions, v);
macro uint   VipeViewExportDirectory.number_of_names(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_names, v);
macro uint   VipeViewExportDirectory.address_of_functions(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_functions, v);
macro uint   VipeViewExportDirectory.address_of_names(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_names, v);
macro uint   VipeViewExportDirectory.address_of_name_ordinals(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_name_ordinals, v);

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

macro ZString VipeViewExport.name(&self, ZString v = ...)
    => common::@exchange(self.name, v);
macro ushort  VipeViewExport.ordinal(&self, ushort v = ...)
    => common::@exchange(self.ordinal, v);
macro bool    VipeViewExport.is_forwarder(&self)
    => self.is_forwarder;
macro uint    VipeViewExport.rva(&self, uint v = ...)
    => common::@exchange(self.rva, v);
macro ZString VipeViewExport.forwarder(&self, ZString v = ...)
    => common::@exchange(self.forwarder, v);

//
// Callbacks
//

alias VipeCallbackExport = fn void?(VipeViewExport* entry, any user_data = null);
