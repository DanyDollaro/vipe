module ope::exports;
import ope::common;

struct OpeRawExportDirectory @packed
{
    uint   characteristics;
    uint   time_date_stamp;
    ushort major_version;
    ushort minor_version;
    uint   name_rva;
    uint   base;
    uint   number_of_functions;
    uint   number_of_names;
    uint   address_of_functions;
    uint   address_of_names;
    uint   address_of_name_ordinals;
}

struct OpeViewExportDirectory
{
    OpeRawExportDirectory* raw;
}

macro uint OpeViewExportDirectory.characteristics(&self, uint v = ...)
    => common::@exchange(self.raw.characteristics, v);

macro uint OpeViewExportDirectory.time_date_stamp(&self, uint v = ...)
    => common::@exchange(self.raw.time_date_stamp, v);

macro ushort OpeViewExportDirectory.major_version(&self, ushort v = ...)
    => common::@exchange(self.raw.major_version, v);

macro ushort OpeViewExportDirectory.minor_version(&self, ushort v = ...)
    => common::@exchange(self.raw.minor_version, v);

macro uint OpeViewExportDirectory.name_rva(&self, uint v = ...)
    => common::@exchange(self.raw.name_rva, v);

macro uint OpeViewExportDirectory.base(&self, uint v = ...)
    => common::@exchange(self.raw.base, v);

macro uint OpeViewExportDirectory.number_of_functions(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_functions, v);

macro uint OpeViewExportDirectory.number_of_names(&self, uint v = ...)
    => common::@exchange(self.raw.number_of_names, v);

macro uint OpeViewExportDirectory.address_of_functions(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_functions, v);

macro uint OpeViewExportDirectory.address_of_names(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_names, v);

macro uint OpeViewExportDirectory.address_of_name_ordinals(&self, uint v = ...)
    => common::@exchange(self.raw.address_of_name_ordinals, v);

struct OpeViewExport
{
    ZString name;
    ushort  ordinal;
    bool    is_forwarder;
    union
    {
        uint    rva;
        ZString forwarder;
    }
}

macro ZString OpeViewExport.name(&self, ZString v = ...)
    => common::@exchange(self.name, v);

macro ushort OpeViewExport.ordinal(&self, ushort v = ...)
    => common::@exchange(self.ordinal, v);

macro bool OpeViewExport.is_forwarder(&self, bool v = ...)
    => common::@exchange(self.is_forwarder, v);

macro uint OpeViewExport.rva(&self, uint v = ...)
    => common::@exchange(self.rva, v);

macro ZString OpeViewExport.forwarder(&self, ZString v = ...)
    => common::@exchange(self.forwarder, v);

alias OpeExportCallback = fn bool(OpeViewExport*);
