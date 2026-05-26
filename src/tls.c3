module vipe::tls;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawTlsDirectory32 @packed
{
    uint raw_data_start_va;
    uint raw_data_end_va;
    uint address_of_index;
    uint address_of_callbacks;
    uint size_of_zero_fill;
    uint characteristics;
}

struct VipeRawTlsDirectory64 @packed
{
    ulong raw_data_start_va;
    ulong raw_data_end_va;
    ulong address_of_index;
    ulong address_of_callbacks;
    uint size_of_zero_fill;
    uint characteristics;
}

//
// View structures definition
//

struct VipeViewTlsDirectory
{
    bool is64;
    union
    {
        VipeRawTlsDirectory32* tls32;
        VipeRawTlsDirectory64* tls64;
    }
}

fn ulong VipeViewTlsDirectory.get_raw_data_start_va(&self)
    => self.is64 ? self.tls64.raw_data_start_va : (ulong)self.tls32.raw_data_start_va;
fn void VipeViewTlsDirectory.set_raw_data_start_va(&self, ulong v)
{
    if (self.is64) { self.tls64.raw_data_start_va = v; }
    else           { self.tls32.raw_data_start_va = (uint)v; }
}

fn ulong VipeViewTlsDirectory.get_raw_data_end_va(&self)
    => self.is64 ? self.tls64.raw_data_end_va : (ulong)self.tls32.raw_data_end_va;
fn void VipeViewTlsDirectory.set_raw_data_end_va(&self, ulong v)
{
    if (self.is64) { self.tls64.raw_data_end_va = v; }
    else           { self.tls32.raw_data_end_va = (uint)v; }
}

fn ulong VipeViewTlsDirectory.get_address_of_index(&self)
    => self.is64 ? self.tls64.address_of_index : (ulong)self.tls32.address_of_index;
fn void VipeViewTlsDirectory.set_address_of_index(&self, ulong v)
{
    if (self.is64) { self.tls64.address_of_index = v; }
    else           { self.tls32.address_of_index = (uint)v; }
}

fn ulong VipeViewTlsDirectory.get_address_of_callbacks(&self)
    => self.is64 ? self.tls64.address_of_callbacks : (ulong)self.tls32.address_of_callbacks;
fn void VipeViewTlsDirectory.set_address_of_callbacks(&self, ulong v)
{
    if (self.is64) { self.tls64.address_of_callbacks = v; }
    else           { self.tls32.address_of_callbacks = (uint)v; }
}

fn uint VipeViewTlsDirectory.get_size_of_zero_fill(&self)
    => self.is64 ? self.tls64.size_of_zero_fill : self.tls32.size_of_zero_fill;
fn void VipeViewTlsDirectory.set_size_of_zero_fill(&self, uint v)
{
    if (self.is64) { self.tls64.size_of_zero_fill = v; }
    else           { self.tls32.size_of_zero_fill = v; }
}

fn uint VipeViewTlsDirectory.get_characteristics(&self)
    => self.is64 ? self.tls64.characteristics : self.tls32.characteristics;
fn void VipeViewTlsDirectory.set_characteristics(&self, uint v)
{
    if (self.is64) { self.tls64.characteristics = v; }
    else           { self.tls32.characteristics = v; }
}

//
// Callbacks
//

alias VipeCallbackTls = fn bool(VipeViewTlsDirectory*, any);
