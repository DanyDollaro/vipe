module ope::tls;
import ope::common;

struct OpeRawTlsDirectory32 @packed
{
    uint raw_data_start_va;
    uint raw_data_end_va;
    uint address_of_index;
    uint address_of_callbacks;
    uint size_of_zero_fill;
    uint characteristics;
}

struct OpeRawTlsDirectory64 @packed
{
    ulong raw_data_start_va;
    ulong raw_data_end_va;
    ulong address_of_index;
    ulong address_of_callbacks;
    uint  size_of_zero_fill;
    uint  characteristics;
}

struct OpeViewTlsDirectory
{
    bool is64;
    union
    {
        OpeRawTlsDirectory32* tls32;
        OpeRawTlsDirectory64* tls64;
    }
}

macro ulong OpeViewTlsDirectory.raw_data_start_va(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.tls64.raw_data_start_va : (ulong)self.tls32.raw_data_start_va, self.is64 ? v : (uint)v);

macro ulong OpeViewTlsDirectory.raw_data_end_va(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.tls64.raw_data_end_va : (ulong)self.tls32.raw_data_end_va, self.is64 ? v : (uint)v);

macro ulong OpeViewTlsDirectory.address_of_index(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.tls64.address_of_index : (ulong)self.tls32.address_of_index, self.is64 ? v : (uint)v);

macro ulong OpeViewTlsDirectory.address_of_callbacks(&self, ulong v = ...)
    => common::@exchange(self.is64 ? self.tls64.address_of_callbacks : (ulong)self.tls32.address_of_callbacks, self.is64 ? v : (uint)v);

macro uint OpeViewTlsDirectory.size_of_zero_fill(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.tls64.size_of_zero_fill : self.tls32.size_of_zero_fill, v);

macro uint OpeViewTlsDirectory.characteristics(&self, uint v = ...)
    => common::@exchange(self.is64 ? self.tls64.characteristics : self.tls32.characteristics, v);

alias OpeTlsCallback = fn bool(OpeViewTlsDirectory*);
