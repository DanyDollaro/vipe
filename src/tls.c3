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
        VipeRawTlsDirectory32* raw32;
        VipeRawTlsDirectory64* raw64;
    }
}

macro ulong VipeViewTlsDirectory.raw_data_start_va(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.raw_data_start_va, v)
        : common::@exchange(self.raw32.raw_data_start_va, (uint)v);

macro ulong VipeViewTlsDirectory.raw_data_end_va(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.raw_data_end_va, v)
        : common::@exchange(self.raw32.raw_data_end_va, (uint)v);

macro ulong VipeViewTlsDirectory.address_of_index(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.address_of_index, v)
        : common::@exchange(self.raw32.address_of_index, (uint)v);

macro ulong VipeViewTlsDirectory.address_of_callbacks(&self, ulong v = ...)
    => self.is64
        ? common::@exchange(self.raw64.address_of_callbacks, v)
        : common::@exchange(self.raw32.address_of_callbacks, (uint)v);

macro uint VipeViewTlsDirectory.size_of_zero_fill(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.size_of_zero_fill, self.raw32.size_of_zero_fill, v);

macro uint VipeViewTlsDirectory.characteristics(&self, uint v = ...)
    => common::@select_exchange(self.is64, self.raw64.characteristics, self.raw32.characteristics, v);

//
// Callbacks
//

alias VipeCallbackTls = fn void?(VipeViewTlsDirectory* entry, any user_data = null);
