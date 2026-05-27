module vipe::headers::dos;
import vipe::common;

const ushort DOS_MAGIC = 0x5A4D;

//
// Raw structures definition
//

struct VipeRawDosHeader @packed
{
    ushort e_magic;
    ushort e_cblp;
    ushort e_cp;
    ushort e_crsym;
    ushort e_cparhdr;
    ushort e_minalloc;
    ushort e_maxalloc;
    ushort e_ss;
    ushort e_sp;
    ushort e_csum;
    ushort e_ip;
    ushort e_cs;
    ushort e_lfarlc;
    ushort e_ovno;
    ushort[4] e_res;
    ushort e_oemid;
    ushort e_oeminfo;
    ushort[10] e_res2;
    int e_lfanew;
}

//
// View structures definition
//

struct VipeViewDosHeader
{
    VipeRawDosHeader* raw;
}

macro ushort VipeViewDosHeader.e_magic(&self, ushort v = ...)
    => common::@exchange(self.raw.e_magic, v);

macro ushort VipeViewDosHeader.e_cblp(&self, ushort v = ...)
    => common::@exchange(self.raw.e_cblp, v);

macro ushort VipeViewDosHeader.e_cp(&self, ushort v = ...)
    => common::@exchange(self.raw.e_cp, v);

macro ushort VipeViewDosHeader.e_crsym(&self, ushort v = ...)
    => common::@exchange(self.raw.e_crsym, v);

macro ushort VipeViewDosHeader.e_cparhdr(&self, ushort v = ...)
    => common::@exchange(self.raw.e_cparhdr, v);

macro ushort VipeViewDosHeader.e_minalloc(&self, ushort v = ...)
    => common::@exchange(self.raw.e_minalloc, v);

macro ushort VipeViewDosHeader.e_maxalloc(&self, ushort v = ...)
    => common::@exchange(self.raw.e_maxalloc, v);

macro ushort VipeViewDosHeader.e_ss(&self, ushort v = ...)
    => common::@exchange(self.raw.e_ss, v);

macro ushort VipeViewDosHeader.e_sp(&self, ushort v = ...)
    => common::@exchange(self.raw.e_sp, v);

macro ushort VipeViewDosHeader.e_csum(&self, ushort v = ...)
    => common::@exchange(self.raw.e_csum, v);

macro ushort VipeViewDosHeader.e_ip(&self, ushort v = ...)
    => common::@exchange(self.raw.e_ip, v);

macro ushort VipeViewDosHeader.e_cs(&self, ushort v = ...)
    => common::@exchange(self.raw.e_cs, v);

macro ushort VipeViewDosHeader.e_lfarlc(&self, ushort v = ...)
    => common::@exchange(self.raw.e_lfarlc, v);

macro ushort VipeViewDosHeader.e_ovno(&self, ushort v = ...)
    => common::@exchange(self.raw.e_ovno, v);

macro ushort VipeViewDosHeader.e_oemid(&self, ushort v = ...)
    => common::@exchange(self.raw.e_oemid, v);

macro ushort VipeViewDosHeader.e_oeminfo(&self, ushort v = ...)
    => common::@exchange(self.raw.e_oeminfo, v);

macro int VipeViewDosHeader.e_lfanew(&self, int v = ...)
    => common::@exchange(self.raw.e_lfanew, v);
