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

fn ushort VipeViewDosHeader.get_e_magic(&self)       => self.raw.e_magic;
fn void VipeViewDosHeader.set_e_magic(&self, ushort v) => self.raw.e_magic = v;

fn ushort VipeViewDosHeader.get_e_cblp(&self)        => self.raw.e_cblp;
fn void VipeViewDosHeader.set_e_cblp(&self, ushort v)  => self.raw.e_cblp = v;

fn ushort VipeViewDosHeader.get_e_cp(&self)          => self.raw.e_cp;
fn void VipeViewDosHeader.set_e_cp(&self, ushort v)    => self.raw.e_cp = v;

fn ushort VipeViewDosHeader.get_e_crsym(&self)       => self.raw.e_crsym;
fn void VipeViewDosHeader.set_e_crsym(&self, ushort v) => self.raw.e_crsym = v;

fn ushort VipeViewDosHeader.get_e_cparhdr(&self)         => self.raw.e_cparhdr;
fn void VipeViewDosHeader.set_e_cparhdr(&self, ushort v)   => self.raw.e_cparhdr = v;

fn ushort VipeViewDosHeader.get_e_minalloc(&self)        => self.raw.e_minalloc;
fn void VipeViewDosHeader.set_e_minalloc(&self, ushort v)  => self.raw.e_minalloc = v;

fn ushort VipeViewDosHeader.get_e_maxalloc(&self)        => self.raw.e_maxalloc;
fn void VipeViewDosHeader.set_e_maxalloc(&self, ushort v)  => self.raw.e_maxalloc = v;

fn ushort VipeViewDosHeader.get_e_ss(&self)          => self.raw.e_ss;
fn void VipeViewDosHeader.set_e_ss(&self, ushort v)    => self.raw.e_ss = v;

fn ushort VipeViewDosHeader.get_e_sp(&self)          => self.raw.e_sp;
fn void VipeViewDosHeader.set_e_sp(&self, ushort v)    => self.raw.e_sp = v;

fn ushort VipeViewDosHeader.get_e_csum(&self)        => self.raw.e_csum;
fn void VipeViewDosHeader.set_e_csum(&self, ushort v)  => self.raw.e_csum = v;

fn ushort VipeViewDosHeader.get_e_ip(&self)          => self.raw.e_ip;
fn void VipeViewDosHeader.set_e_ip(&self, ushort v)    => self.raw.e_ip = v;

fn ushort VipeViewDosHeader.get_e_cs(&self)          => self.raw.e_cs;
fn void VipeViewDosHeader.set_e_cs(&self, ushort v)    => self.raw.e_cs = v;

fn ushort VipeViewDosHeader.get_e_lfarlc(&self)        => self.raw.e_lfarlc;
fn void VipeViewDosHeader.set_e_lfarlc(&self, ushort v)  => self.raw.e_lfarlc = v;

fn ushort VipeViewDosHeader.get_e_ovno(&self)        => self.raw.e_ovno;
fn void VipeViewDosHeader.set_e_ovno(&self, ushort v)  => self.raw.e_ovno = v;

fn ushort VipeViewDosHeader.get_e_oemid(&self)         => self.raw.e_oemid;
fn void VipeViewDosHeader.set_e_oemid(&self, ushort v)   => self.raw.e_oemid = v;

fn ushort VipeViewDosHeader.get_e_oeminfo(&self)       => self.raw.e_oeminfo;
fn void VipeViewDosHeader.set_e_oeminfo(&self, ushort v) => self.raw.e_oeminfo = v;

fn int VipeViewDosHeader.get_e_lfanew(&self)     => self.raw.e_lfanew;
fn void VipeViewDosHeader.set_e_lfanew(&self, int v) => self.raw.e_lfanew = v;
