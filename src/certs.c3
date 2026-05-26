module vipe::certs;
import vipe::common;

//
// Raw structures definition
//

struct VipeRawWinCertificate @packed
{
    uint length;
    ushort revision;
    ushort certificate_type;
    char certificate;
}

//
// View structures definition
//

struct VipeViewCertificate
{
    VipeRawWinCertificate* raw;
    char[] data;
}

fn uint VipeViewCertificate.get_length(&self)
    => self.raw.length;
fn void VipeViewCertificate.set_length(&self, uint v)
    => self.raw.length = v;

fn ushort VipeViewCertificate.get_revision(&self)
    => self.raw.revision;
fn void VipeViewCertificate.set_revision(&self, ushort v)
    => self.raw.revision = v;

fn ushort VipeViewCertificate.get_certificate_type(&self)
    => self.raw.certificate_type;
fn void VipeViewCertificate.set_certificate_type(&self, ushort v)
    => self.raw.certificate_type = v;

//
// Callbacks
//

alias VipeCallbackCertificate = fn bool(VipeViewCertificate*, any);
