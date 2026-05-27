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

macro uint   VipeViewCertificate.length(&self, uint v = ...)
    => common::@exchange(#self.raw.length, v);
macro ushort VipeViewCertificate.revision(&self, ushort v = ...)
    => common::@exchange(#self.raw.revision, v);
macro ushort VipeViewCertificate.certificate_type(&self, ushort v = ...)
    => common::@exchange(#self.raw.certificate_type, v);

//
// Callbacks
//

alias VipeCallbackCertificate = fn bool(VipeViewCertificate*, any);
