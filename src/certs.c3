module ope::certs;
import ope::common;

struct OpeRawWinCertificate @packed
{
    uint   length;
    ushort revision;
    ushort certificate_type;
    char   certificate;
}

struct OpeViewCertificate
{
    OpeRawWinCertificate* raw;
    char[]                data;
}

macro uint OpeViewCertificate.length(&self, uint v = ...)
    => common::@exchange(#self.raw.length, v);

macro ushort OpeViewCertificate.revision(&self, ushort v = ...)
    => common::@exchange(#self.raw.revision, v);

macro ushort OpeViewCertificate.certificate_type(&self, ushort v = ...)
    => common::@exchange(#self.raw.certificate_type, v);

alias OpeCertificateCallback = fn bool(OpeViewCertificate*);
