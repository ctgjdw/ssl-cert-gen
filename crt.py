from OpenSSL.crypto import (
    PKey,
    X509,
    X509Extension,
    TYPE_RSA,
    FILETYPE_PEM,
    dump_certificate,
    dump_privatekey,
)

from common import CertSub

from ca import CA

# pylint: disable = invalid-name
class CRT:
    subject: CertSub
    p_key: PKey
    crt: X509
    ca: CA

    def __init__(self, ca: CA, p_key=PKey(), crt=X509(), sub=CertSub()):
        self.ca = ca
        self.p_key = p_key
        self.crt = crt
        self.subject = sub

    def generate_p_key(self, key_type: int = TYPE_RSA, bits: int = 4096) -> PKey:
        self.p_key.generate_key(key_type, bits)
        return self.p_key

    def generate_x509(
        self, subject_alt_name: str, expiry_years: int = 10, digest_type: str = "sha256"
    ):
        sub = self.crt.get_subject()
        crt = self.crt

        sub.C = self.subject.C
        sub.ST = self.subject.ST
        sub.L = self.subject.L
        sub.O = self.subject.O
        sub.OU = self.subject.OU
        sub.CN = self.subject.CN

        crt.set_serial_number(1000)
        crt.gmtime_adj_notBefore(0)
        crt.gmtime_adj_notAfter(expiry_years * 365 * 24 * 60 * 60)
        crt.set_issuer(self.ca.crt.get_subject())
        crt.set_pubkey(self.p_key)

        san = X509Extension(b"subjectAltName", False, subject_alt_name.encode("utf-8"))
        crt.add_extensions([san])

        crt.set_pubkey(self.p_key)
        crt.sign(self.ca.p_key, digest_type)

    def export_pem(
        self, key_file_name: str = "crt.key", crt_file_name: str = "crt.pem"
    ):
        with open(crt_file_name, "wt", encoding="utf-8") as crt:
            crt.write(dump_certificate(FILETYPE_PEM, self.crt).decode("utf-8"))
        with open(key_file_name, "wt", encoding="utf-8") as key:
            key.write(dump_privatekey(FILETYPE_PEM, self.p_key).decode("utf-8"))

    @classmethod
    def generate_crt(cls, ca: CA):
        crt = cls(ca)
        crt.generate_p_key()
        crt.generate_x509("DNS:nginx")
        crt.export_pem()
        return crt
