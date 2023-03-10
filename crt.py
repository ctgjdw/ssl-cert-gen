from OpenSSL.crypto import (
    PKey,
    X509,
    X509Extension,
    TYPE_RSA,
    FILETYPE_PEM,
    dump_certificate,
    dump_privatekey,
)

from common import CertSub, GenCrtRequest

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

    def generate_p_key(self, req: GenCrtRequest) -> PKey:
        self.p_key.generate_key(req.resolved_p_key_type, req.p_key_bits)
        return self.p_key

    def generate_x509(
        self, req: GenCrtRequest
    ):
        sub = self.crt.get_subject()
        crt = self.crt

        sub.C = self.subject.C
        sub.ST = self.subject.ST
        sub.L = self.subject.L
        sub.O = self.subject.O
        sub.OU = self.subject.OU
        sub.CN = self.subject.CN

        crt.set_serial_number(req.serial_no)
        crt.gmtime_adj_notBefore(0)
        crt.gmtime_adj_notAfter(req.expiry_years * 365 * 24 * 60 * 60)
        crt.set_issuer(self.ca.crt.get_subject())
        crt.set_pubkey(self.p_key)

        if req.extensions and (san_str:=req.extensions.subject_alt_name):
            san = X509Extension(b"subjectAltName", False, san_str.encode("utf-8"))
            crt.add_extensions([san])

        crt.set_pubkey(self.p_key)
        crt.sign(self.ca.p_key, req.signature_alg_type)

    def export_pem(
        self, name: str
    ):
        with open(f"{name}.pem", "wt", encoding="utf-8") as crt:
            crt.write(dump_certificate(FILETYPE_PEM, self.crt).decode("utf-8"))
        with open(f"{name}.key", "wt", encoding="utf-8") as key:
            key.write(dump_privatekey(FILETYPE_PEM, self.p_key).decode("utf-8"))

    @classmethod
    def generate_crt(cls, ca: CA, name: str, req: GenCrtRequest):
        crt = cls(ca, sub=CertSub.parse_obj(req.subject))
        crt.generate_p_key(req)
        crt.generate_x509(req)
        crt.export_pem(name)
        return crt
