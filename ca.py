from OpenSSL.crypto import (
    PKey,
    X509,
    TYPE_RSA,
    FILETYPE_PEM,
    dump_certificate,
    dump_privatekey,
    load_certificate,
    load_privatekey,
)

from common import CertSub


class CA:
    subject: CertSub
    p_key: PKey
    crt: X509

    def __init__(self, p_key=PKey(), crt=X509(), sub=CertSub()):
        self.p_key = p_key
        self.crt = crt
        self.subject = sub

    def generate_p_key(self, key_type: int = TYPE_RSA, bits: int = 4096) -> PKey:
        self.p_key.generate_key(key_type, bits)
        return self.p_key

    def generate_cert(
        self, expiry_years: int = 10, digest_type: str = "sha256"
    ) -> X509:
        ca_crt = self.crt
        sub = ca_crt.get_subject()

        sub.C = self.subject.C
        sub.ST = self.subject.ST
        sub.L = self.subject.L
        sub.O = self.subject.O
        sub.OU = self.subject.OU
        sub.CN = self.subject.CN

        ca_crt.set_serial_number(1000)
        ca_crt.gmtime_adj_notBefore(0)
        ca_crt.gmtime_adj_notAfter(expiry_years * 365 * 24 * 60 * 60)
        ca_crt.set_issuer(sub)
        ca_crt.set_pubkey(self.p_key)
        ca_crt.sign(self.p_key, digest_type)
        return ca_crt

    def export_pem(self, key_file_name: str = "ca.key", crt_file_name: str = "ca.pem"):
        with open(crt_file_name, "wt", encoding="utf-8") as crt:
            crt.write(dump_certificate(FILETYPE_PEM, self.crt).decode("utf-8"))
        with open(key_file_name, "wt", encoding="utf-8") as key:
            key.write(dump_privatekey(FILETYPE_PEM, self.p_key).decode("utf-8"))

    @classmethod
    def build_ca_from_file(
        cls,
        key_file_name,
        crt_file_name,
        key_type: int = FILETYPE_PEM,
        crt_type: int = FILETYPE_PEM,
    ):
        with open(crt_file_name, "r", encoding="utf-8") as crt_file:
            crt = load_certificate(crt_type, crt_file.read())

        with open(key_file_name, "r", encoding="utf-8") as key_file:
            key = load_privatekey(key_type, key_file.read())

        return cls(key, crt)

    @classmethod
    def generate_ca(cls):
        ca = cls()
        ca.generate_p_key()
        ca.generate_cert()
        ca.export_pem()
        return ca
