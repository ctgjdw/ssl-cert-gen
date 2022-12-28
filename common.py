from typing import Literal, Optional

from pydantic import BaseModel
from OpenSSL.crypto import TYPE_RSA, TYPE_DSA
from yaml import safe_load

class CertSub(BaseModel):
    CN: str = "localhost"
    OU: str = "Org Unit"
    O: str = "Org"
    L: str = "Country"
    ST: str = "State"
    C: str = "EG"

P_KEY_TYPES = Literal["RSA", "DSA"]
P_KEY_TYPE_MAP = {
    "RSA": TYPE_RSA,
    "DSA": TYPE_DSA
}

class SslExtensions(BaseModel):
    subject_alt_name: Optional[str]

class BaseRequest(BaseModel):
    p_key_alg_type: P_KEY_TYPES = "RSA"
    p_key_bits: int = 4096
    serial_no: int = 1000
    expiry_years: int = 10
    signature_alg_type: str = "sha256"
    subject: CertSub

    @property
    def resolved_p_key_type(self):
        return P_KEY_TYPE_MAP[self.p_key_alg_type]

    @staticmethod
    def read_from_yaml(file_name: str):
        with open(file_name, mode="r", encoding="utf8") as file:
            req = safe_load(file)
        return req

class GenCaRequest(BaseRequest):
    pass

class GenCrtRequest(BaseRequest):
    extensions: Optional[SslExtensions]

class GenRequest(BaseModel):
    CA: Optional[GenCaRequest]
    CRT: Optional[GenCrtRequest]

    @classmethod
    def build_from_yaml(cls, file_name: str):
        req = BaseRequest.read_from_yaml(file_name)
        return cls.parse_obj(req)
