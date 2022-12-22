from pydantic import BaseModel


class CertSub(BaseModel):
    CN: str = "localhost"
    OU: str = "Org Unit"
    O: str = "Org"
    L: str = "Country"
    ST: str = "State"
    C: str = "EG"
