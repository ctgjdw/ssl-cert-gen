from argparse import ArgumentParser, Namespace

from ca import CA
from crt import CRT
from common import GenRequest

PARSER = ArgumentParser(description="Generate CA/SSL X509 Certificates and Keys from a yaml config file. "
"Generates a new CA cert to sign the certificates if a CA cert and key is not provided.")
PARSER.add_argument("input_file", help="Path to the input file, used to configure and build CA/Keys")
PARSER.add_argument("-n", "--name", metavar="", help="Name of the output SSL cert files", default="crt")
PARSER.add_argument("-c", "--ca-cert", metavar="", help="Path to the existing CA Cert File")
PARSER.add_argument("-k", "--ca-key", metavar="", help="Path to the existing CA Key File")
PARSER.add_argument("-g","--gen-ca", metavar="", help="Generate the CA cert and key only", action="store_const", const=True)


def main(args: Namespace):
    req = GenRequest.build_from_yaml(args.input_file)
    if ca_cert:=args.ca_cert and (ca_key:=args.ca_key):
        print(f"Loading CA cert {ca_cert} and {ca_key}...")
        ca = CA.build_ca_from_file(ca_cert, ca_key)
    else:
        if not req.CA:
            raise ValueError("Config yaml is missing CA configs")
        print(f"Generating CA cert...")
        ca = CA.generate_ca(req.CA)
        if args.gen_ca:
            return
    
    if not req.CRT:
        raise ValueError("Config yaml is missing CRT configs")
    print("Generating SSL cert...")
    CRT.generate_crt(ca, args.name, req.CRT)


if __name__ == "__main__":
    args = PARSER.parse_args()
    main(args)
