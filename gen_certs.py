import argparse
from pathlib import Path

from ca import CA
from crt import CRT

# PARSER = argparse.ArgumentParser()
# PARSER.add_argument("path")


def main():
    ca = CA.generate_ca()
    # ca = CA.build_ca_from_file("ca.key", "ca.pem")
    crt = CRT.generate_crt(ca)
    return crt


if __name__ == "__main__":
    main()
