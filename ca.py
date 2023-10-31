''' Module Imports '''
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# import os

class KeyHandler:
    ''' Handles Key Related Operations '''
    @staticmethod
    def generate_rsa_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)

    @staticmethod
    def generate_ec_key():
        return ec.generate_private_key(curve=ec.SECP256R1())

    # Candidate for removal
    def sign_certificate(self, private_key, certificate):
        return certificate.sign(private_key, hashes.SHA256())


class CertificateHandler:
    ''' Handles Certificate Creation '''
    @staticmethod
    def create_certificate(subject, issuer, public_key, private_key, is_ca=False):
        subjected = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, subject)]
            ) if isinstance(subject, str) else subject
        issued = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, issuer)]
            ) if isinstance(issuer, str) else issuer

        cert = x509.CertificateBuilder().subject_name(subjected)
        cert = cert.issuer_name(issued)
        cert = cert.public_key(public_key)
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.utcnow())
        cert = cert.not_valid_after(datetime.utcnow() + timedelta(days=365))
        if is_ca:
            cert = cert.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)
        certificate = cert.sign(private_key, hashes.SHA256())
        return certificate


class SpecialCertificateHandler(CertificateHandler):
    ''' Acts as a container for Certificate Operations '''
    def create_crl(self):
        # Implement your CRL logic here
        pass

    def create_root(self, name, key_type="RSA"):
        if key_type == "RSA":
            key = KeyHandler.generate_rsa_key()
        else:
            key = KeyHandler.generate_ec_key()

        cert = self.create_certificate(name, name, key.public_key(), key, is_ca=True)
        return key, cert

    def create_intermediate(self, root_key, root_cert, name, key_type="RSA"):
        if key_type == "RSA":
            print('creating rsa key')
            key = KeyHandler.generate_rsa_key()
        else:
            print('creating ec key')
            key = KeyHandler.generate_ec_key()

        cert = self.create_certificate(name,
                                       root_cert.subject,
                                       key.public_key(),
                                       root_key,
                                       is_ca=True)
        return key, cert

    def create_cross_sign(self, to_be_signed_key, to_be_signed_cert, signer_key, signer_name):
        cert = self.create_certificate(to_be_signed_cert.subject,
                                       signer_name,
                                       to_be_signed_key.public_key(),
                                       signer_key)
        return cert

    def create_leaf(self, issuer_key, issuer_cert, name, key_type="RSA"):
        if key_type == "RSA":
            key = KeyHandler.generate_rsa_key()
        else:
            key = KeyHandler.generate_ec_key()

        cert = self.create_certificate(name, issuer_cert.subject, key.public_key(), issuer_key)
        return key, cert


class BoilerPlatePKI:
    ''' Test Class '''
    def __init__(self):
        self.handler = SpecialCertificateHandler()

    def run(self):
        rsa_root_key, rsa_root_cert = self.handler.create_root("RSA 4096 Root")
        ec_root_key, ec_root_cert = self.handler.create_root("EC Root", key_type="EC")

        rsa_inter_key, rsa_inter_cert = self.handler.create_intermediate(rsa_root_key, rsa_root_cert, "RSA 4096 Intermediate")
        ec_inter_key, ec_inter_cert = self.handler.create_intermediate(ec_root_key, ec_root_cert, "EC Intermediate", key_type="EC")

        rsa_leaf_key, rsa_leaf_cert = self.handler.create_leaf(rsa_inter_key, rsa_inter_cert, "RSA 4096 Leaf")
        ec_leaf_key, ec_leaf_cert = self.handler.create_leaf(ec_inter_key, ec_inter_cert, "EC Leaf", key_type="EC")

        print(rsa_inter_cert.subject)
        rsa_cross1 = self.handler.create_cross_sign(rsa_inter_key, rsa_inter_cert, ec_root_key, ec_root_cert.subject)
        rsa_cross2 = self.handler.create_cross_sign(rsa_inter_key, rsa_inter_cert, ec_inter_key, ec_inter_cert.subject)
        print(ec_inter_cert.subject)
        ec_cross1 = self.handler.create_cross_sign(ec_inter_key, ec_inter_cert, rsa_root_key, rsa_root_cert.subject)
        ec_cross2 = self.handler.create_cross_sign(ec_inter_key, ec_inter_cert, rsa_inter_key, rsa_inter_cert.subject)

        # Write assets to the filesystem
        self._write_to_file("rsa_root.pem", rsa_root_cert)
        self._write_to_file("ec_root.pem", ec_root_cert)
        self._write_to_file("rsa_intermediate.pem", rsa_inter_cert)
        self._write_to_file("ec_intermediate.pem", ec_inter_cert)
        self._write_to_file("rsa_leaf.pem", rsa_leaf_cert)
        self._write_to_file("ec_leaf.pem", ec_leaf_cert)
        self._write_to_file("rsa_root_cross.pem", rsa_cross1)
        self._write_to_file("rsa_intermediate_cross.pem", rsa_cross2)
        self._write_to_file("ec_root_cross.pem", ec_cross1)
        self._write_to_file("ec_intermediate_cross.pem", ec_cross2)

        # Verification ( Needs Fixing )
        # self._verify_chain([rsa_leaf_cert, rsa_inter_cert, rsa_root_cert])
        # self._verify_chain([ec_leaf_cert, ec_inter_cert, ec_root_cert])

    def _write_to_file(self, filename, certificate):
        with open(filename, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # def _verify_chain(self, chain):
    #     store = x509.CertificateStore()
    #     for cert in chain[1:]:
    #         store.add_cert(cert)

    #     try:
    #         store_context = x509.CertificateStoreContext(store, chain[0])
    #         store_context.verify()
    #         print(f"Verification for {chain[0].subject} succeeded!")
    #     except x509.CertificateVerificationError:
    #         print(f"Verification for {chain[0].subject} failed!")


if __name__ == "__main__":
    boilerplate = BoilerPlatePKI()
    boilerplate.run()
