from users_table import check_user
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime
import logging
import cProfile
import pstats
from cryptography.x509.oid import NameOID
logging.basicConfig(level=logging.INFO)


def create_private_key():
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend() #TODO explain why this backend
    )
    pem = client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("certificates/client/client_key.pem", "wb") as key_file:
        key_file.write(pem)
    logging.info("Created client_key.pem")
    return client_private_key

def generate_client_csr(client_private_key):
    csr= x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"clientVPN.example.com")])).sign(client_private_key,hashes.SHA256(), default_backend())
    with open("certificates/client/client_csr.pem", "wb") as key_file:
        key_file.write(csr.public_bytes(serialization.Encoding.PEM))

    logging.info("Created client_csr.pem")

    return csr

def sign_csr_by_ca(ca_private_key,ca_cert,csr):
    client_cert=x509.CertificateBuilder().subject_name(csr.subject)
    client_cert=client_cert.issuer_name(ca_cert.subject)
    client_cert= client_cert.public_key(csr.public_key()).serial_number(x509.random_serial_number())
    client_cert = client_cert.not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    client_cert=client_cert.sign(ca_private_key,hashes.SHA256(),default_backend())
    with open("certificates/client/client_cert.pem", "wb") as cert_file:
        cert_file.write(client_cert.public_bytes(serialization.Encoding.PEM))
    logging.info("Created client_cert.pem")
    return client_cert
def load_ca_private_key():
    with open("certificates/ca_key.pem","rb") as key_file:
        ca_private_key=serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
    return ca_private_key
def load_ca_cert():
    with open("certificates/ca_cert.pem","rb") as cert_file:
        ca_cert=x509.load_pem_x509_certificate(cert_file.read(),default_backend())
    return ca_cert
def create_all_keys():
    client_private_key=create_private_key()
    csr=generate_client_csr(client_private_key)
    ca_private_key= load_ca_private_key()
    ca_cert=load_ca_cert()
    sign_csr_by_ca(ca_private_key,ca_cert,csr)
    return open("certificates/client/client_cert.pem",mode="rb").read(),open("certificates/client/client_key.pem",mode="rb").read()


# TODO- Create CSR for the client and sign it with CA
def get_keys(username,password):
    ans= check_user(username,password)
    if ans!=0:
        return ans

if __name__=="__main__":
    with cProfile.Profile() as profile:
        create_all_keys()
    results=pstats.Stats(profile)
    results.sort_stats(pstats.SortKey.TIME)
    results.print_stats()
    results.dump_stats("results.prof")
