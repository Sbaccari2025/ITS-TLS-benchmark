#!/usr/bin/env python3
"""
X.509 Certificate Generator for Benchmarking
Generates standard X.509 certificates for comparison with ITS certificates
"""

import time
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend

class X509_Certificate:

    
    def __init__(self, key_type='ec'):
        self.key_type = key_type
        self.private_key = None
        self.public_key = None
        self.certificate = None
        
    def generate_ec_certificate(self, validity_days=365):
        """Generate ECC-based X.509 certificate (P-256)"""
        # Generate private key
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"benchmark.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Benchmark CA"),
        ])
        
        # Issuer (self-signed for benchmark)
        issuer = subject
        
        # Get current time as datetime objects
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_before = now - datetime.timedelta(hours=1)
        not_valid_after = now + datetime.timedelta(days=validity_days)
        
        # Build certificate
        self.certificate = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(self.private_key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(not_valid_before) \
            .not_valid_after(not_valid_after) \
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ) \
            .sign(self.private_key, hashes.SHA256(), default_backend())
        
        return self.private_key, self.certificate
    
    def generate_rsa_certificate(self, key_size=2048, validity_days=365):
        """Generate RSA-based X.509 certificate (typical for TLS)"""
        # Generate RSA key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"benchmark.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Benchmark CA"),
        ])
        
        issuer = subject
        
        # Get current time as datetime objects
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_before = now - datetime.timedelta(hours=1)
        not_valid_after = now + datetime.timedelta(days=validity_days)
        
        # Build certificate
        self.certificate = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(self.private_key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(not_valid_before) \
            .not_valid_after(not_valid_after) \
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ) \
            .sign(self.private_key, hashes.SHA256(), default_backend())
        
        return self.private_key, self.certificate
    
    def get_der_encoded(self):
        """Get DER encoded certificate"""
        if self.certificate:
            return self.certificate.public_bytes(serialization.Encoding.DER)
        return b''
    
    def get_pem_encoded(self):
        """Get PEM encoded certificate"""
        if self.certificate:
            return self.certificate.public_bytes(serialization.Encoding.PEM)
        return b''
    
    def get_size(self):
        """Get certificate size in bytes"""
        return len(self.get_der_encoded())

def generate_x509_certificates(n_certificates=100):
    """Generate batch of X.509 certificates for benchmarking"""
    
    certificates = []
    
    print(f"Generating {n_certificates} X.509 certificates...")
    
    for i in range(n_certificates):
        # Generate ECC certificate
        cert_ecc = X509_Certificate(key_type='ec')
        priv_ecc, cert_ecc_obj = cert_ecc.generate_ec_certificate()
        
        certificates.append({
            'id': i,
            'type': 'ec',
            'private_key': priv_ecc,
            'certificate': cert_ecc_obj,
            'der_size': len(cert_ecc.get_der_encoded()),
            'pem_size': len(cert_ecc.get_pem_encoded()),
            'der_data': cert_ecc.get_der_encoded()
        })
        
        # Generate RSA certificate
        cert_rsa = X509_Certificate(key_type='rsa')
        priv_rsa, cert_rsa_obj = cert_rsa.generate_rsa_certificate()
        
        certificates.append({
            'id': i,
            'type': 'rsa',
            'private_key': priv_rsa,
            'certificate': cert_rsa_obj,
            'der_size': len(cert_rsa.get_der_encoded()),
            'pem_size': len(cert_rsa.get_pem_encoded()),
            'der_data': cert_rsa.get_der_encoded()
        })
        
        if (i + 1) % 10 == 0:
            print(f"  Generated {i + 1} certificates")
    
    return certificates

if __name__ == '__main__':
    certs = generate_x509_certificates(100)
    
    # Statistics
    ecc_sizes = [c['der_size'] for c in certs if c['type'] == 'ec']
    rsa_sizes = [c['der_size'] for c in certs if c['type'] == 'rsa']
    print(f"\nX.509 Certificate Size Statistics:")
    print(f"  ECC (P-256): {min(ecc_sizes)} - {max(ecc_sizes)} bytes, avg: {sum(ecc_sizes)/len(ecc_sizes):.1f}")
    print(f"  RSA (2048): {min(rsa_sizes)} - {max(rsa_sizes)} bytes, avg: {sum(rsa_sizes)/len(rsa_sizes):.1f}")