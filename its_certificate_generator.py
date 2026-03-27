#!/usr/bin/env python3
"""
ETSI TS 103 097 ITS Certificate Generator
Generates test certificates conforming to ETSI TS 103 097 V1.2.1+
"""

import hashlib
import time
import os
import random
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class ITS_Certificate:
    """ETSI TS 103 097 Certificate Structure"""
    
    # Certificate types (Section 7.2 of ETSI TS 103 097)
    SUBJECT_TYPE = {
        'enrollment_credential': 0,
        'authorization_ticket': 1,
        'authorization_authority': 2,
        'enrollment_authority': 3,
        'root_ca': 4,
        'crl_signer': 5
    }
    
    # Public key algorithms (Section 7.2.2)
    PUBLIC_KEY_ALGORITHMS = {
        'ecdsa_nistp256_with_sha256': 0,
        'ecies_nistp256': 1
    }
    
    def __init__(self):
        self.version = 2  # Current version as per ETSI TS 103 097
        self.signer_info = None
        self.subject_info = None
        self.subject_attributes = {}
        self.validity_restrictions = {}
        self.signature = None
        
    def generate_random_certificate(self, cert_type='authorization_ticket'):
        """Generate a random ITS certificate with realistic test data"""
        
        # Generate ECC key pair (NIST P-256 as per ETSI)
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Serialize public key as octet string (uncompressed format)
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Subject Info
        self.subject_info = {
            'subject_type': self.SUBJECT_TYPE.get(cert_type, 1),
            'subject_name': f"vehicle_{random.randint(1, 10000)}"
        }
        
        # Subject Attributes
        self.subject_attributes = {
            'verification_key': {
                'algorithm': self.PUBLIC_KEY_ALGORITHMS['ecdsa_nistp256_with_sha256'],
                'key': public_key_bytes.hex()
            },
            'its_aid': random.choice([36, 37, 38, 39]),  # ITS Application IDs
            'ssp': bytes([random.randint(0, 255) for _ in range(8)]).hex(),
            'assurance_level': random.randint(0, 7)
        }
        
        # Validity Restrictions
        current_time = int(time.time())
        self.validity_restrictions = {
            'start_time': current_time,
            'end_time': current_time + random.choice([600, 1800, 3600, 7200])  # 10min to 2h
        }
        
        # Optional: Geographic region
        if random.choice([True, False]):
            self.validity_restrictions['region'] = {
                'type': 'circular',
                'latitude': random.uniform(-90, 90),
                'longitude': random.uniform(-180, 180),
                'radius': random.randint(100, 5000)  # meters
            }
        
        # Generate HashedId8 for the certificate (ETSI requirement)
        cert_data = self._serialize_for_hashing()
        self.hashed_id8 = hashlib.sha256(cert_data).digest()[-8:]
        
        return private_key, public_key
    
    def _serialize_for_hashing(self):
        """Serialize certificate fields for hashing (simplified OER encoding)"""
        data = b''
        data += struct.pack('>B', self.version)
        data += struct.pack('>B', self.subject_info['subject_type'])
        data += self.subject_info['subject_name'].encode()
        data += bytes.fromhex(self.subject_attributes['verification_key']['key'])
        data += struct.pack('>I', self.subject_attributes['its_aid'])
        data += bytes.fromhex(self.subject_attributes['ssp'])
        data += struct.pack('>I', self.validity_restrictions['start_time'])
        data += struct.pack('>I', self.validity_restrictions['end_time'])
        return data
    
    def encode_oer(self):
        """
        Encode certificate using Octet Encoding Rules (OER)        """
        encoded = b''
        
        # Version (1 byte)
        encoded += struct.pack('>B', self.version)
        
        # SignerInfo (simplified - just HashedId8)
        encoded += self.hashed_id8
        
        # SubjectInfo
        encoded += struct.pack('>B', self.subject_info['subject_type'])
        name_bytes = self.subject_info['subject_name'].encode()
        encoded += struct.pack('>B', len(name_bytes))
        encoded += name_bytes
        
        # SubjectAttributes
        # Verification key
        key_bytes = bytes.fromhex(self.subject_attributes['verification_key']['key'])
        encoded += struct.pack('>B', self.subject_attributes['verification_key']['algorithm'])
        encoded += struct.pack('>H', len(key_bytes))
        encoded += key_bytes
        
        # ITS-AID
        encoded += struct.pack('>I', self.subject_attributes['its_aid'])
        
        # SSP
        ssp_bytes = bytes.fromhex(self.subject_attributes['ssp'])
        encoded += struct.pack('>B', len(ssp_bytes))
        encoded += ssp_bytes
        
        # Assurance level
        encoded += struct.pack('>B', self.subject_attributes['assurance_level'])
        
        # Validity Restrictions
        encoded += struct.pack('>I', self.validity_restrictions['start_time'])
        encoded += struct.pack('>I', self.validity_restrictions['end_time'])
        
        # Region (optional)
        if 'region' in self.validity_restrictions:
            region = self.validity_restrictions['region']
            encoded += b'\x01'  # Region present
            encoded += region['type'].encode()
            encoded += struct.pack('>i', int(region['latitude'] * 1000000))
            encoded += struct.pack('>i', int(region['longitude'] * 1000000))
            encoded += struct.pack('>I', region['radius'])
        
        return encoded
    
    def encode_der(self):
        """
        Encode certificate using Distinguished Encoding Rules (DER)
        Used for X.509 compatibility comparison
        """
        # Simplified DER encoding for benchmarking
        encoded = b'\x30'  # SEQUENCE tag
        # In real DER, would include length and all fields
        encoded += self._serialize_for_hashing()
        return encoded

def generate_test_certificates(n_certificates=1000, output_dir='its_certs'):
    
    os.makedirs(output_dir, exist_ok=True)
    certificates = []
    
   # print(f"Generating {n_certificates} ITS certificates...")
    
    for i in range(n_certificates):
        cert = ITS_Certificate()
        private_key, public_key = cert.generate_random_certificate()
        
        # Generate both OER and DER encodings
        oer_data = cert.encode_oer()
        der_data = cert.encode_der()
        
        certificates.append({
            'id': i,
            'cert': cert,
            'private_key': private_key,
            'public_key': public_key,
            'oer_size': len(oer_data),
            'der_size': len(der_data),
            'oer_data': oer_data,
            'der_data': der_data
        })
        
        #if (i + 1) % 100 == 0:
            #print(f"  Generated {i + 1} certificates")
    
    # Save statistics
    oer_sizes = [c['oer_size'] for c in certificates]
    der_sizes = [c['der_size'] for c in certificates]
    
    print(f"\nCertificate Size Statistics:")
    print(f"  OER: {min(oer_sizes)} - {max(oer_sizes)} bytes, avg: {sum(oer_sizes)/len(oer_sizes):.1f}")
    print(f"  DER: {min(der_sizes)} - {max(der_sizes)} bytes, avg: {sum(der_sizes)/len(der_sizes):.1f}")
    
    return certificates

if __name__ == '__main__':
    # Generate 1000 test certificates
    certs = generate_test_certificates(1000)
    print("\nSample certificate (first):")
    print(f"  Version: {certs[0]['cert'].version}")
    print(f"  Subject: {certs[0]['cert'].subject_info['subject_name']}")
    print(f"  Validity: {certs[0]['cert'].validity_restrictions['start_time']} -> {certs[0]['cert'].validity_restrictions['end_time']}")
    print(f"  ITS-AID: {certs[0]['cert'].subject_attributes['its_aid']}")
    print(f"  OER size: {certs[0]['oer_size']} bytes")
    print(f"  DER size: {certs[0]['der_size']} bytes")