#!/usr/bin/env python3
"""
ITS Certificates (ETSI TS 103 097) vs X.509 ECC Certificates
"""

import time
import statistics
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from its_certificate_generator import generate_test_certificates
from x509_certificate_generator import X509_Certificate


class ComparativeBenchmark:

    def __init__(self, n_iterations=500, n_certificates=1000):
        self.n_iterations = n_iterations
        self.n_certificates = n_certificates
        self.results = {'its': {}, 'x509': {}}

    # -------------------------------
    # Utility: safe statistics
    # -------------------------------
    def safe_stats(self, data):
        if len(data) == 0:
            return {'mean': 0, 'stdev': 0}
        if len(data) == 1:
            return {'mean': data[0], 'stdev': 0}
        return {
            'mean': statistics.mean(data),
            'stdev': statistics.stdev(data)
        }

    # -------------------------------
    # Generate X.509 ECC certificates
    # -------------------------------
    def generate_x509(self, n):
        certs = []
        for i in range(n):
            cert = X509_Certificate()
            priv, crt = cert.generate_ec_certificate()

            certs.append({
                'private_key': priv,
                'certificate': crt,
                'der_size': len(crt.public_bytes(serialization.Encoding.DER))
            })
        return certs

    # -------------------------------
    # Encoding Benchmark
    # -------------------------------
    def benchmark_encoding(self, its_certs, x509_certs):

        its_times = []
        for c in its_certs[:self.n_iterations]:
            t0 = time.perf_counter()
            _ = c['cert'].encode_oer()
            its_times.append((time.perf_counter() - t0) * 1000)

        x509_times = []
        for c in x509_certs[:self.n_iterations]:
            t0 = time.perf_counter()
            _ = c['certificate'].public_bytes(serialization.Encoding.DER)
            x509_times.append((time.perf_counter() - t0) * 1000)

        self.results['its']['encoding'] = self.safe_stats(its_times)
        self.results['x509']['encoding'] = self.safe_stats(x509_times)

    # -------------------------------
    # Signature Verification
    # -------------------------------
    def benchmark_verification(self, its_certs, x509_certs):

        msg = b"TLS handshake transcript"

        its_times = []
        for _ in its_certs[:self.n_iterations]:
            priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            pub = priv.public_key()
            sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))

            t0 = time.perf_counter()
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            its_times.append((time.perf_counter() - t0) * 1000)

        x509_times = []
        for c in x509_certs[:self.n_iterations]:
            pub = c['certificate'].public_key()
            sig = c['private_key'].sign(msg, ec.ECDSA(hashes.SHA256()))

            t0 = time.perf_counter()
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            x509_times.append((time.perf_counter() - t0) * 1000)

        self.results['its']['verify'] = self.safe_stats(its_times)
        self.results['x509']['verify'] = self.safe_stats(x509_times)

    # -------------------------------
    # PSID / SSP Validation (ITS only)
    # -------------------------------
    def benchmark_psid_ssp(self, its_certs):

        times = []

        for c in its_certs[:self.n_iterations]:
            t0 = time.perf_counter()

            its_aid = c['cert'].subject_attributes['its_aid']
            ssp = c['cert'].subject_attributes['ssp']

            # PSID validation (simple policy check)
            valid_psid = its_aid in [36, 37, 38, 39]

            # SSP validation (length constraint)
            ssp_bytes = bytes.fromhex(ssp)
            valid_ssp = len(ssp_bytes) <= 31

            _ = valid_psid and valid_ssp

            times.append((time.perf_counter() - t0) * 1000)

        self.results['its']['psid_ssp'] = self.safe_stats(times)

    # -------------------------------
    # Certificate Size
    # -------------------------------
    def benchmark_size(self, its_certs, x509_certs):

        its_sizes = [c['oer_size'] for c in its_certs]
        x509_sizes = [c['der_size'] for c in x509_certs]

        self.results['its']['size'] = self.safe_stats(its_sizes)
        self.results['x509']['size'] = self.safe_stats(x509_sizes)

    # -------------------------------
    # Total Validation Time
    # -------------------------------
    def compute_total(self):

        its_total = (
            self.results['its']['encoding']['mean'] +
            self.results['its']['verify']['mean'] +
            self.results['its']['psid_ssp']['mean']
        )

        x509_total = (
            self.results['x509']['encoding']['mean'] +
            self.results['x509']['verify']['mean']
        )

        self.results['its']['total'] = its_total
        self.results['x509']['total'] = x509_total

    # -------------------------------
    # Run Benchmark
    # -------------------------------
    def run(self):

        print("Generating certificates...")
        its_certs = generate_test_certificates(self.n_certificates)
        x509_certs = self.generate_x509(self.n_certificates)

        print("Running benchmark...")

        self.benchmark_encoding(its_certs, x509_certs)
        self.benchmark_verification(its_certs, x509_certs)
        self.benchmark_psid_ssp(its_certs)
        self.benchmark_size(its_certs, x509_certs)
        self.compute_total()

        self.print_results()

        with open("results.json", "w") as f:
            json.dump(self.results, f, indent=2)

        print("Results saved to results.json")

    # -------------------------------
    # Print Results
    # -------------------------------
    def print_results(self):

        print("\n" + "=" * 70)
        print("SUMMARY TABLE")
        print("=" * 70)

        print(f"{'Metric':<30} {'ITS':<15} {'X.509':<15}")
        print("-" * 60)

        print(f"{'Encoding (ms)':<30} {self.results['its']['encoding']['mean']:<15.4f} {self.results['x509']['encoding']['mean']:<15.4f}")
        print(f"{'Verification (ms)':<30} {self.results['its']['verify']['mean']:<15.4f} {self.results['x509']['verify']['mean']:<15.4f}")
        print(f"{'PSID/SSP (ms)':<30} {self.results['its']['psid_ssp']['mean']:<15.4f} {'N/A':<15}")
        print(f"{'Size (bytes)':<30} {self.results['its']['size']['mean']:<15.1f} {self.results['x509']['size']['mean']:<15.1f}")
        print(f"{'Total (ms)':<30} {self.results['its']['total']:<15.4f} {self.results['x509']['total']:<15.4f}")

        print("-" * 60)


# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    bench = ComparativeBenchmark(n_iterations=500, n_certificates=1000)
    bench.run()