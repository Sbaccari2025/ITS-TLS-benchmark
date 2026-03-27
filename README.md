# ITS-TLS Performance Benchmark

This repository contains benchmarking tools for evaluating the performance of ITS certificates (ETSI TS 103 097) compared to X.509 ECC certificates in TLS 1.3 handshakes.

## Overview

This benchmarking suite measures:
- Certificate encoding time (OER vs DER)
- ECDSA signature verification time
- PSID/SSP permission validation (ITS-specific)
- Certificate size
- Total validation time


## Requirements

- Python 3.8 or higher
- cryptography library (version 44.0.2 or higher)


## Results

| Metric | ITS (ETSI) | X.509 ECC |
|:-------|:----------:|:---------:|
| Encoding Time (ms) | 0.0073 ± 0.0005 | 0.0097 ± 0.0003 |
| ECDSA Verification (ms) | 0.1759 ± 0.0024 | 0.1731 ± 0.0031 |
| PSID/SSP (ms) | 0.0011 ± 0.0000 | N/A |
| Certificate Size (bytes) | 123.50 ± 0.24 | 388.00 ± 0.02 |
| **Total Validation (ms)** | **0.1843 ± 0.0025** | **0.1829 ± 0.0029** |

*Values are mean ± standard deviation (n = 15).*