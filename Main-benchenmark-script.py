#!/usr/bin/env python3
"""
Multi-run Benchmark Aggregator
Executes the benchmark multiple times and computes statistics
"""

import statistics
import json
from comparative_benchmark import ComparativeBenchmark


N_RUNS = 15


def safe_mean_std(values):
    if len(values) == 0:
        return 0, 0
    if len(values) == 1:
        return values[0], 0
    return statistics.mean(values), statistics.stdev(values)


def main():

    all_results = {
        'its': {'encoding': [], 'verify': [], 'psid': [], 'size': [], 'total': []},
        'x509': {'encoding': [], 'verify': [], 'size': [], 'total': []}
    }

    print(f"\nRunning benchmark {N_RUNS} times...\n")

    for i in range(N_RUNS):
        print(f"--- Run {i+1}/{N_RUNS} ---")

        bench = ComparativeBenchmark(n_iterations=500, n_certificates=1000)
        bench.run()

        r = bench.results

        # ITS
        all_results['its']['encoding'].append(r['its']['encoding']['mean'])
        all_results['its']['verify'].append(r['its']['verify']['mean'])
        all_results['its']['psid'].append(r['its']['psid_ssp']['mean'])
        all_results['its']['size'].append(r['its']['size']['mean'])
        all_results['its']['total'].append(r['its']['total'])

        # X.509
        all_results['x509']['encoding'].append(r['x509']['encoding']['mean'])
        all_results['x509']['verify'].append(r['x509']['verify']['mean'])
        all_results['x509']['size'].append(r['x509']['size']['mean'])
        all_results['x509']['total'].append(r['x509']['total'])

    # -----------------------------
    # Compute final stats
    # -----------------------------
    final = {
        'its': {},
        'x509': {}
    }

    for metric in all_results['its']:
        mean, std = safe_mean_std(all_results['its'][metric])
        final['its'][metric] = (mean, std)

    for metric in all_results['x509']:
        mean, std = safe_mean_std(all_results['x509'][metric])
        final['x509'][metric] = (mean, std)

    # -----------------------------
    # Print final table
    # -----------------------------
    print("\n" + "=" * 70)
    print("FINAL SUMMARY (MEAN ± STD)")
    print("=" * 70)

    print(f"{'Metric':<30} {'ITS':<20} {'X.509':<20}")
    print("-" * 70)

    def fmt(m, s):
        return f"{m:.4f} ± {s:.4f}"

    print(f"{'Encoding (ms)':<30} {fmt(*final['its']['encoding']):<20} {fmt(*final['x509']['encoding']):<20}")
    print(f"{'Verification (ms)':<30} {fmt(*final['its']['verify']):<20} {fmt(*final['x509']['verify']):<20}")
    print(f"{'PSID/SSP (ms)':<30} {fmt(*final['its']['psid']):<20} {'N/A':<20}")
    print(f"{'Size (bytes)':<30} {fmt(*final['its']['size']):<20} {fmt(*final['x509']['size']):<20}")
    print(f"{'Total (ms)':<30} {fmt(*final['its']['total']):<20} {fmt(*final['x509']['total']):<20}")

    print("-" * 70)

    # Save results
    with open("final_results.json", "w") as f:
        json.dump(final, f, indent=2)

    print("\nFinal results saved to results.json")


if __name__ == "__main__":
    main()
