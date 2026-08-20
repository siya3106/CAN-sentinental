"""
High-Precision Sub-Millisecond Anomaly Detection Latency Benchmark.
Phase 2, Day 10: Performance Verification & Audit

Measures per-frame feature extraction and inference latency under load
to verify strict compliance with automotive real-time sub-millisecond constraints.
"""

import time
import numpy as np
from src.ml.features import StreamingFeatureExtractor, FEATURE_COLUMNS
from src.ml.train_isolation_forest import CANIsolationForestModel

def benchmark_inference_latency(iterations: int = 5000) -> dict:
    """
    Benchmark streaming feature extraction and Isolation Forest inference latency.
    """
    print(f"[*] Initializing latency benchmark ({iterations} iterations)...")

    # Train a baseline model for benchmark
    np.random.seed(42)
    dummy_normal = np.random.normal(loc=0.5, scale=0.1, size=(500, len(FEATURE_COLUMNS)))
    model = CANIsolationForestModel(n_estimators=100, contamination=0.03, random_state=42)
    model.fit(dummy_normal)

    extractor = StreamingFeatureExtractor(window_size=50)

    # Pre-generate random CAN test frames
    test_packets = []
    for i in range(iterations):
        can_id = int(np.random.choice([0x0A0, 0x110, 0x120, 0x180, 0x230]))
        dlc = 4
        data = bytes(np.random.randint(0, 255, size=4, dtype=np.uint8))
        ts = 1000.0 + (i * 0.01)
        test_packets.append((can_id, dlc, data, ts))

    latencies_us = []

    # Warm-up phase (100 iterations)
    for can_id, dlc, data, ts in test_packets[:100]:
        feat = extractor.extract_features(can_id, dlc, data, ts)
        _ = model.predict_single(feat)

    # Benchmark timed loop
    for can_id, dlc, data, ts in test_packets:
        t_start = time.perf_counter_ns()

        feat = extractor.extract_features(can_id, dlc, data, ts)
        pred, score = model.predict_single(feat)

        t_end = time.perf_counter_ns()
        latency_us = (t_end - t_start) / 1000.0
        latencies_us.append(latency_us)

    lat_arr = np.array(latencies_us)
    mean_lat = float(np.mean(lat_arr))
    p50_lat = float(np.percentile(lat_arr, 50))
    p95_lat = float(np.percentile(lat_arr, 95))
    p99_lat = float(np.percentile(lat_arr, 99))
    max_lat = float(np.max(lat_arr))
    min_lat = float(np.min(lat_arr))
    fps_throughput = 1000000.0 / mean_lat if mean_lat > 0 else 0.0

    results = {
        "iterations": iterations,
        "mean_latency_us": round(mean_lat, 2),
        "p50_latency_us": round(p50_lat, 2),
        "p95_latency_us": round(p95_lat, 2),
        "p99_latency_us": round(p99_lat, 2),
        "max_latency_us": round(max_lat, 2),
        "min_latency_us": round(min_lat, 2),
        "throughput_fps": round(fps_throughput, 1),
        "sub_millisecond_verified": bool(p95_lat < 1000.0)
    }

    print("\n" + "=" * 60)
    print("      CAN-Sentinel: Real-Time Inference Latency Audit")
    print("=" * 60)
    print(f"[*] Evaluated Frames       : {iterations}")
    print(f"[*] Mean Latency           : {results['mean_latency_us']} µs ({results['mean_latency_us']/1000.0:.4f} ms)")
    print(f"[*] Median Latency (p50)   : {results['p50_latency_us']} µs")
    print(f"[*] 95th Percentile (p95)  : {results['p95_latency_us']} µs")
    print(f"[*] 99th Percentile (p99)  : {results['p99_latency_us']} µs")
    print(f"[*] Max Latency            : {results['max_latency_us']} µs")
    print(f"[*] Theoretical Throughput : {results['throughput_fps']:,.0f} frames/second")
    print("-" * 60)
    if results["sub_millisecond_verified"]:
        print(f"[SUCCESS] Sub-millisecond constraint satisfied (p95 < 1.0 ms).")
    else:
        print(f"[WARNING] Latency exceeds 1.0 ms threshold.")
    print("=" * 60 + "\n")

    return results

if __name__ == "__main__":
    benchmark_inference_latency(iterations=5000)
