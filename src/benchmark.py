import sys
import os
import time
import datetime
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.mongo_manager import MongoManager
from src.graph_engine import GraphEngine
from src.risk_engine import RiskEngine
from src.path_analyzer import ExplainablePathAnalyzer
from src.telemetry_generator import TelemetryGenerator

def benchmark_ingestion_throughput():
    print("\n==================================================")
    print(" 1. BENCHMARK: TELEMETRY LOG INGESTION THROUGHPUT ")
    print("==================================================")

    mongo = MongoManager()
    gen = TelemetryGenerator()
    base_events = gen.generate_apt_attack_sequence()

    batch_sizes = [100, 1000, 5000]
    results = []

    for size in batch_sizes:
        # Scale events
        events_batch = []
        for i in range(size):
            evt = dict(random.choice(base_events))
            evt["event_id"] = f"EVT-BENCH-{i}"
            evt["timestamp"] = (datetime.datetime(2026, 8, 22, 14, 0, 0) + datetime.timedelta(seconds=i)).isoformat() + "Z"
            events_batch.append(evt)

        start_time = time.time()
        mongo.insert_telemetry_batch(events_batch)
        elapsed = time.time() - start_time

        throughput = size / max(0.0001, elapsed)
        results.append({
            "batch_size": size,
            "elapsed_sec": round(elapsed, 4),
            "throughput_eps": round(throughput, 2)
        })
        print(f"Batch Size: {size:5d} logs | Time: {elapsed:.4f}s | Throughput: {throughput:8.2f} events/sec")

    return results

def benchmark_graph_traversal_latency():
    print("\n==================================================")
    print(" 2. BENCHMARK: MULTI-HOP GRAPH TRAVERSAL LATENCY ")
    print("==================================================")

    graph = GraphEngine()
    gen = TelemetryGenerator()

    # Seed 50 attack chains into graph
    for i in range(10):
        for evt in gen.generate_apt_attack_sequence():
            # Create distinct nodes
            evt_copy = dict(evt)
            if "host" in evt_copy and isinstance(evt_copy["host"], dict):
                evt_copy["host"]["host_id"] = f"HOST-{i}-{evt_copy['host']['host_id']}"
            graph.process_telemetry_event(evt_copy)

    risk = RiskEngine(graph)
    risk.propagate_risk()
    analyzer = ExplainablePathAnalyzer(graph)

    # Benchmark path query
    start_time = time.time()
    paths = analyzer.find_explainable_attack_paths()
    elapsed_ms = (time.time() - start_time) * 1000.0

    print(f"Total Graph Nodes: {len(graph.nodes)} | Edges: {len(graph.edges)}")
    print(f"Discovered Attack Paths: {len(paths)}")
    print(f"Chronological Path Traversal Latency: {elapsed_ms:.2f} ms")

    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "paths_found": len(paths),
        "latency_ms": round(elapsed_ms, 2)
    }

if __name__ == "__main__":
    print("Running Quantitative Performance Benchmarking Suite...")
    t_results = benchmark_ingestion_throughput()
    g_results = benchmark_graph_traversal_latency()

    print("\n==================================================")
    print(" SUMMARY FOR RESUME & TECHNICAL PORTFOLIO METRICS ")
    print("==================================================")
    max_throughput = max(r["throughput_eps"] for r in t_results)
    print(f"• Peak Log Ingestion Rate: {max_throughput:,.2f} BSON Events / Sec")
    print(f"• Multi-Hop Path Query Latency: {g_results['latency_ms']} ms across {g_results['nodes']} Nodes")
    print("==================================================\n")
