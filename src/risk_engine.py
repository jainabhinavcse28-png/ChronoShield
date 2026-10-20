import math
import datetime
import config

class RiskEngine:
    """
    Dynamic Risk Propagation Engine.
    Computes cumulative risk scores across connected entity nodes using CVSS vulnerability scores,
    action event weights, and exponential time decay.
    """

    def __init__(self, graph_engine):
        self.graph = graph_engine
        self.action_weights = config.EVENT_ACTION_WEIGHTS
        self.decay_lambda = config.TIME_DECAY_LAMBDA

    def calculate_temporal_decay(self, edge_time_str, current_time_str):
        try:
            t_edge = datetime.datetime.fromisoformat(edge_time_str.replace("Z", ""))
            t_curr = datetime.datetime.fromisoformat(current_time_str.replace("Z", ""))
            hours_diff = max(0.0, (t_curr - t_edge).total_seconds() / 3600.0)
            return math.exp(-self.decay_lambda * hours_diff)
        except Exception:
            return 1.0

    def propagate_risk(self, current_time_str=None):
        """
        Executes dynamic risk propagation algorithm across all nodes in the temporal graph.
        Returns updated node risk dictionary.
        """
        if current_time_str is None:
            current_time_str = datetime.datetime(2026, 8, 22, 16, 0, 0).isoformat() + "Z"

        # 1. Initialize base risk scores for nodes
        risk_map = {}
        for nid, data in self.graph.nodes.items():
            label = data["label"]
            props = data["props"]

            base = config.BASE_RISK_SCORES.get(label, 10.0)

            # Boost base risk for high CVSS vulnerabilities or suspicious processes
            if label == "Vulnerability":
                cvss = props.get("cvss", 5.0)
                base = cvss * 10.0  # Scale 1-10 to 10-100
            elif label == "Process" and props.get("is_suspicious"):
                base += 55.0
            elif label == "User" and props.get("is_privileged"):
                base += 20.0
            elif label == "Host" and props.get("criticality") == "CRITICAL":
                base += 25.0

            risk_map[nid] = base

        # 2. Propagate risk along directed temporal edges
        # Iterative propagation (2 passes for multi-hop propagation)
        for _ in range(2):
            for edge in self.graph.edges:
                src = edge["source"]
                tgt = edge["target"]
                rel_type = edge["type"]
                t_edge = edge.get("timestamp", current_time_str)

                weight = self.action_weights.get(rel_type, 0.40)
                decay = self.calculate_temporal_decay(t_edge, current_time_str)

                src_risk = risk_map.get(src, 10.0)
                propagated_increment = src_risk * weight * decay

                # Accumulate risk on target node (capped at 100.0)
                current_tgt_risk = risk_map.get(tgt, 10.0)
                risk_map[tgt] = min(100.0, current_tgt_risk + (propagated_increment * 0.35))

        # 3. Update graph engine node states
        for nid, new_score in risk_map.items():
            if nid in self.graph.nodes:
                self.graph.nodes[nid]["risk_score"] = round(new_score, 2)

        return risk_map

if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

    from src.graph_engine import GraphEngine
    from src.telemetry_generator import TelemetryGenerator

    g = GraphEngine()
    gen = TelemetryGenerator()
    events = gen.generate_apt_attack_sequence()
    for e in events:
        g.process_telemetry_event(e)

    risk_eng = RiskEngine(g)
    results = risk_eng.propagate_risk()
    print("Risk Propagation Results:")
    for nid, score in sorted(results.items(), key=lambda x: x[1], reverse=True):
        print(f"  {nid}: {score:.2f}")
