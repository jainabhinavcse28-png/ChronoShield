import datetime

class ExplainablePathAnalyzer:
    """
    Explainable Attack Path Analyzer.
    Formulates and executes Cypher-style chronological path discovery queries
    enforcing temporal ordering (t1 <= t2 <= ... <= tn) and returns human-readable attack walkthroughs.
    """

    def __init__(self, graph_engine):
        self.graph = graph_engine

    def find_explainable_attack_paths(self):
        """
        Extracts top-risk chronological attack paths leading to critical assets.
        """
        paths = []

        # Find initial entry nodes (untrusted IP or external login)
        entry_nodes = [nid for nid, d in self.graph.nodes.items() if d["label"] in ["IPAddress", "User"]]
        # Find target critical assets
        target_nodes = [nid for nid, d in self.graph.nodes.items() if d["label"] == "Host" and d["props"].get("criticality") == "CRITICAL"]

        # Traverse graph paths using Depth-First Search (DFS) with temporal ordering constraint
        for entry in entry_nodes:
            for target in target_nodes:
                dfs_paths = self._dfs_temporal_search(entry, target, current_path=[entry], current_edges=[], last_time=None)
                paths.extend(dfs_paths)

        # Sort attack paths by cumulative risk score
        formatted_results = []
        for path_nodes, path_edges in paths:
            cum_risk = sum(self.graph.nodes[nid]["risk_score"] for nid in path_nodes if nid in self.graph.nodes)
            
            explanation_steps = []
            for idx, edge in enumerate(path_edges, 1):
                src_label = edge["source"].split(":")[1] if ":" in edge["source"] else edge["source"]
                tgt_label = edge["target"].split(":")[1] if ":" in edge["target"] else edge["target"]
                rel_type = edge["type"]
                ts = edge.get("timestamp", "N/A")
                
                step_desc = f"Step {idx} [{ts}]: {src_label} --({rel_type})--> {tgt_label}"
                explanation_steps.append(step_desc)

            formatted_results.append({
                "entry_point": entry,
                "target_asset": target,
                "path_length": len(path_edges),
                "cumulative_risk": round(cum_risk, 2),
                "nodes": path_nodes,
                "edges": path_edges,
                "timeline": explanation_steps
            })

        formatted_results.sort(key=lambda x: x["cumulative_risk"], reverse=True)
        return formatted_results[:5]  # Return top 5 highest risk paths

    def _dfs_temporal_search(self, current_node, target_node, current_path, current_edges, last_time, max_depth=6):
        if len(current_path) > max_depth:
            return []

        if current_node == target_node and len(current_edges) > 0:
            return [(list(current_path), list(current_edges))]

        results = []
        # Find outgoing edges from current_node
        outgoing = [e for e in self.graph.edges if e["source"] == current_node]

        for edge in outgoing:
            next_node = edge["target"]
            edge_time_str = edge.get("timestamp")

            # Check temporal ordering constraint (t_edge >= last_time)
            is_chronological = True
            if last_time and edge_time_str:
                try:
                    t_curr = datetime.datetime.fromisoformat(edge_time_str.replace("Z", ""))
                    t_last = datetime.datetime.fromisoformat(last_time.replace("Z", ""))
                    if t_curr < t_last:
                        is_chronological = False
                except Exception:
                    pass

            if is_chronological and next_node not in current_path:
                current_path.append(next_node)
                current_edges.append(edge)

                sub_results = self._dfs_temporal_search(next_node, target_node, current_path, current_edges, edge_time_str, max_depth)
                results.extend(sub_results)

                current_path.pop()
                current_edges.pop()

        return results

if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

    from src.graph_engine import GraphEngine
    from src.telemetry_generator import TelemetryGenerator
    from src.risk_engine import RiskEngine

    g = GraphEngine()
    gen = TelemetryGenerator()
    for e in gen.generate_apt_attack_sequence():
        g.process_telemetry_event(e)

    r = RiskEngine(g)
    r.propagate_risk()

    analyzer = ExplainablePathAnalyzer(g)
    paths = analyzer.find_explainable_attack_paths()

    print(f"Discovered {len(paths)} explainable attack paths:")
    for p in paths:
        print(f"\n--- Path Risk Score: {p['cumulative_risk']} ---")
        for step in p["timeline"]:
            print("  " + step)
