import datetime
import logging
import config

try:
    from neo4j import GraphDatabase
    NEO4J_DRIVER_AVAILABLE = True
except ImportError:
    NEO4J_DRIVER_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GraphEngine")

class GraphEngine:
    """
    Temporal Graph Engine for Cyber Attack Graphs & Dynamic Risk Propagation.
    Supports Neo4j Cypher operations and high-performance in-memory graph fallback engine.
    Implements complete CRUD operations for Nodes & Relationships, Graph Centrality Algorithms,
    and Subgraph Neighborhood extraction.
    """

    def __init__(self, uri=config.NEO4J_URI, user=config.NEO4J_USER, password=config.NEO4J_PASSWORD):
        self.is_connected = False
        self.driver = None

        # Fallback In-Memory Graph Data Structures
        self.nodes = {}  # id -> {id, label, props, risk_score}
        self.edges = []  # [{source, target, type, props, timestamp}]

        if NEO4J_DRIVER_AVAILABLE:
            try:
                self.driver = GraphDatabase.driver(uri, auth=(user, password))
                self.driver.verify_connectivity()
                self.is_connected = True
                logger.info("Connected to live Neo4j instance.")
                self._init_constraints()
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j instance ({e}). Operating in Memory Graph mode.")
                self.is_connected = False
        else:
            logger.warning("neo4j driver package not installed. Operating in Memory Graph mode.")

    def _init_constraints(self):
        if not self.is_connected:
            return
        cypher_constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.host_id IS UNIQUE;",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE;",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.pid_hash IS UNIQUE;",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.ip IS UNIQUE;"
        ]
        with self.driver.session() as session:
            for query in cypher_constraints:
                try:
                    session.run(query)
                except Exception as ex:
                    logger.debug(f"Constraint creation note: {ex}")

    # ==================== GRAPH CRUD: CREATE ====================

    def add_node(self, node_id, label, props=None):
        if props is None:
            props = {}
        if "risk_score" not in props:
            props["risk_score"] = config.BASE_RISK_SCORES.get(label, 10.0)

        if node_id in self.nodes:
            self.nodes[node_id]["props"].update(props)
            if "risk_score" in props:
                self.nodes[node_id]["risk_score"] = props["risk_score"]
        else:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "props": props,
                "risk_score": props["risk_score"]
            }

        if self.is_connected:
            cypher = f"MERGE (n:{label} {{id: $node_id}}) SET n += $props"
            with self.driver.session() as session:
                session.run(cypher, node_id=node_id, props=props)
        return self.nodes[node_id]

    def add_relationship(self, source_id, target_id, rel_type, props=None):
        if props is None:
            props = {}
        edge = {
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            "props": props,
            "timestamp": props.get("timestamp")
        }
        self.edges.append(edge)

        if self.is_connected:
            cypher = f"""
            MATCH (a {{id: $source_id}}), (b {{id: $target_id}})
            CREATE (a)-[r:{rel_type} $props]->(b)
            """
            with self.driver.session() as session:
                session.run(cypher, source_id=source_id, target_id=target_id, props=props)
        return edge

    # ==================== GRAPH CRUD: READ ====================

    def get_node_by_id(self, node_id):
        if self.is_connected:
            with self.driver.session() as session:
                res = session.run("MATCH (n {id: $node_id}) RETURN n", node_id=node_id).single()
                if res:
                    return dict(res["n"])
        return self.nodes.get(node_id)

    def get_topology(self):
        """Returns JSON representation of nodes and links for web visualization."""
        nodes_list = []
        for nid, data in self.nodes.items():
            nodes_list.append({
                "id": nid,
                "label": nid.split(":")[1] if ":" in nid else nid,
                "group": data["label"],
                "risk_score": round(data["risk_score"], 2),
                "props": data["props"]
            })

        edges_list = []
        for e in self.edges:
            edges_list.append({
                "from": e["source"],
                "to": e["target"],
                "label": e["type"],
                "timestamp": e.get("timestamp", "")
            })

        return {"nodes": nodes_list, "edges": edges_list}

    def get_subgraph(self, node_id, depth=1):
        """Extracts N-hop neighborhood subgraph for a given node."""
        sub_nodes = set([node_id])
        sub_edges = []

        for _ in range(depth):
            new_nodes = set()
            for e in self.edges:
                if e["source"] in sub_nodes or e["target"] in sub_nodes:
                    new_nodes.add(e["source"])
                    new_nodes.add(e["target"])
                    if e not in sub_edges:
                        sub_edges.append(e)
            sub_nodes.update(new_nodes)

        nodes_data = [self.nodes[nid] for nid in sub_nodes if nid in self.nodes]
        return {"nodes": nodes_data, "edges": sub_edges}

    # ==================== GRAPH CRUD: UPDATE ====================

    def update_node_risk(self, node_id, new_risk):
        if node_id in self.nodes:
            self.nodes[node_id]["risk_score"] = round(new_risk, 2)
            self.nodes[node_id]["props"]["risk_score"] = round(new_risk, 2)
            if self.is_connected:
                with self.driver.session() as session:
                    session.run("MATCH (n {id: $node_id}) SET n.risk_score = $risk", node_id=node_id, risk=new_risk)
            return True
        return False

    def update_node_props(self, node_id, props):
        if node_id in self.nodes:
            self.nodes[node_id]["props"].update(props)
            if "risk_score" in props:
                self.nodes[node_id]["risk_score"] = props["risk_score"]
            if self.is_connected:
                with self.driver.session() as session:
                    session.run("MATCH (n {id: $node_id}) SET n += $props", node_id=node_id, props=props)
            return True
        return False

    # ==================== GRAPH CRUD: DELETE ====================

    def delete_node(self, node_id):
        if node_id in self.nodes:
            del self.nodes[node_id]
            self.edges = [e for e in self.edges if e["source"] != node_id and e["target"] != node_id]
            if self.is_connected:
                with self.driver.session() as session:
                    session.run("MATCH (n {id: $node_id}) DETACH DELETE n", node_id=node_id)
            return True
        return False

    def delete_relationship(self, source_id, target_id, rel_type):
        before = len(self.edges)
        self.edges = [e for e in self.edges if not (e["source"] == source_id and e["target"] == target_id and e["type"] == rel_type)]
        deleted = len(self.edges) < before

        if deleted and self.is_connected:
            cypher = f"MATCH (a {{id: $source_id}})-[r:{rel_type}]->(b {{id: $target_id}}) DELETE r"
            with self.driver.session() as session:
                session.run(cypher, source_id=source_id, target_id=target_id)
        return deleted

    def clear_graph(self):
        self.nodes = {}
        self.edges = []
        if self.is_connected:
            with self.driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")

    def execute_cypher(self, cypher_query):
        """
        Executes a Cypher query on live Neo4j, or simulates common queries in in-memory mode.
        Returns a list of records (dicts) and execution metadata.
        """
        cypher_query_clean = cypher_query.strip()

        if self.is_connected:
            try:
                with self.driver.session() as session:
                    result = session.run(cypher_query_clean)
                    records = [record.data() for record in result]
                    return {"success": True, "records": records, "count": len(records), "mode": "Live Neo4j"}
            except Exception as e:
                return {"success": False, "error": str(e), "mode": "Live Neo4j"}

        # In-Memory Cypher Simulator
        q_upper = cypher_query_clean.upper()
        records = []

        try:
            # 1. MATCH (n) WHERE n.risk_score >= ...
            if "WHERE" in q_upper and "RISK_SCORE" in q_upper:
                threshold = 70.0
                import re
                m = re.search(r'RISK_SCORE\s*(>=|>)\s*(\d+(?:\.\d+)?)', q_upper)
                if m:
                    threshold = float(m.group(2))
                for nid, n in self.nodes.items():
                    if n.get("risk_score", 0) >= threshold:
                        records.append({"n": {"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n["props"]}})

            # 2. MATCH (h:Host) or specific label
            elif "MATCH (H:HOST)" in q_upper or "(:HOST)" in q_upper:
                for nid, n in self.nodes.items():
                    if n["label"] == "Host":
                        records.append({"h": {"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n["props"]}})

            # 3. MATCH (u:User)
            elif "MATCH (U:USER)" in q_upper or "(:USER)" in q_upper:
                for nid, n in self.nodes.items():
                    if n["label"] == "User":
                        records.append({"u": {"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n["props"]}})

            # 4. MATCH path = ... RETURN path
            elif "PATH" in q_upper and "RETURN" in q_upper:
                # Return paths connecting entry nodes to critical assets
                for e in self.edges:
                    records.append({
                        "path": {
                            "source": e["source"],
                            "relationship": e["type"],
                            "target": e["target"],
                            "timestamp": e.get("timestamp", "")
                        }
                    })

            # 5. MATCH (n)-[r]->(m) RETURN n, r, m
            elif "-[R]->" in q_upper or "-[" in q_upper:
                for e in self.edges:
                    src_node = self.nodes.get(e["source"], {"id": e["source"]})
                    tgt_node = self.nodes.get(e["target"], {"id": e["target"]})
                    records.append({
                        "n": src_node,
                        "r": {"type": e["type"], "props": e.get("props", {})},
                        "m": tgt_node
                    })

            # 6. MATCH (n) RETURN n (All nodes)
            elif "MATCH (N)" in q_upper:
                for nid, n in self.nodes.items():
                    records.append({"n": {"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n["props"]}})

            # 7. Fallback: Return all nodes
            else:
                for nid, n in self.nodes.items():
                    records.append({"n": {"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n["props"]}})

            return {"success": True, "records": records, "count": len(records), "mode": "In-Memory Cypher Engine"}
        except Exception as ex:
            return {"success": False, "error": str(ex), "mode": "In-Memory Cypher Engine"}


    # ==================== ADVANCED NOSQL: GRAPH ALGORITHMS ====================

    def calculate_node_centrality(self):
        """
        Computes Degree Centrality and Risk Influence metric across graph nodes
        to isolate key bottleneck / bridge entities in attack paths.
        """
        centrality_map = {}
        for nid, data in self.nodes.items():
            in_degree = sum(1 for e in self.edges if e["target"] == nid)
            out_degree = sum(1 for e in self.edges if e["source"] == nid)
            total_degree = in_degree + out_degree

            # Risk Influence Score = Degree * Node Risk Score
            risk_influence = total_degree * data["risk_score"]

            centrality_map[nid] = {
                "node_id": nid,
                "label": nid.split(":")[1] if ":" in nid else nid,
                "group": data["label"],
                "in_degree": in_degree,
                "out_degree": out_degree,
                "total_degree": total_degree,
                "risk_score": round(data["risk_score"], 2),
                "influence_score": round(risk_influence, 2)
            }

        sorted_centrality = sorted(centrality_map.values(), key=lambda x: x["influence_score"], reverse=True)
        return sorted_centrality

    def process_telemetry_event(self, event):
        """Converts a raw telemetry JSON event into temporal graph nodes and edges."""
        evt_type = event.get("event_type")
        timestamp = event.get("timestamp")

        if evt_type == "AUTHENTICATION":
            user_data = event.get("user", {})
            host_data = event.get("host", {})
            net_data = event.get("network", {})

            u_id = f"User:{user_data.get('username')}"
            h_id = f"Host:{host_data.get('host_id')}"
            ip_id = f"IP:{net_data.get('src_ip')}"

            self.add_node(u_id, "User", {"username": user_data.get("username"), "is_privileged": user_data.get("is_privileged", False)})
            self.add_node(h_id, "Host", {"host_id": host_data.get("host_id"), "hostname": host_data.get("hostname"), "criticality": host_data.get("criticality", "MEDIUM")})
            self.add_node(ip_id, "IPAddress", {"ip": net_data.get("src_ip"), "is_external": True})

            self.add_relationship(ip_id, u_id, "AUTHENTICATED_FROM", {"timestamp": timestamp})
            self.add_relationship(u_id, h_id, "AUTHENTICATED_TO", {"timestamp": timestamp, "port": net_data.get("port")})

        elif evt_type == "PROCESS_SPAWN":
            host_data = event.get("host", {})
            proc_data = event.get("process", {})

            h_id = f"Host:{host_data.get('host_id')}"
            p_id = f"Process:{host_data.get('host_id')}_{proc_data.get('name')}_{proc_data.get('pid')}"

            self.add_node(h_id, "Host", {"host_id": host_data.get("host_id"), "hostname": host_data.get("hostname"), "criticality": host_data.get("criticality", "MEDIUM")})
            self.add_node(p_id, "Process", {
                "pid": proc_data.get("pid"),
                "name": proc_data.get("name"),
                "cmd": proc_data.get("command_line"),
                "is_suspicious": proc_data.get("is_suspicious", False)
            })

            rel = "MALICIOUS_PROCESS" if proc_data.get("is_suspicious") else "HOSTS_PROCESS"
            self.add_relationship(h_id, p_id, rel, {"timestamp": timestamp})

        elif evt_type == "VULNERABILITY_EXPLOIT":
            host_data = event.get("host", {})
            vuln_data = event.get("vulnerability", {})

            h_id = f"Host:{host_data.get('host_id')}"
            v_id = f"Vuln:{vuln_data.get('cve_id')}"

            self.add_node(h_id, "Host", {"host_id": host_data.get("host_id"), "hostname": host_data.get("hostname"), "criticality": host_data.get("criticality", "MEDIUM")})
            self.add_node(v_id, "Vulnerability", {"cve_id": vuln_data.get("cve_id"), "cvss": vuln_data.get("cvss_score")})

            self.add_relationship(h_id, v_id, "EXPLOITED_VULN", {"timestamp": timestamp, "cvss": vuln_data.get("cvss_score")})

        elif evt_type == "LATERAL_MOVEMENT":
            src_host = event.get("source_host", {})
            tgt_host = event.get("target_host", {})
            net_data = event.get("network", {})

            src_id = f"Host:{src_host.get('host_id')}"
            tgt_id = f"Host:{tgt_host.get('host_id')}"

            self.add_node(src_id, "Host", {"host_id": src_host.get("host_id")})
            self.add_node(tgt_id, "Host", {"host_id": tgt_host.get("host_id"), "criticality": tgt_host.get("criticality", "CRITICAL")})

            self.add_relationship(src_id, tgt_id, "LATERAL_MOVE_TO", {"timestamp": timestamp, "port": net_data.get("port")})

        elif evt_type == "DATA_EXFILTRATION":
            host_data = event.get("host", {})
            net_data = event.get("network", {})

            h_id = f"Host:{host_data.get('host_id')}"
            c2_id = f"IP:{net_data.get('dst_ip')}"

            self.add_node(h_id, "Host", {"host_id": host_data.get("host_id")})
            self.add_node(c2_id, "IPAddress", {"ip": net_data.get("dst_ip"), "is_external": True})

            self.add_relationship(h_id, c2_id, "DATA_EXFILTRATION", {"timestamp": timestamp, "bytes": net_data.get("bytes_transferred")})

if __name__ == "__main__":
    engine = GraphEngine()
    print(f"GraphEngine initialized. Connected: {engine.is_connected}")
