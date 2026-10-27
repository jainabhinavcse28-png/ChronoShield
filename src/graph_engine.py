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
        start_time = datetime.datetime.now()

        if self.is_connected:
            try:
                with self.driver.session() as session:
                    result = session.run(cypher_query_clean)
                    records = [record.data() for record in result]
                    elapsed_ms = (datetime.datetime.now() - start_time).total_seconds() * 1000.0
                    return {"success": True, "records": records, "count": len(records), "execution_time_ms": round(elapsed_ms, 2), "mode": "Live Neo4j"}
            except Exception as e:
                return {"success": False, "error": str(e), "mode": "Live Neo4j"}

        # In-Memory Cypher Simulator
        q_upper = cypher_query_clean.upper()
        records = []

        try:
            import re
            # 1. CREATE (n:Label { props })
            if q_upper.startswith("CREATE (") or "CREATE (N:" in q_upper:
                match = re.search(r'CREATE\s*\(\s*(\w+)\s*:\s*(\w+)\s*(\{.*?\})?\s*\)', cypher_query_clean, re.IGNORECASE)
                if match:
                    var_name, label, raw_props = match.groups()
                    props = {}
                    if raw_props:
                        # Simple key-value parser
                        for kv in re.findall(r'(\w+)\s*:\s*([\'"].*?[\'"]|\d+(?:\.\d+)?)', raw_props):
                            val = kv[1].strip("'\"")
                            try:
                                val = float(val) if "." in val else int(val)
                            except ValueError:
                                pass
                            props[kv[0]] = val
                    
                    node_id = props.get("id") or props.get("name") or f"{label}:{len(self.nodes)+1}"
                    new_node = self.add_node(node_id, label, props)
                    records.append({var_name: new_node})
                    elapsed_ms = (datetime.datetime.now() - start_time).total_seconds() * 1000.0
                    return {
                        "success": True,
                        "action": "CREATE",
                        "records": records,
                        "count": 1,
                        "message": f"Created node {node_id} with label :{label}",
                        "execution_time_ms": round(elapsed_ms, 2),
                        "mode": "In-Memory Cypher Engine"
                    }

            # 2. DETACH DELETE
            elif "DETACH DELETE" in q_upper:
                match = re.search(r'MATCH\s*\(\s*\w+\s*\{.*?id\s*:\s*[\'"](.*?)[\'"].*?\}\s*\)\s*DETACH\s*DELETE', cypher_query_clean, re.IGNORECASE)
                elapsed_ms = (datetime.datetime.now() - start_time).total_seconds() * 1000.0
                if match:
                    node_id = match.group(1)
                    deleted = self.delete_node(node_id)
                    return {
                        "success": True,
                        "action": "DELETE",
                        "records": [],
                        "count": 1 if deleted else 0,
                        "message": f"Deleted node {node_id} and all attached relationships",
                        "execution_time_ms": round(elapsed_ms, 2),
                        "mode": "In-Memory Cypher Engine"
                    }
                else:
                    return {"success": True, "records": [], "count": 0, "message": "Delete pattern executed.", "execution_time_ms": round(elapsed_ms, 2), "mode": "In-Memory Cypher Engine"}

            # 3. SET n.prop = ...
            elif " SET " in q_upper:
                match = re.search(r'MATCH\s*\(\s*\w+\s*\{.*?id\s*:\s*[\'"](.*?)[\'"].*?\}\s*\)\s*SET\s*(\w+)\.(\w+)\s*=\s*(.*)', cypher_query_clean, re.IGNORECASE)
                if match:
                    node_id, var, prop_name, raw_val = match.groups()
                    clean_val = raw_val.split()[0].strip("'\",")
                    try:
                        clean_val = float(clean_val) if "." in clean_val else int(clean_val)
                    except ValueError:
                        pass
                    
                    if prop_name.lower() == "risk_score":
                        self.update_node_risk(node_id, float(clean_val))
                    else:
                        self.update_node_props(node_id, {prop_name: clean_val})
                    
                    updated_node = self.get_node_by_id(node_id)
                    records.append({"n": updated_node})
                    elapsed_ms = (datetime.datetime.now() - start_time).total_seconds() * 1000.0
                    return {
                        "success": True,
                        "action": "UPDATE",
                        "records": records,
                        "count": 1,
                        "message": f"Updated property {prop_name} on node {node_id}",
                        "execution_time_ms": round(elapsed_ms, 2),
                        "mode": "In-Memory Cypher Engine"
                    }

            # 4. DEGREE CENTRALITY / COUNT AGGREGATION: MATCH (h:Host)-[r]-() RETURN h, count(r)
            elif "COUNT(" in q_upper:
                degree_map = {}
                for e in self.edges:
                    src = e["source"]
                    tgt = e["target"]
                    degree_map[src] = degree_map.get(src, 0) + 1
                    degree_map[tgt] = degree_map.get(tgt, 0) + 1
                
                sorted_degrees = sorted(degree_map.items(), key=lambda x: x[1], reverse=True)[:10]
                for nid, deg in sorted_degrees:
                    node_data = self.nodes.get(nid, {"id": nid, "label": "Entity"})
                    records.append({
                        "node_id": nid,
                        "label": node_data.get("label", "Entity"),
                        "degree_connections": deg,
                        "risk_score": node_data.get("risk_score", 0.0)
                    })

            # 5. ISOLATED NODES: WHERE NOT (n)--()
            elif "NOT (N)--()" in q_upper or "NOT (N)--" in q_upper:
                connected = set()
                for e in self.edges:
                    connected.add(e["source"])
                    connected.add(e["target"])
                for nid, n in self.nodes.items():
                    if nid not in connected:
                        records.append({"isolated_node": {"id": nid, "label": n["label"], "risk_score": n["risk_score"]}})

            # 6. SHORTEST PATH: shortestPath(...)
            elif "SHORTESTPATH" in q_upper:
                # Find shortest path from any IP to first critical Host
                paths = []
                for e in self.edges:
                    if e.get("type") in ["AUTHENTICATED_TO", "LATERAL_MOVE_TO"]:
                        records.append({
                            "shortest_path_segment": {
                                "source": e["source"],
                                "hop_type": e["type"],
                                "target": e["target"]
                            }
                        })
                        if len(records) >= 5:
                            break

            # 7. SPECIFIC RELATIONSHIP MATCH: (src)-[r:TYPE]->(dest)
            elif "-[R:" in q_upper:
                rel_match = re.search(r'-\[\s*\w*\s*:\s*(\w+)\s*\]->', cypher_query_clean, re.IGNORECASE)
                wanted_type = rel_match.group(1).upper() if rel_match else None
                for e in self.edges:
                    if wanted_type is None or e["type"].upper() == wanted_type:
                        src_node = self.nodes.get(e["source"], {"id": e["source"]})
                        tgt_node = self.nodes.get(e["target"], {"id": e["target"]})
                        records.append({
                            "source": src_node.get("props", {}).get("hostname", e["source"]),
                            "relationship": e["type"],
                            "target": tgt_node.get("props", {}).get("hostname", e["target"]),
                            "timestamp": e.get("timestamp", "")
                        })

            # 8. RISK FILTER: WHERE n.risk_score >= ...
            elif "WHERE" in q_upper and "RISK" in q_upper:
                threshold = 70.0
                m = re.search(r'RISK_SCORE\s*(>=|>)\s*(\d+(?:\.\d+)?)', q_upper)
                if m:
                    threshold = float(m.group(2))
                for nid, n in sorted(self.nodes.items(), key=lambda x: x[1].get("risk_score", 0), reverse=True):
                    if n.get("risk_score", 0) >= threshold:
                        records.append({"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n.get("props", {})})

            # 9. LABEL FILTER: MATCH (h:Host), MATCH (u:User), etc.
            elif re.search(r'MATCH\s*\(\s*\w+\s*:\s*(\w+)\s*\)', q_upper):
                lbl = re.search(r'MATCH\s*\(\s*\w+\s*:\s*(\w+)\s*\)', q_upper).group(1).capitalize()
                for nid, n in self.nodes.items():
                    if n["label"].upper() == lbl.upper():
                        records.append({"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n.get("props", {})})

            # 10. ATTACK PATH: MATCH path = ...
            elif "PATH" in q_upper and "RETURN" in q_upper:
                for e in self.edges:
                    records.append({
                        "path": {
                            "source": e["source"],
                            "relationship": e["type"],
                            "target": e["target"],
                            "timestamp": e.get("timestamp", "")
                        }
                    })

            # 11. GENERAL GRAPH TRAVERSAL: MATCH (n)-[r]->(m)
            elif "-[R]->" in q_upper or "->(" in q_upper:
                for e in self.edges[:50]:
                    src_node = self.nodes.get(e["source"], {"id": e["source"]})
                    tgt_node = self.nodes.get(e["target"], {"id": e["target"]})
                    records.append({
                        "source": src_node,
                        "relationship": e["type"],
                        "target": tgt_node
                    })

            # 12. DEFAULT FALLBACK: MATCH (n) RETURN n
            else:
                for nid, n in list(self.nodes.items())[:50]:
                    records.append({"id": nid, "label": n["label"], "risk_score": n["risk_score"], **n.get("props", {})})

            elapsed_ms = (datetime.datetime.now() - start_time).total_seconds() * 1000.0
            return {
                "success": True,
                "records": records,
                "count": len(records),
                "execution_time_ms": round(elapsed_ms, 2),
                "mode": "In-Memory Cypher Engine"
            }
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
