import os
import sys
import logging
import uuid
import datetime
from flask import Flask, render_template, jsonify, request

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import config
from src.telemetry_generator import TelemetryGenerator
from src.mongo_manager import MongoManager
from src.graph_engine import GraphEngine
from src.risk_engine import RiskEngine
from src.path_analyzer import ExplainablePathAnalyzer
from src.polyglot_transaction import PolyglotTransactionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ChronoShieldApp")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.SECRET_KEY

# Initialize NoSQL Database Managers
mongo_mgr = MongoManager()
graph_eng = GraphEngine()
risk_eng = RiskEngine(graph_eng)
path_analyzer = ExplainablePathAnalyzer(graph_eng)
telemetry_gen = TelemetryGenerator()
tx_manager = PolyglotTransactionManager(mongo_mgr, graph_eng)

def seed_initial_data():
    """Seeds initial dataset so stats are populated for demonstration."""
    mongo_mgr.clear_all_telemetry()
    graph_eng.clear_graph()
    
    events = telemetry_gen.generate_enterprise_telemetry_dataset()
    mongo_mgr.insert_telemetry_batch(events)
    for evt in events:
        graph_eng.process_telemetry_event(evt)
    
    risk_eng.propagate_risk()
    logger.info(f"Initial seed completed: {len(events)} events processed into {len(graph_eng.nodes)} graph nodes.")

def load_simple_attack_scenario():
    """Seeds the canonical 6-stage APT attack scenario into MongoDB & Neo4j."""
    mongo_mgr.clear_all_telemetry()
    graph_eng.clear_graph()
    
    events = telemetry_gen.generate_apt_attack_sequence()
    mongo_mgr.insert_telemetry_batch(events)
    for evt in events:
        graph_eng.process_telemetry_event(evt)
    
    risk_eng.propagate_risk()
    logger.info(f"Loaded Simple Scenario: {len(events)} logs, {len(graph_eng.nodes)} nodes, {len(graph_eng.edges)} edges.")
    return len(events), len(graph_eng.nodes), len(graph_eng.edges)

# Seed on startup
seed_initial_data()

@app.route("/")
def index():
    return render_template("index.html")

# ==============================================================================
# SECTION 1: CORE STATS & TOPOLOGY APIS
# ==============================================================================

@app.route("/api/stats")
def api_stats():
    logs = mongo_mgr.get_all_telemetry(limit=1000)
    alerts = mongo_mgr.get_alerts()
    topology = graph_eng.get_topology()
    
    high_risk_nodes = [n for n in topology["nodes"] if n["risk_score"] >= config.RISK_ALERT_THRESHOLD]

    return jsonify({
        "status": "online",
        "mongo_connected": mongo_mgr.is_connected,
        "neo4j_connected": graph_eng.is_connected,
        "total_logs": len(logs),
        "total_nodes": len(topology["nodes"]),
        "total_edges": len(topology["edges"]),
        "high_risk_alerts": len(high_risk_nodes) + len(alerts),
        "timestamp": logs[0]["timestamp"] if logs else datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

@app.route("/api/graph")
def api_graph():
    risk_eng.propagate_risk()
    topology = graph_eng.get_topology()
    return jsonify(topology)

@app.route("/api/attack-paths")
def api_attack_paths():
    risk_eng.propagate_risk()
    paths = path_analyzer.find_explainable_attack_paths()
    return jsonify(paths)

@app.route("/api/scenario/load-simple", methods=["POST"])
def api_load_simple():
    logs_cnt, nodes_cnt, edges_cnt = load_simple_attack_scenario()
    return jsonify({
        "success": True,
        "message": f"Successfully loaded simple 6-stage attack scenario into MongoDB & Neo4j.",
        "logs_count": logs_cnt,
        "nodes_count": nodes_cnt,
        "edges_count": edges_cnt
    })

@app.route("/api/scenario/clear", methods=["POST"])
def api_clear_scenario():
    mongo_mgr.clear_all_telemetry()
    graph_eng.clear_graph()
    return jsonify({
        "success": True,
        "message": "Successfully cleared all records from MongoDB and Neo4j."
    })

# ==============================================================================
# SECTION 2: MONGODB CRUD OPERATIONS (DOCUMENT NOSQL)
# ==============================================================================

# CREATE & READ Logs
@app.route("/api/mongodb/logs", methods=["GET", "POST"])
def api_mongodb_logs():
    if request.method == "POST":
        data = request.json or {}
        event_id = data.get("event_id") or f"EVT-{uuid.uuid4().hex[:6].upper()}"
        event_type = data.get("event_type", "AUTHENTICATION")
        severity = data.get("severity", "MEDIUM")
        status = data.get("status", "OPEN")
        host_id = data.get("host_id", "HOST-FIN-01")
        user = data.get("user", "admin_user")
        ip = data.get("ip", "192.168.1.100")
        description = data.get("description", "Security event recorded via MongoDB CRUD API")

        doc = {
            "event_id": event_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "status": status,
            "host": {"host_id": host_id, "ip": ip},
            "user": {"username": user},
            "description": description
        }

        # 1. MongoDB Create: db.security_logs.insertOne(doc)
        inserted_id = mongo_mgr.insert_telemetry_log(doc)

        # 2. Also map to graph node/edge so topology stays in sync
        graph_eng.process_telemetry_event(doc)
        risk_eng.propagate_risk()

        return jsonify({
            "success": True,
            "action": "CREATE (db.security_logs.insertOne)",
            "inserted_id": inserted_id,
            "document": doc
        }), 201

    else:
        # READ: db.security_logs.find()
        limit = int(request.args.get("limit", 100))
        severity = request.args.get("severity")
        event_type = request.args.get("event_type")
        status = request.args.get("status")

        query = {}
        if severity and severity != "ALL":
            query["severity"] = severity
        if event_type and event_type != "ALL":
            query["event_type"] = event_type
        if status and status != "ALL":
            query["status"] = status

        logs = mongo_mgr.get_all_telemetry(limit=limit, query=query if query else None)
        return jsonify({
            "action": "READ (db.security_logs.find)",
            "query_used": query,
            "count": len(logs),
            "logs": logs
        })

# UPDATE & DELETE Single Log
@app.route("/api/mongodb/logs/<event_id>", methods=["PUT", "DELETE"])
def api_mongodb_log_single(event_id):
    if request.method == "PUT":
        # UPDATE: db.security_logs.updateOne({event_id: ...}, {$set: ...})
        data = request.json or {}
        update_fields = {}
        for k in ["status", "severity", "description", "event_type"]:
            if k in data:
                update_fields[k] = data[k]

        if not update_fields:
            return jsonify({"success": False, "error": "No update fields provided."}), 400

        updated = mongo_mgr.update_telemetry_log(event_id, update_fields)
        return jsonify({
            "success": updated,
            "action": "UPDATE (db.security_logs.updateOne)",
            "event_id": event_id,
            "updated_fields": update_fields
        })

    elif request.method == "DELETE":
        # DELETE: db.security_logs.deleteOne({event_id: ...})
        deleted = mongo_mgr.delete_telemetry_log(event_id)
        return jsonify({
            "success": deleted,
            "action": "DELETE (db.security_logs.deleteOne)",
            "event_id": event_id
        })

# ==============================================================================
# SECTION 3: NEO4J & CYPHER CRUD OPERATIONS (GRAPH NOSQL)
# ==============================================================================

# CREATE & READ Nodes
@app.route("/api/neo4j/nodes", methods=["GET", "POST"])
def api_neo4j_nodes():
    if request.method == "POST":
        # CREATE: CREATE (n:Label {id: ..., risk_score: ...})
        data = request.json or {}
        node_id = data.get("node_id")
        label = data.get("label", "Host")
        risk_score = float(data.get("risk_score", 20.0))
        criticality = data.get("criticality", "MEDIUM")

        if not node_id:
            return jsonify({"success": False, "error": "node_id is required"}), 400

        props = {
            "name": data.get("name", node_id.split(":")[-1]),
            "risk_score": risk_score,
            "criticality": criticality
        }

        created_node = graph_eng.add_node(node_id, label, props)
        risk_eng.propagate_risk()

        return jsonify({
            "success": True,
            "action": "CREATE NODE (Cypher: CREATE (n:Label {...}))",
            "cypher": f"CREATE (n:{label} {{id: '{node_id}', risk_score: {risk_score}}})",
            "node": created_node
        }), 201

    else:
        # READ: MATCH (n) RETURN n
        nodes_list = []
        for nid, n in graph_eng.nodes.items():
            nodes_list.append({
                "id": nid,
                "label": n["label"],
                "risk_score": n.get("risk_score", 0.0),
                "props": n.get("props", {})
            })
        return jsonify({
            "action": "READ NODES (Cypher: MATCH (n) RETURN n)",
            "count": len(nodes_list),
            "nodes": nodes_list
        })

# UPDATE & DELETE Single Node
@app.route("/api/neo4j/nodes/<node_id>", methods=["PUT", "DELETE"])
def api_neo4j_node_single(node_id):
    if request.method == "PUT":
        # UPDATE: MATCH (n {id: ...}) SET n.risk_score = ...
        data = request.json or {}
        new_risk = data.get("risk_score")
        if new_risk is not None:
            graph_eng.update_node_risk(node_id, float(new_risk))
        if "props" in data:
            graph_eng.update_node_props(node_id, data["props"])

        return jsonify({
            "success": True,
            "action": "UPDATE NODE (Cypher: MATCH (n {id: $id}) SET n.risk_score = $val)",
            "cypher": f"MATCH (n {{id: '{node_id}'}}) SET n.risk_score = {new_risk}",
            "node_id": node_id
        })

    elif request.method == "DELETE":
        # DELETE: MATCH (n {id: ...}) DETACH DELETE n
        deleted = graph_eng.delete_node(node_id)
        risk_eng.propagate_risk()
        return jsonify({
            "success": deleted,
            "action": "DELETE NODE (Cypher: MATCH (n {id: $id}) DETACH DELETE n)",
            "cypher": f"MATCH (n {{id: '{node_id}'}}) DETACH DELETE n",
            "node_id": node_id
        })

# CREATE Relationship (Edge)
@app.route("/api/neo4j/edges", methods=["POST"])
def api_neo4j_edges():
    data = request.json or {}
    source = data.get("source")
    target = data.get("target")
    rel_type = data.get("type", "CONNECTED_TO")
    timestamp = data.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

    if not source or not target:
        return jsonify({"success": False, "error": "source and target are required"}), 400

    # Ensure nodes exist
    if source not in graph_eng.nodes:
        graph_eng.add_node(source, "Host", {"risk_score": 20.0})
    if target not in graph_eng.nodes:
        graph_eng.add_node(target, "Host", {"risk_score": 20.0})

    edge = graph_eng.add_relationship(source, target, rel_type, {"timestamp": timestamp})
    risk_eng.propagate_risk()

    return jsonify({
        "success": True,
        "action": "CREATE RELATIONSHIP (Cypher: CREATE (a)-[r:TYPE]->(b))",
        "cypher": f"MATCH (a {{id: '{source}'}}), (b {{id: '{target}'}}) CREATE (a)-[r:{rel_type}]->(b)",
        "edge": edge
    }), 201

# CYPHER QUERY RUNNER
@app.route("/api/neo4j/cypher", methods=["POST"])
def api_neo4j_cypher():
    data = request.json or {}
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"success": False, "error": "Cypher query is empty"}), 400

    result = graph_eng.execute_cypher(query)
    return jsonify({
        "query": query,
        "result": result
    })

# ==============================================================================
# SECTION 4: BACKWARDS COMPATIBILITY ENDPOINTS (KEEP TESTS WORKING)
# ==============================================================================

@app.route("/api/logs")
def api_logs_legacy():
    limit = int(request.args.get("limit", 100))
    return jsonify(mongo_mgr.get_all_telemetry(limit=limit))

@app.route("/api/crud/logs", methods=["GET", "POST", "PUT", "DELETE"])
def api_crud_logs_legacy():
    if request.method == "GET":
        limit = int(request.args.get("limit", 50))
        return jsonify(mongo_mgr.get_all_telemetry(limit=limit))
    elif request.method == "POST":
        data = request.json or {}
        tx_res = tx_manager.ingest_event_with_transaction(data)
        risk_eng.propagate_risk()
        return jsonify({"success": True, "transaction": tx_res, "event": data})
    elif request.method == "PUT":
        data = request.json or {}
        event_id = data.get("event_id")
        updated = mongo_mgr.update_telemetry_log(event_id, {k: v for k, v in data.items() if k != "event_id"})
        return jsonify({"success": updated, "event_id": event_id})
    elif request.method == "DELETE":
        event_id = request.args.get("event_id")
        deleted = mongo_mgr.delete_telemetry_log(event_id)
        return jsonify({"success": deleted, "event_id": event_id})

@app.route("/api/crud/nodes", methods=["GET", "POST", "PUT", "DELETE"])
def api_crud_nodes_legacy():
    if request.method == "GET":
        return jsonify(graph_eng.get_topology()["nodes"])
    elif request.method == "POST":
        data = request.json or {}
        added = graph_eng.add_node(data.get("node_id"), data.get("label", "Host"), data.get("props", {}))
        risk_eng.propagate_risk()
        return jsonify({"success": True, "node": added})
    elif request.method == "PUT":
        data = request.json or {}
        node_id = data.get("node_id")
        updated = graph_eng.update_node_risk(node_id, float(data.get("risk_score", 50.0)))
        return jsonify({"success": updated, "node_id": node_id})
    elif request.method == "DELETE":
        node_id = request.args.get("node_id")
        deleted = graph_eng.delete_node(node_id)
        risk_eng.propagate_risk()
        return jsonify({"success": deleted, "node_id": node_id})

@app.route("/api/simulate", methods=["POST"])
def api_simulate_legacy():
    new_events = telemetry_gen.generate_apt_attack_sequence()
    for evt in new_events:
        mongo_mgr.insert_telemetry_log(evt)
        graph_eng.process_telemetry_event(evt)
    risk_eng.propagate_risk()
    paths = path_analyzer.find_explainable_attack_paths()
    return jsonify({
        "success": True,
        "message": f"Successfully simulated and ingested {len(new_events)} APT events.",
        "attack_paths_count": len(paths)
    })

# ==================== ADVANCED NOSQL API (TEST COMPATIBILITY) ====================

@app.route("/api/advanced/aggregations")
def api_advanced_aggregations():
    severity_agg = mongo_mgr.aggregate_severity_distribution()
    host_risk_agg = mongo_mgr.aggregate_host_risk_summary()
    return jsonify({
        "severity_distribution": severity_agg,
        "host_risk_summary": host_risk_agg
    })

@app.route("/api/advanced/centrality")
def api_advanced_centrality():
    risk_eng.propagate_risk()
    centrality_list = graph_eng.calculate_node_centrality()
    return jsonify(centrality_list[:15])

@app.route("/api/advanced/indexes")
def api_advanced_indexes():
    mongo_indexes = mongo_mgr.get_index_information()
    neo4j_constraints = [
        "Host.host_id IS UNIQUE (Constraint)",
        "User.username IS UNIQUE (Constraint)",
        "Process.pid_hash IS UNIQUE (Constraint)",
        "IPAddress.ip IS UNIQUE (Constraint)",
        "AUTHENTICATED_TO.timestamp (Range Index)"
    ]
    return jsonify({
        "mongodb_indexes": mongo_indexes,
        "neo4j_constraints": neo4j_constraints
    })

@app.route("/api/advanced/transaction-test", methods=["POST"])
def api_transaction_test():
    data = request.json or {}
    simulate_failure = data.get("simulate_failure", False)
    
    import uuid
    test_evt = {
        "event_id": f"EVT-TX-{uuid.uuid4().hex[:6]}",
        "timestamp": "2026-08-22T16:15:00Z",
        "event_type": "AUTHENTICATION",
        "stage": "Polyglot Transaction Test",
        "user": {"username": "tx_test_user", "domain": "CORP", "is_privileged": False},
        "host": {"host_id": "HOST-TEST-01", "hostname": "test.corp.internal", "ip": "10.0.9.9", "criticality": "MEDIUM"},
        "network": {"src_ip": "198.51.100.222", "dst_ip": "10.0.9.9", "port": 443, "protocol": "HTTPS"},
        "severity": "MEDIUM",
        "description": "Polyglot Dual-Database Transaction Consistency Test Event",
        "_simulate_failure": "graph" if simulate_failure else None
    }

    tx_res = tx_manager.ingest_event_with_transaction(test_evt)
    risk_eng.propagate_risk()

    return jsonify({
        "transaction_result": tx_res,
        "transaction_history": tx_manager.get_transaction_logs(10)
    })


if __name__ == "__main__":
    print(f"Starting ChronoShield SOC Server on http://localhost:{config.PORT}...")
    app.run(host="0.0.0.0", port=config.PORT, debug=True)
