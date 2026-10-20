import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.telemetry_generator import TelemetryGenerator
from src.mongo_manager import MongoManager
from src.graph_engine import GraphEngine
from src.risk_engine import RiskEngine
from src.path_analyzer import ExplainablePathAnalyzer
from src.polyglot_transaction import PolyglotTransactionManager
from app import app

class TestCyberAttackGraphSystem(unittest.TestCase):

    def setUp(self):
        self.telemetry_gen = TelemetryGenerator()
        self.mongo_mgr = MongoManager()
        self.graph_eng = GraphEngine()
        self.risk_eng = RiskEngine(self.graph_eng)
        self.path_analyzer = ExplainablePathAnalyzer(self.graph_eng)
        self.tx_manager = PolyglotTransactionManager(self.mongo_mgr, self.graph_eng)
        self.client = app.test_client()

    def test_01_telemetry_generator_50_plus_dataset(self):
        events = self.telemetry_gen.generate_enterprise_telemetry_dataset()
        self.assertGreaterEqual(len(events), 50, "Dataset must contain at least 50 sample records.")
        self.assertEqual(events[0]["event_type"], "AUTHENTICATION")

    def test_02_mongo_crud_operations(self):
        events = self.telemetry_gen.generate_enterprise_telemetry_dataset()
        inserted_ids = self.mongo_mgr.insert_telemetry_batch(events)
        self.assertEqual(len(inserted_ids), len(events))
        
        # Read
        logs = self.mongo_mgr.get_all_telemetry(limit=100)
        self.assertGreaterEqual(len(logs), 50, "MongoDB must contain at least 50 telemetry documents.")

        # Single Read
        single_evt = self.mongo_mgr.get_telemetry_by_id(events[0]["event_id"])
        self.assertIsNotNone(single_evt)

        # Update
        updated = self.mongo_mgr.update_telemetry_log(events[0]["event_id"], {"severity": "CRITICAL"})
        self.assertTrue(updated)
        updated_log = self.mongo_mgr.get_telemetry_by_id(events[0]["event_id"])
        self.assertEqual(updated_log["severity"], "CRITICAL")

        # Delete
        deleted = self.mongo_mgr.delete_telemetry_log(events[0]["event_id"])
        self.assertTrue(deleted)
        self.assertIsNone(self.mongo_mgr.get_telemetry_by_id(events[0]["event_id"]))

    def test_03_graph_crud_and_50_nodes(self):
        events = self.telemetry_gen.generate_enterprise_telemetry_dataset()
        for evt in events:
            self.graph_eng.process_telemetry_event(evt)

        topology = self.graph_eng.get_topology()
        self.assertGreaterEqual(len(topology["nodes"]), 50, "Graph engine must create at least 50 graph nodes.")
        self.assertGreater(len(topology["edges"]), 0)

        # Update Node Risk
        test_node_id = topology["nodes"][0]["id"]
        updated = self.graph_eng.update_node_risk(test_node_id, 99.9)
        self.assertTrue(updated)
        self.assertEqual(self.graph_eng.nodes[test_node_id]["risk_score"], 99.9)

        # Delete Node
        deleted = self.graph_eng.delete_node(test_node_id)
        self.assertTrue(deleted)
        self.assertNotIn(test_node_id, self.graph_eng.nodes)

    def test_04_advanced_nosql_aggregations(self):
        events = self.telemetry_gen.generate_enterprise_telemetry_dataset()
        self.mongo_mgr.insert_telemetry_batch(events)

        severity_agg = self.mongo_mgr.aggregate_severity_distribution()
        self.assertGreater(len(severity_agg), 0)
        self.assertIn("severity", severity_agg[0])
        self.assertIn("count", severity_agg[0])

        host_risk_agg = self.mongo_mgr.aggregate_host_risk_summary()
        self.assertGreater(len(host_risk_agg), 0)

    def test_05_graph_centrality_and_path_traversal(self):
        events = self.telemetry_gen.generate_enterprise_telemetry_dataset()
        for evt in events:
            self.graph_eng.process_telemetry_event(evt)
        self.risk_eng.propagate_risk()

        centrality = self.graph_eng.calculate_node_centrality()
        self.assertGreater(len(centrality), 0)
        self.assertIn("influence_score", centrality[0])

        paths = self.path_analyzer.find_explainable_attack_paths()
        self.assertGreater(len(paths), 0)
        self.assertIn("cumulative_risk", paths[0])

    def test_06_polyglot_transaction_commit_and_rollback(self):
        test_evt = {
            "event_id": "EVT-TX-TEST-001",
            "timestamp": "2026-08-22T16:00:00Z",
            "event_type": "AUTHENTICATION",
            "user": {"username": "tx_user", "is_privileged": False},
            "host": {"host_id": "HOST-TX-01", "hostname": "tx-01.corp.internal"},
            "network": {"src_ip": "1.2.3.4"}
        }

        # Commit Test
        tx_commit = self.tx_manager.ingest_event_with_transaction(test_evt)
        self.assertEqual(tx_commit["status"], "COMMITTED")
        self.assertIsNotNone(self.mongo_mgr.get_telemetry_by_id("EVT-TX-TEST-001"))

        # Rollback Test
        test_fail_evt = {
            "event_id": "EVT-TX-FAIL-001",
            "timestamp": "2026-08-22T16:01:00Z",
            "event_type": "AUTHENTICATION",
            "_simulate_failure": "graph"
        }
        tx_rollback = self.tx_manager.ingest_event_with_transaction(test_fail_evt)
        self.assertEqual(tx_rollback["status"], "ROLLED_BACK")
        self.assertIsNone(self.mongo_mgr.get_telemetry_by_id("EVT-TX-FAIL-001"))

    def test_07_flask_api_endpoints(self):
        res_stats = self.client.get("/api/stats")
        self.assertEqual(res_stats.status_code, 200)
        self.assertGreaterEqual(res_stats.json["total_logs"], 50)
        self.assertGreaterEqual(res_stats.json["total_nodes"], 50)

        res_crud_get = self.client.get("/api/crud/logs")
        self.assertEqual(res_crud_get.status_code, 200)

        res_agg = self.client.get("/api/advanced/aggregations")
        self.assertEqual(res_agg.status_code, 200)

        res_cent = self.client.get("/api/advanced/centrality")
        self.assertEqual(res_cent.status_code, 200)

        res_idx = self.client.get("/api/advanced/indexes")
        self.assertEqual(res_idx.status_code, 200)

        res_tx = self.client.post("/api/advanced/transaction-test", json={"simulate_failure": False})
        self.assertEqual(res_tx.status_code, 200)
        self.assertEqual(res_tx.json["transaction_result"]["status"], "COMMITTED")

if __name__ == "__main__":
    unittest.main()
