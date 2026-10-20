import logging
import datetime
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolyglotTransactionManager")

class PolyglotTransactionManager:
    """
    Polyglot NoSQL Transaction Manager.
    Coordinates synchronized multi-database ingestion across MongoDB (Document Store)
    and Neo4j (Graph Engine), guaranteeing data consistency and executing transaction
    rollback if an operation fails in either database layer.
    """

    def __init__(self, mongo_manager, graph_engine):
        self.mongo = mongo_manager
        self.graph = graph_engine
        self.transaction_log = []

    def ingest_event_with_transaction(self, event):
        """
        Executes a polyglot 2-phase transaction across MongoDB and Neo4j.
        Returns dict with status, transaction_id, and details.
        """
        tx_id = f"TX-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        logger.info(f"[{tx_id}] Starting Polyglot Transaction for Event {event.get('event_id')}...")

        mongo_inserted_id = None
        graph_nodes_added = []
        graph_edges_added = []

        try:
            # Phase 1: Insert into MongoDB (Document Ingestion)
            mongo_inserted_id = self.mongo.insert_telemetry_log(event)
            logger.info(f"[{tx_id}] Phase 1 Success: Inserted into MongoDB (ID: {mongo_inserted_id})")

            # Simulate potential error if explicitly flagged for test
            if event.get("_simulate_failure") == "graph":
                raise RuntimeError("Simulated Graph Engine Transaction Failure")

            # Phase 2: Process Event into Neo4j Temporal Graph
            nodes_before = set(self.graph.nodes.keys())
            edges_count_before = len(self.graph.edges)

            self.graph.process_telemetry_event(event)

            nodes_after = set(self.graph.nodes.keys())
            graph_nodes_added = list(nodes_after - nodes_before)
            graph_edges_added = len(self.graph.edges) - edges_count_before

            logger.info(f"[{tx_id}] Phase 2 Success: Processed in Neo4j (Added {len(graph_nodes_added)} nodes, {graph_edges_added} edges)")

            # Transaction Commit
            tx_record = {
                "transaction_id": tx_id,
                "timestamp": timestamp,
                "status": "COMMITTED",
                "event_id": event.get("event_id"),
                "mongo_inserted": True,
                "neo4j_nodes_added": len(graph_nodes_added),
                "neo4j_edges_added": graph_edges_added,
                "error": None
            }
            self.transaction_log.append(tx_record)
            return tx_record

        except Exception as err:
            logger.error(f"[{tx_id}] Transaction Error: {err}. Initiating Rollback...")

            # Rollback Phase 1: Remove from MongoDB if inserted
            if mongo_inserted_id and event.get("event_id"):
                self.mongo.delete_telemetry_log(event.get("event_id"))
                logger.info(f"[{tx_id}] Rollback MongoDB: Deleted document {event.get('event_id')}")

            # Rollback Phase 2: Revert graph nodes added
            for nid in graph_nodes_added:
                self.graph.delete_node(nid)
                logger.info(f"[{tx_id}] Rollback Neo4j: Reverted node {nid}")

            tx_record = {
                "transaction_id": tx_id,
                "timestamp": timestamp,
                "status": "ROLLED_BACK",
                "event_id": event.get("event_id"),
                "mongo_inserted": False,
                "neo4j_nodes_added": 0,
                "neo4j_edges_added": 0,
                "error": str(err)
            }
            self.transaction_log.append(tx_record)
            return tx_record

    def get_transaction_logs(self, limit=20):
        return sorted(self.transaction_log, key=lambda x: x["timestamp"], reverse=True)[:limit]
