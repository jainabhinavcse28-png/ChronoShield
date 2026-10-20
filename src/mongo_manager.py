import datetime
import logging
import config

try:
    import pymongo
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MongoManager")

class MongoManager:
    """
    MongoDB Document Manager for raw telemetry logs, asset inventory, and alerts.
    Implements complete CRUD operations, advanced aggregation pipelines, compound indexing,
    and fallback in-memory store for robust demonstration.
    """

    def __init__(self, uri=config.MONGO_URI, db_name=config.MONGO_DB_NAME):
        self.is_connected = False
        self.client = None
        self.db = None
        
        # In-memory fallback stores
        self._memory_telemetry = []
        self._memory_assets = []
        self._memory_alerts = []

        if PYMONGO_AVAILABLE:
            try:
                self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=2000)
                # Test connection
                self.client.server_info()
                self.db = self.client[db_name]
                self.is_connected = True
                logger.info("Connected to live MongoDB instance.")
                self._setup_indexes()
            except Exception as e:
                logger.warning(f"Could not connect to MongoDB server ({e}). Operating in memory mode.")
                self.is_connected = False
        else:
            logger.warning("pymongo package not installed. Operating in memory mode.")

    def _setup_indexes(self):
        """Creates compound indexes and unique constraints in MongoDB."""
        if self.is_connected and self.db is not None:
            try:
                self.db.raw_telemetry.create_index([("timestamp", pymongo.DESCENDING)])
                self.db.raw_telemetry.create_index([("event_id", pymongo.ASCENDING)], unique=True)
                self.db.raw_telemetry.create_index([("event_type", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)])
                self.db.raw_telemetry.create_index([("host.host_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)])
                self.db.asset_inventory.create_index([("host_id", pymongo.ASCENDING)], unique=True)
                self.db.alerts.create_index([("created_at", pymongo.DESCENDING)])
                logger.info("MongoDB compound indexes and unique constraints created successfully.")
            except Exception as e:
                logger.error(f"Error creating MongoDB indexes: {e}")

    # ==================== CRUD: CREATE ====================

    def insert_telemetry_log(self, evt):
        if "ingested_at" not in evt:
            evt["ingested_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        if self.is_connected:
            res = self.db.raw_telemetry.insert_one(evt)
            return str(res.inserted_id)
        else:
            # Prevent duplicate event_id in memory
            self._memory_telemetry = [e for e in self._memory_telemetry if e.get("event_id") != evt.get("event_id")]
            self._memory_telemetry.append(evt)
            return evt.get("event_id")

    def insert_telemetry_batch(self, events):
        inserted_ids = []
        for evt in events:
            inserted_ids.append(self.insert_telemetry_log(evt))
        return inserted_ids

    def insert_asset(self, asset_doc):
        if self.is_connected:
            self.db.asset_inventory.replace_one({"host_id": asset_doc["host_id"]}, asset_doc, upsert=True)
        else:
            self._memory_assets = [a for a in self._memory_assets if a.get("host_id") != asset_doc.get("host_id")]
            self._memory_assets.append(asset_doc)

    def insert_alert(self, alert_doc):
        if "created_at" not in alert_doc:
            alert_doc["created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if "status" not in alert_doc:
            alert_doc["status"] = "OPEN"

        if self.is_connected:
            res = self.db.alerts.insert_one(alert_doc)
            return str(res.inserted_id)
        else:
            if "alert_id" not in alert_doc:
                alert_doc["alert_id"] = f"ALT-{len(self._memory_alerts) + 1}"
            self._memory_alerts.append(alert_doc)
            return alert_doc["alert_id"]

    # ==================== CRUD: READ ====================

    def get_telemetry_by_id(self, event_id):
        if self.is_connected:
            return self.db.raw_telemetry.find_one({"event_id": event_id}, {"_id": 0})
        else:
            for log in self._memory_telemetry:
                if log.get("event_id") == event_id:
                    return log
            return None

    def get_all_telemetry(self, limit=100, query=None):
        if query is None:
            query = {}
        if self.is_connected:
            cursor = self.db.raw_telemetry.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
            return list(cursor)
        else:
            filtered = self._memory_telemetry
            if "event_type" in query:
                filtered = [e for e in filtered if e.get("event_type") == query["event_type"]]
            if "severity" in query:
                filtered = [e for e in filtered if e.get("severity") == query["severity"]]
            return sorted(filtered, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    def get_assets(self):
        if self.is_connected:
            return list(self.db.asset_inventory.find({}, {"_id": 0}))
        else:
            return self._memory_assets

    def get_alerts(self):
        if self.is_connected:
            return list(self.db.alerts.find({}, {"_id": 0}))
        else:
            return self._memory_alerts

    # ==================== CRUD: UPDATE ====================

    def update_telemetry_log(self, event_id, update_dict):
        if self.is_connected:
            res = self.db.raw_telemetry.update_one({"event_id": event_id}, {"$set": update_dict})
            return res.modified_count > 0
        else:
            for log in self._memory_telemetry:
                if log.get("event_id") == event_id:
                    log.update(update_dict)
                    return True
            return False

    def update_asset(self, host_id, update_dict):
        if self.is_connected:
            res = self.db.asset_inventory.update_one({"host_id": host_id}, {"$set": update_dict})
            return res.modified_count > 0
        else:
            for asset in self._memory_assets:
                if asset.get("host_id") == host_id:
                    asset.update(update_dict)
                    return True
            return False

    def update_alert_status(self, alert_id, status):
        if self.is_connected:
            res = self.db.alerts.update_one({"alert_id": alert_id}, {"$set": {"status": status}})
            return res.modified_count > 0
        else:
            for alt in self._memory_alerts:
                if alt.get("alert_id") == alert_id or alt.get("_id") == alert_id:
                    alt["status"] = status
                    return True
            return False

    # ==================== CRUD: DELETE ====================

    def delete_telemetry_log(self, event_id):
        if self.is_connected:
            res = self.db.raw_telemetry.delete_one({"event_id": event_id})
            return res.deleted_count > 0
        else:
            before = len(self._memory_telemetry)
            self._memory_telemetry = [e for e in self._memory_telemetry if e.get("event_id") != event_id]
            return len(self._memory_telemetry) < before

    def delete_alert(self, alert_id):
        if self.is_connected:
            res = self.db.alerts.delete_one({"alert_id": alert_id})
            return res.deleted_count > 0
        else:
            before = len(self._memory_alerts)
            self._memory_alerts = [a for a in self._memory_alerts if a.get("alert_id") != alert_id]
            return len(self._memory_alerts) < before

    def clear_all_telemetry(self):
        if self.is_connected:
            self.db.raw_telemetry.delete_many({})
            self.db.alerts.delete_many({})
        self._memory_telemetry = []
        self._memory_alerts = []

    # ==================== ADVANCED NOSQL: AGGREGATIONS ====================

    def aggregate_severity_distribution(self):
        """Pipeline 1: Aggregates total logs grouped by severity level."""
        if self.is_connected:
            pipeline = [
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            results = list(self.db.raw_telemetry.aggregate(pipeline))
            return [{"severity": r["_id"] or "UNKNOWN", "count": r["count"]} for r in results]
        else:
            counts = {}
            for e in self._memory_telemetry:
                sev = e.get("severity", "UNKNOWN")
                counts[sev] = counts.get(sev, 0) + 1
            return [{"severity": k, "count": v} for k, v in counts.items()]

    def aggregate_host_risk_summary(self):
        """Pipeline 2: Groups logs by host to compute total events and distinct event types."""
        if self.is_connected:
            pipeline = [
                {"$group": {
                    "_id": "$host.host_id",
                    "total_events": {"$sum": 1},
                    "event_types": {"$addToSet": "$event_type"},
                    "latest_event": {"$max": "$timestamp"}
                }},
                {"$sort": {"total_events": -1}},
                {"$limit": 10}
            ]
            results = list(self.db.raw_telemetry.aggregate(pipeline))
            return [{"host_id": r["_id"] or "N/A", "total_events": r["total_events"], "event_types": r["event_types"], "latest_event": r["latest_event"]} for r in results]
        else:
            host_map = {}
            for e in self._memory_telemetry:
                host_info = e.get("host", {})
                hid = host_info.get("host_id") if isinstance(host_info, dict) else str(host_info)
                if not hid:
                    continue
                if hid not in host_map:
                    host_map[hid] = {"total_events": 0, "event_types": set(), "latest_event": ""}
                host_map[hid]["total_events"] += 1
                host_map[hid]["event_types"].add(e.get("event_type", "UNKNOWN"))
                if e.get("timestamp", "") > host_map[hid]["latest_event"]:
                    host_map[hid]["latest_event"] = e.get("timestamp", "")

            return [{"host_id": k, "total_events": v["total_events"], "event_types": list(v["event_types"]), "latest_event": v["latest_event"]} for k, v in sorted(host_map.items(), key=lambda x: x[1]["total_events"], reverse=True)[:10]]

    def get_index_information(self):
        """Returns details on active MongoDB indexes."""
        if self.is_connected:
            return self.db.raw_telemetry.index_information()
        else:
            return {
                "timestamp_-1": {"key": [("timestamp", -1)]},
                "event_id_1": {"key": [("event_id", 1)], "unique": True},
                "event_type_1_timestamp_-1": {"key": [("event_type", 1), ("timestamp", -1)]},
                "host.host_id_1_timestamp_-1": {"key": [("host.host_id", 1), ("timestamp", -1)]}
            }

if __name__ == "__main__":
    manager = MongoManager()
    print(f"MongoManager initialized. Live Connected: {manager.is_connected}")
