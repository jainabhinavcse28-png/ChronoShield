import os

# Database Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cyber_attack_db")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

# Risk Propagation Parameters
BASE_RISK_SCORES = {
    "User": 10.0,
    "Host": 15.0,
    "Process": 20.0,
    "IPAddress": 25.0,
    "Vulnerability": 50.0
}

EVENT_ACTION_WEIGHTS = {
    "AUTHENTICATED_TO": 0.25,
    "HOSTS_PROCESS": 0.30,
    "SPAWNED_PROCESS": 0.65,
    "MALICIOUS_PROCESS": 0.95,
    "LATERAL_MOVE_TO": 0.85,
    "EXPLOITED_VULN": 0.90,
    "DATA_EXFILTRATION": 0.98
}

RISK_ALERT_THRESHOLD = 70.0
TIME_DECAY_LAMBDA = 0.05  # Per hour decay factor

# Web Application Settings
SECRET_KEY = os.getenv("SECRET_KEY", "cyber_attack_graph_secret_key_2026")
PORT = int(os.getenv("PORT", 5000))
