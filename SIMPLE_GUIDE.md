# 🛡️ ChronoShield: Simple Polyglot NoSQL Project Guide

> **Project Title:** ChronoShield — Simple Cyber Attack Detection via Polyglot NoSQL  
> **Databases Used:** **MongoDB** (Document NoSQL) & **Neo4j** (Graph NoSQL with Cypher)  
> **Core Focus:** Easy-to-explain architecture with full **CRUD Operations** on both databases.

---

## 1. Project Concept in 60 Seconds (For Viva / Evaluation)

### The Problem
Traditional relational databases (SQL) store security events across multiple normalized tables (`hosts`, `users`, `processes`, `network_connections`). When detecting multi-stage cyber attacks (e.g. Attacker $\rightarrow$ Phished User $\rightarrow$ Jumpbox $\rightarrow$ Malware Process $\rightarrow$ Production Database), querying connected paths requires heavy multi-table `JOIN` operations that slow down exponentially ($O(k^d)$).

### The Simple NoSQL Solution: Polyglot Architecture
Instead of using a single database, **ChronoShield** combines two specialized NoSQL databases:
1. **MongoDB (Document Store):** Stores high-velocity, semi-structured security logs (Sysmon, authentication events, network flows).
2. **Neo4j (Graph Database):** Stores entities (Attacker, User, Host, Process, Database) as **Nodes** and malicious connections as **Edges**, using **Cypher** queries to trace attack paths in constant time ($O(1)$ per hop).

---

## 2. MongoDB: Document CRUD Operations

MongoDB collection: `db.security_logs`

| Operation | Action in UI | MongoDB Shell Command Executed |
| :--- | :--- | :--- |
| **CREATE** | Fill Form & Click *"Insert Log"* | `db.security_logs.insertOne({ event_id: "EVT-101", event_type: "AUTHENTICATION", severity: "HIGH", status: "OPEN", host: { host_id: "HOST-01" }, user: { username: "admin" } });` |
| **READ** | Filter by Severity / View Table | `db.security_logs.find({ severity: "HIGH" }).sort({ timestamp: -1 });` |
| **UPDATE** | Click *"Resolve"* or *"Investigate"* | `db.security_logs.updateOne({ event_id: "EVT-101" }, { $set: { status: "RESOLVED" } });` |
| **DELETE** | Click *"Delete"* button | `db.security_logs.deleteOne({ event_id: "EVT-101" });` |

---

## 3. Neo4j & Cypher: Graph CRUD Operations

Neo4j graph entities: `(:IPAddress)`, `(:User)`, `(:Host)`, `(:Process)`, `(:Vulnerability)`

| Operation | Action in UI | Cypher Query Executed |
| :--- | :--- | :--- |
| **CREATE Node** | Fill Form & Click *"Create Node"* | `CREATE (n:Host { id: "Host:BACKUP-01", name: "Backup Server", risk_score: 25.0 });` |
| **CREATE Relationship** | Select Source & Target & Click *"Create Relationship"* | `MATCH (a { id: "Host:JUMPBOX-01" }), (b { id: "Host:DB-PROD-01" }) CREATE (a)-[r:LATERAL_MOVE_TO]->(b);` |
| **READ / Query Path** | Click *"1. Find Attack Path"* | `MATCH path = (a:IPAddress)-[*1..4]->(target:Host) RETURN path;` |
| **READ / Filter High Risk** | Click *"3. High Risk (&ge;70)"* | `MATCH (n) WHERE n.risk_score >= 70 RETURN n;` |
| **UPDATE Risk** | Click *"+20 Risk"* on any node | `MATCH (n { id: "Host:DB-PROD-01" }) SET n.risk_score = 95.0 RETURN n;` |
| **DELETE Node** | Click *"Detach Delete"* | `MATCH (n { id: "Host:BACKUP-01" }) DETACH DELETE n;` |

---

## 4. How to Run & Demonstrate the Project

### Step 1: Start the Web Server
Open your terminal in `c:\Users\abhij\OneDrive\Desktop\dbms` and run:
```bash
python app.py
```
Open your web browser at: **`http://localhost:5000`**

### Step 2: Live Demonstration Steps for Evaluators

1. **Tab 1: 📊 Attack Graph & Cypher Queries**
   - Click **"⚡ Load 6-Stage Attack"** in the sidebar.
   - Point out the visual attack path on the graph:
     `Attacker (198.51.100.44)` $\rightarrow$ `User (admin_temp)` $\rightarrow$ `Jumpbox (HOST-JUMPBOX-01)` $\rightarrow$ `Process (Mimikatz)` $\rightarrow$ `Critical Database (HOST-DB-PROD-01)`
   - Click any button in the Cypher Playground (e.g. **"🎯 1. Find Attack Path"**) to show how Cypher finds the full attack path in milliseconds!

2. **Tab 2: 🍃 MongoDB CRUD Studio**
   - **Create:** Fill the quick form and click *"Insert Log"*. Show the new log appear in the table.
   - **Update:** Click *"Resolve"* to change status from `OPEN` to `RESOLVED` (`updateOne`).
   - **Delete:** Click *"Delete"* to remove an event (`deleteOne`).
   - Show the **MongoDB Command Inspector** at the top right which displays the exact JavaScript shell code executed!

3. **Tab 3: 🕸️ Neo4j Cypher CRUD Studio**
   - **Create Node:** Add a new node (e.g. `Host:TEST-01`).
   - **Update Risk:** Click *"+20 Risk"* on any node to demonstrate Cypher `SET`.
   - **Delete:** Click *"Detach Delete"* to demonstrate Cypher `DETACH DELETE`.
   - Show the **Cypher Command Inspector** at the bottom displaying the Cypher query!

---

## 5. Quick Questions & Answers for Viva

**Q1: Why did you choose MongoDB and Neo4j together?**  
> *"MongoDB handles the unstructured high-volume security logs with fast writes and flexible JSON schemas. Neo4j handles the relationships between hosts, users, and processes, allowing us to find multi-hop attack paths without heavy SQL JOIN bottlenecks."*

**Q2: What is Cypher?**  
> *"Cypher is the declarative graph query language for Neo4j. It uses ASCII-art style syntax like `(a)-[r]->(b)` to match and create nodes and relationships easily."*

**Q3: Does the project work if live MongoDB or Neo4j servers are offline?**  
> *"Yes, the system has an automatic in-memory fallback engine so the full CRUD and graph visualization demo works reliably anytime without crashing."*
