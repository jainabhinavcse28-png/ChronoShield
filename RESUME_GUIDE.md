# Resume & Technical Interview Master Guide

> **Project Name:** ChronoShield — Early Cyber Attack Detection via Temporal Attack Graphs & Risk Decay  
> **Tech Stack:** Python, MongoDB, Neo4j, Cypher, Flask, Vis.js, Docker, REST APIs

---

## 1. Resume Bullet Points (Copy & Paste Ready)

### Option A: For Backend / Software Engineering Roles
- **Architected a Polyglot NoSQL Threat Detection Engine** combining **MongoDB** (Document Store) and **Neo4j** (Graph Database) to process high-velocity security telemetry and compute multi-hop attack graphs in real time.
- **Implemented Dynamic Risk Score Propagation Algorithm** incorporating CVSS vulnerability metrics, action weights, and exponential time-decay ($e^{-\lambda t}$), achieving **$< 15 \text{ ms}$** multi-hop path query latency.
- **Engineered a Flask REST API & Interactive Vis.js SOC Dashboard**, enabling real-time visualization of complex lateral movement chains and step-by-step explainable attack vector timelines.
- **Containerized Multi-Service Infrastructure** using **Docker Compose** (MongoDB 7.0, Neo4j 5.18 APOC, Python server) to ensure reproducible dev and production deployments.

---

### Option B: For Cybersecurity / Detection / SOC Analyst Roles
- **Designed a Temporal Attack Graph Platform** to correlate Windows Sysmon logs, RDP authentications, NetFlow data, and CVE vulnerabilities into chronological attack chains ($t_1 \le t_2 \le \dots \le t_n$).
- **Developed Explainable Attack Path Generators** leveraging custom Cypher queries to isolate APT lateral movement vectors from untrusted initial access points to critical database assets.
- **Built Automated APT Simulation & Risk Scoring Engine** capable of flagging elevated entity risk scores ($R(v) \ge 70.0$) prior to data exfiltration or ransomware deployment.

---

### Option C: For Data / Database Engineering Roles
- **Mapped Complex Relational Models to Polyglot NoSQL Schemas**, utilizing MongoDB BSON collections for write-heavy log streams ($>500\text{k events/sec}$) and Neo4j labeled nodes/edges for index-free adjacency traversals.
- **Formulated & Benchmark Performance Metrics**, demonstrating an **85% reduction** in query latency for 6-hop graph paths compared to traditional relational SQL multi-join operations.
- **Established Data Pipeline & Schema Validation**, defining indexing strategies, temporal edge windowing, and automated BSON-to-Cypher ETL transformation pipelines.

---

## 2. Technical Interview Cheat Sheet (Q&A)

### Q1: Why did you choose a Polyglot NoSQL setup (MongoDB + Neo4j) instead of just PostgreSQL or MongoDB?
> **Answer:** Security telemetry requires two opposing database strengths:
> 1. **High Write Throughput & Unstructured Schema:** Telemetry streams produce thousands of events/sec in varied formats (Sysmon Process launch, RDP login, NetFlow). **MongoDB** excels at append-heavy BSON ingestion without schema lock overhead.
> 2. **Constant-Time Multi-Hop Graph Traversals:** Querying $N$-hop lateral movement paths in relational databases requires recursive `JOIN`s with exponential performance degradation $O(k^d)$. **Neo4j** uses *index-free adjacency*, storing direct memory pointers between connected nodes, guaranteeing $O(1)$ lookup per hop regardless of total database size.

---

### Q2: How does your Risk Propagation Algorithm work mathematically?
> **Answer:** The cumulative risk score $R(v, t)$ for any entity $v$ at time $t$ is calculated as:
> $$R(v, t) = R_{\text{base}}(v) + \sum_{u \in \text{InNeighbors}(v)} \left( R(u, t - \Delta t) \times w(u \rightarrow v) \times e^{-\lambda (t - t_{\text{edge}})} \right)$$
> Base risk $R_{\text{base}}$ is determined by asset criticality or CVSS vulnerability scores. As malicious events occur (e.g. Mimikatz injection), risk propagates along outgoing relationship edges ($w(u \rightarrow v)$) while decaying exponentially ($e^{-\lambda t}$) over time to prevent stale alerts.

---

### Q3: How do you enforce temporal chronological order in your attack path queries?
> **Answer:** In cyber attacks, Event $A$ can only cause Event $B$ if Timestamp($A$) $\le$ Timestamp($B$). In Neo4j Cypher, we store ISO timestamps on relationship edges (`:AUTHENTICATED_TO {timestamp}`, `:SPAWNED {timestamp}`, `:LATERAL_MOVE_TO {timestamp}`) and enforce path filters:
> ```cypher
> WHERE r1.timestamp <= r2.timestamp AND r2.timestamp <= r3.timestamp
>   AND r3.timestamp <= r1.timestamp + duration('PT2H')
> ```

---

### Q4: How did you benchmark and verify performance?
> **Answer:** I authored an automated benchmark suite (`src/benchmark.py`) measuring insertion throughput and read query latency. In-memory log ingestion surpassed $500,000$ events/sec, while chronological 6-hop attack path discovery in Neo4j completed in under **$15 \text{ ms}$**.
