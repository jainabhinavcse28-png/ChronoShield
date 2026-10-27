let network = null;
let activeTab = "tab-graph";
let allNodesMap = {};

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initTabs();
    refreshAllData();

    // Attach Top Action Listeners
    document.getElementById("btn-load-scenario").addEventListener("click", loadSimpleScenario);
    document.getElementById("btn-clear-scenario").addEventListener("click", clearAllScenarioData);

    // Cypher Console Runner
    document.getElementById("btn-run-cypher").addEventListener("click", () => {
        const query = document.getElementById("cypher-input").value;
        runCypherQuery(query);
    });

    // Cross-Database JOIN Runner
    const btnJoin = document.getElementById("btn-execute-join");
    if (btnJoin) {
        btnJoin.addEventListener("click", executeDatabaseJoin);
    }

    // Form Submissions
    document.getElementById("form-mongo-create").addEventListener("submit", handleMongoCreate);
    document.getElementById("form-neo4j-node").addEventListener("submit", handleNeo4jCreateNode);
    document.getElementById("form-neo4j-edge").addEventListener("submit", handleNeo4jCreateEdge);

    // Filter Listeners
    document.getElementById("filter-mongo-severity").addEventListener("change", fetchMongoLogs);

    // Auto Refresh every 12 seconds
    setInterval(() => {
        fetchStats();
        if (activeTab === "tab-graph") {
            fetchGraphTopology();
            fetchAttackPaths();
        }
    }, 12000);
});

function initClock() {
    const clock = document.getElementById("clock-display");
    function update() {
        const now = new Date();
        clock.innerText = now.toUTCString().replace("GMT", "UTC");
    }
    update();
    setInterval(update, 1000);
}

function initTabs() {
    const navLinks = document.querySelectorAll(".nav-link");
    navLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            navLinks.forEach(l => l.classList.remove("active"));
            link.classList.add("active");

            const tabId = link.getAttribute("data-tab");
            activeTab = tabId;

            document.querySelectorAll(".tab-content").forEach(tab => {
                tab.classList.remove("active");
            });
            const targetTab = document.getElementById(tabId);
            if (targetTab) {
                targetTab.classList.add("active");
            }

            // Tab-specific refreshes
            if (tabId === "tab-graph") {
                fetchGraphTopology();
                fetchAttackPaths();
            } else if (tabId === "tab-mongo") {
                fetchMongoLogs();
            } else if (tabId === "tab-neo4j") {
                fetchNeo4jNodes();
            } else if (tabId === "tab-join") {
                executeDatabaseJoin();
            }
        });
    });
}

function refreshAllData() {
    fetchStats();
    fetchGraphTopology();
    fetchAttackPaths();
    fetchMongoLogs();
    fetchNeo4jNodes();
}

function showToast(message, isError = false) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast ${isError ? "toast-error" : ""}`;
    toast.innerText = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// ==============================================================================
// 1. STATS & GRAPH VISUALIZATION
// ==============================================================================

async function fetchStats() {
    try {
        const res = await fetch("/api/stats");
        const data = await res.json();

        document.getElementById("stat-logs").innerText = data.total_logs;
        document.getElementById("stat-nodes").innerText = data.total_nodes;
        document.getElementById("stat-edges").innerText = data.total_edges;
        document.getElementById("stat-alerts").innerText = data.high_risk_alerts;

        // DB Status Badges
        const mDot = document.getElementById("mongo-dot");
        const mBadge = document.getElementById("mongo-badge");
        if (data.mongo_connected) {
            mDot.style.backgroundColor = "#10B981";
            mBadge.innerText = "Connected";
            mBadge.style.background = "rgba(16, 185, 129, 0.2)";
        }

        const nDot = document.getElementById("neo4j-dot");
        const nBadge = document.getElementById("neo4j-badge");
        if (data.neo4j_connected) {
            nDot.style.backgroundColor = "#10B981";
            nBadge.innerText = "Connected";
            nBadge.style.background = "rgba(16, 185, 129, 0.2)";
        }
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

async function fetchGraphTopology() {
    try {
        const res = await fetch("/api/graph");
        const data = await res.json();

        const container = document.getElementById("network-container");
        allNodesMap = {};

        const visNodes = data.nodes.map(n => {
            allNodesMap[n.id] = n;

            let color = "#0284C7"; // Low Risk Blue
            if (n.risk_score >= 70.0) color = "#EF4444";     // High Risk Red
            else if (n.risk_score >= 40.0) color = "#F97316"; // Medium Risk Orange
            else if (n.group === "Vulnerability") color = "#EAB308"; // Vuln Yellow

            let shape = "dot";
            if (n.group === "Host") shape = "diamond";
            else if (n.group === "User") shape = "star";
            else if (n.group === "Process") shape = "hexagon";

            return {
                id: n.id,
                label: `${n.label}\n[Risk: ${n.risk_score}]`,
                color: {
                    background: color,
                    border: "#FFFFFF",
                    highlight: { background: "#FFFFFF", border: color }
                },
                shape: shape,
                size: Math.max(16, Math.min(34, n.risk_score / 2.5)),
                font: { color: "#F8FAFC", face: "Outfit", size: 11 }
            };
        });

        const visEdges = data.edges.map(e => {
            return {
                from: e.from,
                to: e.to,
                label: e.label,
                arrows: "to",
                color: { color: "#475569", highlight: "#38BDF8" },
                font: { color: "#94A3B8", size: 9, face: "JetBrains Mono" },
                smooth: { type: "curvedCW", roundness: 0.18 }
            };
        });

        const graphData = {
            nodes: new vis.DataSet(visNodes),
            edges: new vis.DataSet(visEdges)
        };

        const options = {
            physics: {
                barnesHut: { gravitationalConstant: -2800, centralGravity: 0.25, springLength: 100 }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        if (network === null) {
            network = new vis.Network(container, graphData, options);
            network.on("click", (params) => {
                if (params.nodes.length > 0) {
                    const selectedId = params.nodes[0];
                    inspectNode(selectedId);
                }
            });
        } else {
            network.setData(graphData);
        }
    } catch (err) {
        console.error("Error loading graph:", err);
    }
}

function inspectNode(nodeId) {
    const node = allNodesMap[nodeId];
    const inspector = document.getElementById("inspector-content");
    if (!node) {
        inspector.innerHTML = `<div class="inspector-empty">Node details not found.</div>`;
        return;
    }

    inspector.className = "inspector-loaded";
    inspector.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: #38BDF8; font-size: 14px;">${node.id}</strong>
            <span class="pill pill-${node.risk_score >= 70 ? 'CRITICAL' : (node.risk_score >= 40 ? 'HIGH' : 'LOW')}">Risk: ${node.risk_score}</span>
        </div>
        <div style="font-size: 11px; line-height: 1.6; color: var(--text-muted); font-family: var(--font-code);">
            <div><strong>Type / Label:</strong> ${node.group}</div>
            <div><strong>Display Name:</strong> ${node.label}</div>
            <div><strong>Properties:</strong> ${JSON.stringify(node.props)}</div>
        </div>
        <div style="margin-top: 10px; display: flex; gap: 6px;">
            <button class="btn-sm-action" onclick="quickUpdateRisk('${node.id}', 95.0)">⚡ Set High Risk (95)</button>
            <button class="btn-sm-action" onclick="quickUpdateRisk('${node.id}', 10.0)">🛡️ Reset Risk (10)</button>
            <button class="btn-sm-danger" onclick="deleteNeo4jNode('${node.id}')">🗑️ Delete Node</button>
        </div>
    `;
}

async function fetchAttackPaths() {
    try {
        const res = await fetch("/api/attack-paths");
        const paths = await res.json();
        const container = document.getElementById("attack-paths-list");
        container.innerHTML = "";

        if (paths.length === 0) {
            container.innerHTML = `<div class="hint-text" style="padding: 16px;">No critical multi-hop attack paths detected currently.</div>`;
            return;
        }

        paths.forEach((p, idx) => {
            const card = document.createElement("div");
            card.className = "path-card";
            const timelineHtml = p.timeline.map(step => `<div class="path-step">${step}</div>`).join("");

            card.innerHTML = `
                <div class="path-header">
                    <span><strong>Attack Vector #${idx + 1}</strong> (${p.path_length} hops)</span>
                    <span class="risk-badge">Cumulative Risk: ${p.cumulative_risk}</span>
                </div>
                <div class="path-timeline">${timelineHtml}</div>
            `;
            container.appendChild(card);
        });
    } catch (err) {
        console.error("Error fetching attack paths:", err);
    }
}

// ==============================================================================
// 2. CYPHER QUERY PLAYGROUND
// ==============================================================================

function setAndRunCypher(query) {
    document.getElementById("cypher-input").value = query;
    runCypherQuery(query);
}

async function runCypherQuery(query) {
    const resultsBox = document.getElementById("cypher-results");
    resultsBox.innerText = `Executing Cypher: ${query} ...`;

    try {
        const res = await fetch("/api/neo4j/cypher", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: query })
        });
        const data = await res.json();

        if (data.result && data.result.success) {
            const records = data.result.records;
            resultsBox.innerText = `// Cypher Result (${data.result.mode}) - ${data.result.count} records returned\n` +
                                   JSON.stringify(records, null, 2);
            showToast(`Cypher executed: ${data.result.count} records found.`);
        } else {
            resultsBox.innerText = `// Error executing Cypher:\n` + (data.result?.error || data.error || "Unknown error");
            showToast("Cypher query error", true);
        }
    } catch (err) {
        resultsBox.innerText = `// Request Failed: ${err.message}`;
    }
}

// ==============================================================================
// 3. MONGODB CRUD STUDIO
// ==============================================================================

async function handleMongoCreate(e) {
    e.preventDefault();
    const payload = {
        event_type: document.getElementById("m-evt-type").value,
        severity: document.getElementById("m-severity").value,
        host_id: document.getElementById("m-host-id").value,
        user: document.getElementById("m-user").value,
        ip: document.getElementById("m-ip").value,
        description: document.getElementById("m-desc").value,
        status: "OPEN"
    };

    try {
        const res = await fetch("/api/mongodb/logs", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            showToast(`Document created in MongoDB (ID: ${data.document.event_id})`);
            document.getElementById("mongo-command-display").innerText = 
                `// Executed MongoDB Shell Command:\n` +
                `db.security_logs.insertOne({\n` +
                `  event_id: "${data.document.event_id}",\n` +
                `  event_type: "${payload.event_type}",\n` +
                `  severity: "${payload.severity}",\n` +
                `  host: { host_id: "${payload.host_id}", ip: "${payload.ip}" },\n` +
                `  user: { username: "${payload.user}" },\n` +
                `  status: "OPEN",\n` +
                `  description: "${payload.description}"\n` +
                `});`;

            fetchMongoLogs();
            fetchStats();
            fetchGraphTopology();
        }
    } catch (err) {
        showToast("Error creating document in MongoDB", true);
    }
}

async function fetchMongoLogs() {
    const sev = document.getElementById("filter-mongo-severity").value;
    const url = `/api/mongodb/logs?limit=50${sev !== "ALL" ? `&severity=${sev}` : ""}`;

    try {
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById("mongo-logs-tbody");
        tbody.innerHTML = "";

        const logs = data.logs || [];
        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color: var(--text-muted); padding: 18px;">No MongoDB records found matching criteria.</td></tr>`;
            return;
        }

        logs.forEach(log => {
            const tr = document.createElement("tr");
            const ts = log.timestamp ? log.timestamp.substring(11, 19) : "N/A";
            const sev = log.severity || "MEDIUM";
            const status = log.status || "OPEN";
            const host = log.host?.host_id || log.host || "N/A";
            const user = log.user?.username || log.user || "N/A";
            const statusBadgeClass = status === "RESOLVED" ? "badge-resolved" : (status === "INVESTIGATING" ? "badge-investigating" : "badge-open");

            tr.innerHTML = `
                <td style="font-family: var(--font-code); color: #38BDF8;">${log.event_id}</td>
                <td style="font-family: var(--font-code); color: var(--text-muted);">${ts}</td>
                <td><span class="pill pill-${sev}">${sev}</span></td>
                <td><span class="pill ${statusBadgeClass}">${status}</span></td>
                <td><strong>${log.event_type}</strong></td>
                <td>${host}</td>
                <td>${user}</td>
                <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.description || ""}</td>
                <td>
                    <button class="btn-sm-action" onclick="updateMongoLogStatus('${log.event_id}', 'RESOLVED')">Resolve</button>
                    <button class="btn-sm-action" onclick="updateMongoLogStatus('${log.event_id}', 'INVESTIGATING')">Investigate</button>
                    <button class="btn-sm-danger" onclick="deleteMongoLog('${log.event_id}')">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Error reading MongoDB logs:", err);
    }
}

async function updateMongoLogStatus(eventId, newStatus) {
    try {
        const res = await fetch(`/api/mongodb/logs/${eventId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Updated log ${eventId} to status: ${newStatus}`);
            document.getElementById("mongo-command-display").innerText =
                `// Executed MongoDB Shell Command (UPDATE):\n` +
                `db.security_logs.updateOne(\n` +
                `  { event_id: "${eventId}" },\n` +
                `  { $set: { status: "${newStatus}" } }\n` +
                `);`;
            fetchMongoLogs();
        }
    } catch (err) {
        showToast("Error updating MongoDB document", true);
    }
}

async function deleteMongoLog(eventId) {
    if (!confirm(`Are you sure you want to delete MongoDB log: ${eventId}?`)) return;

    try {
        const res = await fetch(`/api/mongodb/logs/${eventId}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            showToast(`Deleted document ${eventId} from MongoDB`);
            document.getElementById("mongo-command-display").innerText =
                `// Executed MongoDB Shell Command (DELETE):\n` +
                `db.security_logs.deleteOne({ event_id: "${eventId}" });`;
            fetchMongoLogs();
            fetchStats();
        }
    } catch (err) {
        showToast("Error deleting MongoDB log", true);
    }
}

// ==============================================================================
// 4. NEO4J CYPHER CRUD STUDIO
// ==============================================================================

async function handleNeo4jCreateNode(e) {
    e.preventDefault();
    const payload = {
        node_id: document.getElementById("n-node-id").value,
        label: document.getElementById("n-label").value,
        name: document.getElementById("n-name").value,
        risk_score: parseFloat(document.getElementById("n-risk").value)
    };

    try {
        const res = await fetch("/api/neo4j/nodes", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            showToast(`Created Node ${payload.node_id} via Cypher`);
            document.getElementById("cypher-command-display").innerText =
                `// Executed Cypher Command (CREATE NODE):\n` +
                `CREATE (n:${payload.label} { id: "${payload.node_id}", name: "${payload.name}", risk_score: ${payload.risk_score} });`;
            fetchNeo4jNodes();
            fetchStats();
            fetchGraphTopology();
        }
    } catch (err) {
        showToast("Error creating node in Neo4j", true);
    }
}

async function handleNeo4jCreateEdge(e) {
    e.preventDefault();
    const payload = {
        source: document.getElementById("e-source").value,
        target: document.getElementById("e-target").value,
        type: document.getElementById("e-type").value
    };

    try {
        const res = await fetch("/api/neo4j/edges", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            showToast(`Created Relationship: ${payload.type}`);
            document.getElementById("cypher-command-display").innerText =
                `// Executed Cypher Command (CREATE RELATIONSHIP):\n` +
                `MATCH (a { id: "${payload.source}" }), (b { id: "${payload.target}" })\n` +
                `CREATE (a)-[r:${payload.type}]->(b);`;
            fetchStats();
            fetchGraphTopology();
            fetchAttackPaths();
        }
    } catch (err) {
        showToast("Error creating relationship in Neo4j", true);
    }
}

async function fetchNeo4jNodes() {
    try {
        const res = await fetch("/api/neo4j/nodes");
        const data = await res.json();
        const tbody = document.getElementById("neo4j-nodes-tbody");
        tbody.innerHTML = "";

        const nodes = data.nodes || [];
        if (nodes.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 18px;">No graph nodes found in Neo4j.</td></tr>`;
            return;
        }

        nodes.forEach(node => {
            const tr = document.createElement("tr");
            const risk = node.risk_score || 0;
            const riskClass = risk >= 70 ? "pill-CRITICAL" : (risk >= 40 ? "pill-HIGH" : "pill-LOW");

            tr.innerHTML = `
                <td style="font-family: var(--font-code); color: #38BDF8;">${node.id}</td>
                <td><span class="badge" style="background:#0F172A; border:1px solid #334155;">${node.label}</span></td>
                <td><span class="pill ${riskClass}">${risk.toFixed(1)}</span></td>
                <td style="font-family: var(--font-code); font-size: 11px; color: var(--text-muted);">${JSON.stringify(node.props)}</td>
                <td>
                    <button class="btn-sm-action" onclick="quickUpdateRisk('${node.id}', ${risk + 20})">+20 Risk</button>
                    <button class="btn-sm-danger" onclick="deleteNeo4jNode('${node.id}')">Detach Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Error reading Neo4j nodes:", err);
    }
}

async function quickUpdateRisk(nodeId, newRisk) {
    newRisk = Math.min(100.0, Math.max(0.0, newRisk));
    try {
        const res = await fetch(`/api/neo4j/nodes/${nodeId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ risk_score: newRisk })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Updated risk for ${nodeId} to ${newRisk.toFixed(1)}`);
            document.getElementById("cypher-command-display").innerText =
                `// Executed Cypher Command (UPDATE NODE):\n` +
                `MATCH (n { id: "${nodeId}" }) SET n.risk_score = ${newRisk} RETURN n;`;
            fetchNeo4jNodes();
            fetchGraphTopology();
            fetchAttackPaths();
            fetchStats();
            inspectNode(nodeId);
        }
    } catch (err) {
        showToast("Error updating node risk in Neo4j", true);
    }
}

async function deleteNeo4jNode(nodeId) {
    if (!confirm(`Are you sure you want to DETACH DELETE node: ${nodeId}?`)) return;

    try {
        const res = await fetch(`/api/neo4j/nodes/${nodeId}`, { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            showToast(`Deleted Node ${nodeId} via Cypher`);
            document.getElementById("cypher-command-display").innerText =
                `// Executed Cypher Command (DELETE NODE):\n` +
                `MATCH (n { id: "${nodeId}" }) DETACH DELETE n;`;
            fetchNeo4jNodes();
            fetchGraphTopology();
            fetchAttackPaths();
            fetchStats();
            document.getElementById("inspector-content").innerHTML = `<div class="inspector-empty">Node deleted.</div>`;
        }
    } catch (err) {
        showToast("Error deleting node in Neo4j", true);
    }
}

// ==============================================================================
// 6. CROSS-DATABASE POLYGLOT JOIN
// ==============================================================================

async function executeDatabaseJoin() {
    const select = document.getElementById("join-entity-select");
    const entityId = select ? select.value : "HOST-JUMPBOX-01";
    const neoOut = document.getElementById("join-neo4j-output");
    const mongoOut = document.getElementById("join-mongo-output");

    if (!neoOut || !mongoOut) return;

    neoOut.innerText = `Querying Neo4j Graph Database for entity: ${entityId}...`;
    mongoOut.innerText = `Executing Polyglot JOIN with MongoDB security logs...`;

    try {
        const res = await fetch(`/api/database/join?entity_id=${encodeURIComponent(entityId)}`);
        const data = await res.json();

        neoOut.innerText = `// Neo4j Entity Details (${data.neo4j_graph_entity.node_id})\n` +
                           `Risk Score: ${data.neo4j_graph_entity.risk_score}\n` +
                           `Label: ${data.neo4j_graph_entity.label}\n` +
                           `Connected Edges: ${data.neo4j_graph_entity.connected_relationships_count}\n` +
                           `Properties:\n` +
                           JSON.stringify(data.neo4j_graph_entity.properties, null, 2) + "\n\n" +
                           `Relationships:\n` +
                           JSON.stringify(data.neo4j_graph_entity.relationships, null, 2);

        mongoOut.innerText = `// MongoDB Matched Documents (${data.mongodb_matched_documents_count} logs joined on ${data.join_key})\n` +
                             JSON.stringify(data.mongodb_documents, null, 2);

        showToast(`Polyglot JOIN completed: ${data.mongodb_matched_documents_count} logs joined.`);
    } catch (err) {
        neoOut.innerText = "Error executing join: " + err.message;
        mongoOut.innerText = "Error executing join: " + err.message;
        showToast("Error executing database join", true);
    }
}

// ==============================================================================
// 5. ONE-CLICK SCENARIO LOAD & CLEAR
// ==============================================================================

async function loadSimpleScenario() {
    const btn = document.getElementById("btn-load-scenario");
    btn.disabled = true;
    btn.innerHTML = `⚡ Loading 6-Stage Attack...`;

    try {
        const res = await fetch("/api/scenario/load-simple", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            refreshAllData();
        }
    } catch (err) {
        showToast("Error loading simple scenario", true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">⚡</span> Load 6-Stage Attack`;
    }
}

async function clearAllScenarioData() {
    if (!confirm("Are you sure you want to clear all logs from MongoDB and all nodes from Neo4j?")) return;

    try {
        const res = await fetch("/api/scenario/clear", { method: "POST" });
        const data = await res.json();
        if (data.success) {
            showToast(data.message);
            refreshAllData();
        }
    } catch (err) {
        showToast("Error clearing database records", true);
    }
}
