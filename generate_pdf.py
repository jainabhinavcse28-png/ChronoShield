import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_header_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (Only on page 2 and later)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "DBMS Review 1 Report: Cyber Attack Graph & NoSQL Architecture")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)
            
        # Footer (On all pages)
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 36, page_text)
        self.drawString(54, 36, "CONFIDENTIAL - DBMS Project Review 1 Deliverable")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, letter[0] - 54, 48)
        
        self.restoreState()

def build_pdf():
    pdf_filename = "Review_1_Report.pdf"
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Palette
    PRIMARY = colors.HexColor("#0F172A")     # Dark Slate
    SECONDARY = colors.HexColor("#0284C7")   # Deep Sky Blue
    ACCENT = colors.HexColor("#0D9488")      # Teal
    TEXT_COLOR = colors.HexColor("#334155")  # Dark Neutral
    BG_LIGHT = colors.HexColor("#F8FAFC")    # Slate 50
    CODE_BG = colors.HexColor("#1E293B")     # Code slate

    # Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=PRIMARY,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=SECONDARY,
        spaceAfter=15
    )

    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=TEXT_COLOR
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=SECONDARY,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=TEXT_COLOR,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=TEXT_COLOR,
        leftIndent=15,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#E2E8F0"),
        spaceBefore=4,
        spaceAfter=4
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    table_body_style = ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=TEXT_COLOR
    )

    story = []

    # Title & Header Banner
    story.append(Paragraph("ChronoShield: Early Cyber Attack Detection via Temporal Attack Graphs & Risk Decay", title_style))
    story.append(Paragraph("DBMS Review 1 Report: Problem Definition, Requirement Analysis & NoSQL Database Design", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=SECONDARY, spaceBefore=0, spaceAfter=12))

    meta_text = """
    <b>Course:</b> Database Management Systems (NoSQL Architecture)<br/>
    <b>Review Stage:</b> Review 1 (Marks: 10)<br/>
    <b>Selected NoSQL Databases:</b> MongoDB (Document Store) & Neo4j (Graph Database)<br/>
    <b>Target Domain:</b> Cyber Security Threat Detection & Temporal Graph Analytics
    """
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 14))

    # SECTION 1: Problem Statement, Objectives, and Scope (2 Marks)
    story.append(Paragraph("1. Problem Statement, Objectives & Scope (2 Marks)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=PRIMARY, spaceBefore=0, spaceAfter=8))

    story.append(Paragraph("1.1 Background & Problem Statement", h2_style))
    p1 = ("Modern cyber attacks executed by Advanced Persistent Threats (APTs) rarely consist of a single isolated "
          "malicious action. Instead, adversaries conduct low-and-slow tactics spanning days or weeks—such as initial credential exploitation, "
          "stealthy process injection, internal reconnaissance, lateral movement, and privilege escalation—to reach critical database assets. "
          "Traditional Intrusion Detection Systems (IDS) and relational Security Information and Event Management (SIEM) solutions fail because:")
    story.append(Paragraph(p1, body_style))

    story.append(Paragraph("• <b>Stateless Log Processing:</b> They evaluate security logs in isolation or within small static rulesets, missing temporal multi-hop attack paths.", bullet_style))
    story.append(Paragraph("• <b>Relational Join Bottlenecks:</b> Querying N-hop connected entity paths in Relational DBMS produces exponential join computational complexity O(k^d), severely degrading query performance.", bullet_style))
    story.append(Paragraph("• <b>Lack of Explainable Causal Paths:</b> Traditional tools issue disjointed alerts without displaying the end-to-end attack graph sequence to SOC analysts.", bullet_style))

    story.append(Paragraph("1.2 Core Objectives", h2_style))
    story.append(Paragraph("• Ingest high-velocity, semi-structured system and network telemetry logs into a scalable Document Store (MongoDB).", bullet_style))
    story.append(Paragraph("• Transform log events into a dynamic Temporal Graph (Neo4j) maintaining index-free adjacency for instant path traversal.", bullet_style))
    story.append(Paragraph("• Compute continuous Risk Propagation across graph entities based on CVSS vulnerabilities, anomaly scores, and temporal decay.", bullet_style))
    story.append(Paragraph("• Generate Explainable Attack Paths using Cypher queries to highlight compromised vectors leading to critical assets.", bullet_style))

    story.append(Paragraph("1.3 System Scope", h2_style))
    story.append(Paragraph("The system ingests Windows Sysmon event logs, Linux Auditd records, authentication logs, and network flow data. MongoDB handles append-heavy raw telemetry and auditing, while Neo4j maintains active topological graph states for real-time risk scoring and path queries.", body_style))

    story.append(Spacer(1, 10))

    # SECTION 2: Selection and Justification of NoSQL Database (3 Marks)
    story.append(Paragraph("2. Selection and Justification of NoSQL Database (3 Marks)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=PRIMARY, spaceBefore=0, spaceAfter=8))

    story.append(Paragraph("2.1 Why Polyglot NoSQL (MongoDB + Neo4j)?", h2_style))
    story.append(Paragraph("No single database model optimal for both high-velocity append-heavy log streams and complex graph traversals. Hence, a Polyglot NoSQL approach is adopted:", body_style))

    story.append(Paragraph("• <b>MongoDB (Document Store):</b> Provides high write throughput for unstructured/semi-structured BSON telemetry logs. It allows schema-less ingestion of varying log formats (Sysmon Process Creation, Auth Events, NetFlow) without schema lock overhead.", bullet_style))
    story.append(Paragraph("• <b>Neo4j (Graph Database):</b> Utilizes index-free adjacency where graph nodes reference connected neighbors directly via pointers. This guarantees constant-time traversal O(1) per hop regardless of total database size, ideal for multi-stage lateral attack path discovery.", bullet_style))

    story.append(Paragraph("2.2 NoSQL Database Comparison Matrix", h2_style))

    table_data = [
        [Paragraph("Feature / Criteria", table_header_style), 
         Paragraph("Relational DB (SQL)", table_header_style), 
         Paragraph("MongoDB (Document)", table_header_style), 
         Paragraph("Neo4j (Graph)", table_header_style), 
         Paragraph("Our Polyglot Choice", table_header_style)],
        
        [Paragraph("Log Ingestion Speed", table_body_style), Paragraph("Low (Schema overhead)", table_body_style), Paragraph("<b>Very High (Append BSON)</b>", table_body_style), Paragraph("Moderate", table_body_style), Paragraph("<b>MongoDB</b> for raw log ingestion", table_body_style)],
        [Paragraph("Schema Flexibility", table_body_style), Paragraph("Rigid (Migrations)", table_body_style), Paragraph("<b>Dynamic Schema-less</b>", table_body_style), Paragraph("Flexible Node/Edge attributes", table_body_style), Paragraph("<b>MongoDB</b> for varied log formats", table_body_style)],
        [Paragraph("Multi-Hop Traversal", table_body_style), Paragraph("Slow (O(k^d) JOINs)", table_body_style), Paragraph("Slow (Application-side)", table_body_style), Paragraph("<b>Optimal (Index-free O(1))</b>", table_body_style), Paragraph("<b>Neo4j</b> for lateral movement paths", table_body_style)],
        [Paragraph("Risk Propagation", table_body_style), Paragraph("Complex Recursive SQL", table_body_style), Paragraph("Inefficient Map-Reduce", table_body_style), Paragraph("<b>Native Graph Algorithms</b>", table_body_style), Paragraph("<b>Neo4j</b> Cypher graph traversals", table_body_style)]
    ]

    t_matrix = Table(table_data, colWidths=[1.1*inch, 1.2*inch, 1.4*inch, 1.4*inch, 1.9*inch])
    t_matrix.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_matrix)

    story.append(Spacer(1, 14))

    # SECTION 3: Data Model Design (5 Marks)
    story.append(Paragraph("3. Data Model Design (5 Marks)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=PRIMARY, spaceBefore=0, spaceAfter=8))

    story.append(Paragraph("3.1 ER-to-NoSQL Mapping Strategy", h2_style))

    er_mapping_data = [
        [Paragraph("Relational Concept", table_header_style), Paragraph("MongoDB Collection / Field", table_header_style), Paragraph("Neo4j Graph Element", table_header_style)],
        [Paragraph("Host (Asset)", table_body_style), Paragraph("db.asset_inventory (Document)", table_body_style), Paragraph("(:Host {host_id, ip, criticality, risk_score})", table_body_style)],
        [Paragraph("User Account", table_body_style), Paragraph("db.users (Document)", table_body_style), Paragraph("(:User {username, domain, is_privileged})", table_body_style)],
        [Paragraph("Process Execution", table_body_style), Paragraph("db.raw_telemetry.process (Embedded)", table_body_style), Paragraph("(:Process {pid, name, cmd_hash, risk_score})", table_body_style)],
        [Paragraph("Vulnerability", table_body_style), Paragraph("db.asset_inventory.vulnerabilities", table_body_style), Paragraph("(:Vulnerability {cve_id, cvss_score})", table_body_style)],
        [Paragraph("Auth / Network Event", table_body_style), Paragraph("db.raw_telemetry (Event Doc)", table_body_style), Paragraph("[:AUTHENTICATED_TO], [:CONNECTED_TO], [:SPAWNED]", table_body_style)]
    ]

    t_er = Table(er_mapping_data, colWidths=[1.8*inch, 2.4*inch, 2.8*inch])
    t_er.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), SECONDARY),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_LIGHT]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_er)

    story.append(Spacer(1, 8))
    story.append(Paragraph("3.2 MongoDB Collection Schema (Document Design)", h2_style))
    story.append(Paragraph("Sample BSON schema for <code>raw_telemetry</code> collection storing high-velocity process execution logs:", body_style))

    mongo_json_code = (
        "{\n"
        '  "_id": ObjectId("66c7f1a8e4b0a123456789ab"),\n'
        '  "timestamp": ISODate("2026-08-22T14:32:10Z"),\n'
        '  "event_type": "ProcessCreation",\n'
        '  "host": { "host_id": "HOST-FIN-01", "ip": "10.0.4.15" },\n'
        '  "user": { "username": "jsmith", "domain": "CORP" },\n'
        '  "process": {\n'
        '    "pid": 4120, "name": "powershell.exe",\n'
        '    "cmd": "powershell -ep bypass -c Invoke-Mimikatz"\n'
        "  },\n"
        '  "network": { "dst_ip": "194.26.29.112", "dst_port": 443 }\n'
        "}"
    )

    t_code1 = Table([[Paragraph(mongo_json_code.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)]], colWidths=[7.0*inch])
    t_code1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CODE_BG),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_code1)

    story.append(Spacer(1, 8))
    story.append(Paragraph("3.3 Neo4j Graph Schema (Nodes & Temporal Relationships)", h2_style))
    story.append(Paragraph("<b>Nodes:</b> <code>(:Host)</code>, <code>(:User)</code>, <code>(:Process)</code>, <code>(:IPAddress)</code>, <code>(:Vulnerability)</code><br/>"
                           "<b>Temporal Edges:</b> <code>[:AUTHENTICATED_TO {timestamp}]</code>, <code>[:SPAWNED {timestamp}]</code>, <code>[:LATERAL_MOVE_TO {timestamp}]</code>", body_style))

    story.append(Paragraph("3.4 Risk Propagation Model", h2_style))
    story.append(Paragraph("Dynamic risk score for entity node v at time t is computed as:", body_style))
    story.append(Paragraph("<b>R(v, t) = R_base(v) + Σ [ R(u, t - Δt) × w(u → v) × e^(-λ (t - t_edge)) ]</b>", ParagraphStyle('Formula', parent=body_style, fontName='Helvetica-Bold', textColor=SECONDARY, leftIndent=15)))
    story.append(Paragraph("Where R_base is vulnerability severity (CVSS), w(u → v) is edge action weight, and e^(-λ t) represents temporal risk decay.", body_style))

    story.append(Spacer(1, 10))

    # SECTION 4: Expected Deliverables & Sample Dataset Design
    story.append(Paragraph("4. Expected Deliverables & Sample Dataset Design", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=PRIMARY, spaceBefore=0, spaceAfter=8))

    story.append(Paragraph("4.1 Requirement Specifications", h2_style))
    story.append(Paragraph("• <b>FR-01 (Log Ingestion):</b> Ingest raw security logs into MongoDB <code>raw_telemetry</code> collection.", bullet_style))
    story.append(Paragraph("• <b>FR-02 (Graph Streaming):</b> Parse MongoDB log documents into Neo4j nodes and temporal edges (< 2s latency).", bullet_style))
    story.append(Paragraph("• <b>FR-03 (Temporal Constraint Filter):</b> Enforce chronological validity (t1 ≤ t2 ≤ ... ≤ tn) on attack paths.", bullet_style))
    story.append(Paragraph("• <b>FR-04 (Explainable Path Query):</b> Return node-by-node Cypher attack path visualization for SOC analysts.", bullet_style))
    story.append(Paragraph("• <b>NFR-01 (Performance):</b> Support ≥ 2,000 logs/sec in MongoDB and < 150ms 6-hop Cypher queries in Neo4j.", bullet_style))

    story.append(Spacer(1, 8))
    story.append(Paragraph("4.2 Executable Cypher Query for Explainable Attack Paths", h2_style))

    cypher_code = (
        "// Cypher Query: Discover Chronological Explainable Attack Path\n"
        "MATCH path = (u:User)-[r1:AUTHENTICATED_TO]->(h1:Host)-[r2:HOSTS_PROCESS]->(p:Process)-[r3:LATERAL_MOVE_TO]->(target:Host {criticality: 'CRITICAL'})\n"
        "WHERE r1.timestamp <= r2.timestamp \n"
        "  AND r2.timestamp <= r3.timestamp\n"
        "  AND r3.timestamp <= r1.timestamp + duration('PT2H')\n"
        "RETURN \n"
        "  u.username AS Attacker, h1.host_id AS EntryHost, p.cmd AS MaliciousCommand,\n"
        "  target.host_id AS TargetAsset, nodes(path) AS AttackPathNodes,\n"
        "  reduce(totalRisk = 0.0, n IN nodes(path) | totalRisk + n.risk_score) AS CumulativePathRisk\n"
        "ORDER BY CumulativePathRisk DESC LIMIT 5;"
    )

    t_code2 = Table([[Paragraph(cypher_code.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style)]], colWidths=[7.0*inch])
    t_code2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CODE_BG),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_code2)

    story.append(Spacer(1, 14))
    story.append(Paragraph("<b>Deliverable Status:</b> Review 1 Report complete and ready for evaluation.", meta_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print("PDF generated successfully: Review_1_Report.pdf")

if __name__ == "__main__":
    build_pdf()
