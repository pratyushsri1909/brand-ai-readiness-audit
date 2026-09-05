"""
tests/run_blind_generalization_eval.py
Synthetic/Adversarial Generalization Benchmark.

The synthetic benchmark validates robustness across deliberately varied unseen-like
site structures. It does not by itself establish performance on arbitrary real-world domains.

Evaluates crawler and detector generalization against 21 unseen, adversarial
archetypes with strict ground-truth scoring:
 - expected_rules = findings that SHOULD be present
 - actual_rules   = all findings emitted
 - TP = expected & actual
 - FN = expected - actual
 - FP = actual - expected (strictly penalizes any unpredicted finding)
 - Clean sites have expected_rules = set(), so any emitted defect is an FP.

Reports:
 - Fixture regression performance
 - Crawl-discovery performance (pages sampled, depth distribution, subpage defect discovery)
 - Browser-render recovery performance (escalated, recovered, unusable)
 - Accuracy metrics (TP, FP, FN, precision, recall, false positive rate)
 - Per-case detail report
"""
import importlib.util
import json
import sys

# global getaddrinfo mock for .test domains
import socket
if not hasattr(socket, '_real_c_getaddrinfo'):
    socket._real_c_getaddrinfo = socket.getaddrinfo
def _fake_getaddrinfo(host, port, *args, **kwargs):
    if host and (host.endswith('.test') or host.endswith('.example') or host.endswith('.invalid')):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 0))]
    return socket._real_c_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _fake_getaddrinfo
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_audit",
    ROOT / "skills/audit-orchestrator/scripts/run_audit.py",
)
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)


class MockResponse:
    def __init__(self, content, status=200, url="http://eval.test/", headers=None):
        self._content = content.encode("utf-8") if isinstance(content, str) else content
        self.status = status
        self.url = url
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def read(self, amt=None):
        return self._content

    def geturl(self):
        return self.url

    def getheader(self, name, default=None):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def getcode(self):
        return self.status

    def close(self):
        pass


def make_site_mock(pages, default_robots=None):
    def mock_open(req, timeout=10):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url in pages:
            data = pages[url]
            if isinstance(data, tuple):
                body, status = data[0], data[1]
                ctype = data[2] if len(data) > 2 else "text/html"
                extra_headers = data[3] if len(data) > 3 else {}
                hdrs = {"Content-Type": ctype}
                hdrs.update(extra_headers)
                return MockResponse(body, status, url, hdrs)
            return MockResponse(data, 200, url, {"Content-Type": "text/html"})
        if url.endswith("/robots.txt"):
            rob = default_robots or "User-agent: *\nAllow: /\n"
            return MockResponse(rob, 200, url, {"Content-Type": "text/plain"})
        if url.endswith("/sitemap.xml"):
            return MockResponse("<?xml version='1.0'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'></urlset>", 200, url, {"Content-Type": "application/xml"})
        return MockResponse("<html><body><h1>Not Found</h1></body></html>", 404, url)
    return mock_open


# 21 Unseen Adversarial Fixture Archetypes with Explicit Ground Truth
EVAL_CASES = [
    # -----------------------------------------------------------------------
    # 1. CLEAN MULTI-PAGE PLATFORM (Depth 2 Discovery, Clean Baseline)
    # Expected: 0 findings across 3 sampled pages
    # -----------------------------------------------------------------------
    {
        "id": "01_clean_multipage_saas_platform",
        "url": "https://cloud-ops.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://cloud-ops.test/sitemap.xml\n",
        "pages": {
            "https://cloud-ops.test/": """<!DOCTYPE html><html><head><title>CloudOps Platform - Infrastructure Orchestration</title>
            <meta name="description" content="Automated cloud infrastructure orchestration for container clusters, microservices, and distributed systems.">
            <link rel="canonical" href="https://cloud-ops.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://cloud-ops.test/#org","name":"CloudOps Platform","url":"https://cloud-ops.test/"}</script>
            </head><body><header><nav><a href="/compare-solutions">Compare architectural solutions</a><a href="/work-with-us">Speak with our advisors</a></nav></header>
            <main><h1>Automated Cloud Infrastructure Platform</h1>
            <p>Our distributed deployment orchestrator automates container rollout and high-availability health checking across multi-region hybrid clouds. Continuous configuration synchronization maintains desired cluster state with verifiable operational guarantees.</p>
            <p>Modern engineering teams leverage automated deployment pipelines to safely roll back failed deployments and isolate noisy workloads across dedicated nodes. Production environments benefit from comprehensive metrics collection and predictive scaling algorithms.</p>
            <p>Integrated telemetry streams aggregate distributed traces and host metric counters into high-performance columnar storage for rapid forensic query execution.</p>
            <a href="/work-with-us">Schedule Technical Consultation</a></main></body></html>""",
            "https://cloud-ops.test/compare-solutions": """<!DOCTYPE html><html><head><title>Architecture Comparison Matrix - CloudOps</title>
            <meta name="description" content="Detailed architectural comparison across cloud deployment paradigms and container engines.">
            <link rel="canonical" href="https://cloud-ops.test/compare-solutions">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Architecture Comparison"}</script>
            </head><body><header><nav><a href="/">Home</a><a href="/tiers-and-investment">Review investment tiers</a></nav></header>
            <main><h1>Enterprise Architectural Comparison</h1>
            <p>Compare virtualization strategies, bare metal performance characteristics, and container runtime isolation mechanisms. Our engine guarantees deterministic CPU scheduling and low-latency network packet delivery across all tenant boundaries.</p>
            <p>Select the deployment topology that aligns with internal compliance requirements, data sovereignty constraints, and latency Service Level Objectives. We support hybrid on-premise hardware appliances alongside major public hyperscalers.</p>
            <p>Every architecture variant includes dedicated telemetry pipelines, automated failover routing, and hardened cryptographic transport layers to defend mission-critical services against network partition hazards.</p>
            <p>Platform operators maintain full governance over container image registries and enforce cryptographic signature verification prior to host scheduling.</p>
            <a href="/tiers-and-investment">Explore Investment Options</a></main></body></html>""",
            "https://cloud-ops.test/tiers-and-investment": """<!DOCTYPE html><html><head><title>Investment Tiers and Enterprise Capacity - CloudOps</title>
            <meta name="description" content="Flexible infrastructure deployment tiers tailored for growing engineering teams and enterprises.">
            <link rel="canonical" href="https://cloud-ops.test/tiers-and-investment">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Investment Tiers"}</script>
            </head><body><header><nav><a href="/">Home</a><a href="/compare-solutions">Solutions</a></nav></header>
            <main><h1>Enterprise Investment Framework</h1>
            <p>We provide transparent operational investment models based on active compute nodes and dedicated network ingress bandwidth. Choose between managed SaaS coordination planes or self-hosted air-gapped deployments.</p>
            <p>Every tier includes round-the-clock site reliability engineering escalations, dedicated solution architects, and custom telemetry data retention policies.</p>
            <p>Our capacity reservation contracts protect enterprise workloads against unexpected pricing surges during catastrophic traffic surges across public cloud zones.</p>
            <p>Volume licensing commitments provide significant unit cost reductions for high-density compute deployments and extended multi-year infrastructure roadmaps.</p>
            <p>Enterprise infrastructure investment plans provide guaranteed compute capacity reservations across multi-tenant regions. Engineering organizations receive dedicated solution architect advisory hours and customized disaster recovery orchestration.</p>
            <a href="/work-with-us">Request Custom Quotation</a></main></body></html>""",
            "https://cloud-ops.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://cloud-ops.test/</loc></url>
                <url><loc>https://cloud-ops.test/compare-solutions</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 2. CONSULTING BOUTIQUE (No Pricing, Natural Semantic Navigation)
    # Expected: 0 findings (no false defect for missing pricing)
    # -----------------------------------------------------------------------
    {
        "id": "02_consulting_boutique_no_pricing",
        "url": "https://strategy-boutique.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://strategy-boutique.test/sitemap.xml\n",
        "pages": {
            "https://strategy-boutique.test/": """<!DOCTYPE html><html><head><title>Vanguard Advisory Partners</title>
            <meta name="description" content="Strategic executive advisory firm counseling enterprise leadership on corporate governance and organizational design.">
            <link rel="canonical" href="https://strategy-boutique.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://strategy-boutique.test/#org","name":"Vanguard Advisory Partners","url":"https://strategy-boutique.test/"}</script>
            </head><body><header><nav><a href="/case-studies">Representative Engagements</a><a href="/work-with-us">Speak with our advisors</a></nav></header>
            <main><h1>Executive Leadership and Advisory</h1>
            <p>We provide discreet board-level counsel on capital allocation, organizational succession, and transformational restructuring. Our senior partners work directly with executive leadership committees to navigate complex market transitions.</p>
            <p>Our bespoke engagements are tailored exclusively to enterprise scale and long-term shareholder value creation. We accept only a limited number of advisory mandates annually to maintain direct partner involvement.</p>
            <p>Senior leadership teams benefit from proprietary research methodologies and independent governance benchmarking developed over three decades of practice.</p>
            <a href="/work-with-us">Inquire About Engagement</a></main></body></html>""",
            "https://strategy-boutique.test/work-with-us": """<!DOCTYPE html><html><head><title>Engagement Inquiry - Vanguard Advisory</title>
            <meta name="description" content="Initiate a confidential discussion with our senior advisory partners.">
            <link rel="canonical" href="https://strategy-boutique.test/work-with-us">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"ContactPage","name":"Engagement Inquiry"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Confidential Strategic Inquiries</h1>
            <p>Prospective client engagements begin with an introductory consultation with an industry practice lead. All communications are protected under mutual non-disclosure covenants.</p>
            <p>Our practice leads review submissions within one business day to determine conflict clearance and team availability across international jurisdictions.</p>
            <p>Please outline your organizational context, current board priorities, and anticipated project timeline in your introductory message to ensure timely routing.</p>
            <p>Our advisory panel convenes bi-weekly to assign partner teams to qualified corporate mandates and strategic transaction advisory roles across key industry verticals.</p>
            <p>Senior practice directors evaluate board-level mandate specifications and prepare bespoke engagement agreements outlining project phases, governance milestones, and advisory deliverables.</p>
            <a href="mailto:partners@strategy-boutique.test">Submit Direct Consultation Request</a></main></body></html>""",
            "https://strategy-boutique.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://strategy-boutique.test/</loc></url>
                <url><loc>https://strategy-boutique.test/work-with-us</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 3. DEVELOPER UTILITY (No About Page, Sparse Legitimate Home)
    # Expected: 0 findings (no false defect for missing About or sparse homepage)
    # -----------------------------------------------------------------------
    {
        "id": "03_developer_utility_no_about",
        "url": "https://quick-cli.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://quick-cli.test/sitemap.xml\n",
        "pages": {
            "https://quick-cli.test/": """<!DOCTYPE html><html><head><title>QuickCLI Binary Tool</title>
            <meta name="description" content="Single-binary command line utility for parsing NDJSON streams.">
            <link rel="canonical" href="https://quick-cli.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"QuickCLI","applicationCategory":"DeveloperApplication"}</script>
            </head><body><header><nav><a href="/documentation/cli-reference">Command Line Reference</a><a href="/api/v2-specs">API Specifications</a></nav></header>
            <main><h1>Fast Stream Parsing Utility</h1>
            <p>QuickCLI filters gigabyte-scale structured newline-delimited JSON streams in constant memory with zero heap allocations. Designed specifically for low-latency Unix pipeline processing and automated log analytics workflows.</p>
            <pre><code>curl -sL https://quick-cli.test/install.sh | bash</code></pre>
            <a href="/documentation/cli-reference">Explore Documentation</a></main></body></html>""",
            "https://quick-cli.test/documentation/cli-reference": """<!DOCTYPE html><html><head><title>CLI Reference - QuickCLI</title>
            <meta name="description" content="Complete command-line flags, environment variables, and exit codes for QuickCLI.">
            <link rel="canonical" href="https://quick-cli.test/documentation/cli-reference">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"CLI Reference"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Command Reference Guide</h1>
            <p>Detailed breakdown of CLI argument parsing flags, buffered I/O options, concurrency workers, and regex filter expressions. The binary supports standard UNIX pipes and POSIX stream semantics.</p>
            <p>Use the memory limit flag to enforce deterministic ceiling limits on containerized execution environments. Output streams can be redirected directly into gzip compressors without pipeline stalls.</p>
            <p>Automated benchmarks verify sustained processing throughput exceeding ten million records per second on commodity multicore server hardware without memory degradation.</p>
            <p>Configurable exit codes integrate cleanly with containerized orchestration systems and automated monitoring alert daemons.</p>
            <p>Developers can pipe standard input directly into downstream transformation scripts or store intermediate binary traces in localized temporary files without degrading processing throughput.</p>
            <a href="/">Download QuickCLI Binary</a></main></body></html>""",
            "https://quick-cli.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://quick-cli.test/</loc></url>
                <url><loc>https://quick-cli.test/documentation/cli-reference</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 4. MULTILINGUAL GERMAN STORE (German Navigation & German CTA)
    # Expected: 0 findings (no false defect on German CTA or navigation)
    # -----------------------------------------------------------------------
    {
        "id": "04_german_multilingual_store",
        "url": "https://industrie-shop.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://industrie-shop.test/sitemap.xml\n",
        "pages": {
            "https://industrie-shop.test/": """<!DOCTYPE html><html lang="de"><head><title>IndustrieTech Hardware Katalog</title>
            <meta name="description" content="Zertifizierte Komponenten und Messgeräte für Automatisierung und Fertigungsanlagen.">
            <link rel="canonical" href="https://industrie-shop.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://industrie-shop.test/#org","name":"IndustrieTech GmbH","url":"https://industrie-shop.test/"}</script>
            </head><body><header><nav><a href="/produkte/server-rack">Unsere Serverlösungen</a><a href="/kontakt">Technischer Kundendienst</a></nav></header>
            <main><h1>Industrielle Steuerungssysteme und Messtechnik</h1>
            <p>Wir liefern hochpräzise speicherprogrammierbare Steuerungen, industrielle Netzwerkhubs und robuste Sensormodule für anspruchsvolle Fertigungsumgebungen weltweit.</p>
            <p>Unsere Systeme erfüllen höchste Sicherheitsstandards nach ISO-Zertifizierung und garantieren unterbrechungsfreien Dauerbetrieb in Produktionsstraßen.</p>
            <p>Erfahrene Vertriebsingenieure beraten Sie gerne bei der Dimensionierung Ihrer Automatisierungshardware und Steuerungsarchitektur.</p>
            <a href="/produkte/server-rack">Produkte Jetzt Anfragen und Bestellen</a></main></body></html>""",
            "https://industrie-shop.test/produkte/server-rack": """<!DOCTYPE html><html lang="de"><head><title>Server Rack Systeme - IndustrieTech</title>
            <meta name="description" content="Schwingungsgedämpfte 19-Zoll Industrie Server Racks für Rechenzentren.">
            <link rel="canonical" href="https://industrie-shop.test/produkte/server-rack">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Industrie Server Rack 42HE","offers":{"@type":"Offer","price":"1299.00","priceCurrency":"EUR"}}</script>
            </head><body><header><nav><a href="/">Startseite</a></nav></header>
            <main><h1>Modulare Server Rack Systeme</h1>
            <p>Robuste 19-Zoll Rackschränke mit integrierter passiver Luftkühlung, Kabelführungskanälen und redundantem Schließsystem für maximale Datensicherheit.</p>
            <p>Jedes Serversystem wird vor Auslieferung unter thermischer Volllast umfassend qualitätsgeprüft und mit detaillierten Messprotokollen versehen.</p>
            <p>Modulare Einschubschienen ermöglichen den werkzeuglosen Austausch von Lüfterkassetten und Netzteilen während des laufenden Betriebs.</p>
            <p>Unsere Servergehäuse bieten optimalen Schutz gegen elektromagnetische Störfelder und mechanische Vibrationen im industriellen Dauerbetrieb.</p>
            <p>Integrierte Temperaturfühler und automatische Überlastungssensoren überwachen kontinuierlich die Umgebungsbedingungen im Rack-Innenraum. Unsere Gehäusesysteme gewährleisten höchste Betriebssicherheit in kritischen Industrieumgebungen mit anspruchsvollen klimatischen Anforderungen.</p>
            <p>Kundenorientierte Anpassungen wie kundenspezifische Bohrungen, spezielle Pulverbeschichtungen und vorinstallierte Stromverteilerleisten realisieren wir flexibel nach Ihren technischen Spezifikationen.</p>
            <button type="submit">Jetzt Angebot Anfordern</button></main></body></html>""",
            "https://industrie-shop.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://industrie-shop.test/</loc></url>
                <url><loc>https://industrie-shop.test/produkte/server-rack</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 5. UNUSUAL ACTION CTA (Academic Fellowship Site)
    # Expected: 0 findings (no false defect on unusual action verbs)
    # -----------------------------------------------------------------------
    {
        "id": "05_unusual_cta_fellowship",
        "url": "https://frontier-institute.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://frontier-institute.test/sitemap.xml\n",
        "pages": {
            "https://frontier-institute.test/": """<!DOCTYPE html><html><head><title>Frontier Research Foundation</title>
            <meta name="description" content="Supporting independent postdoctoral research fellowships in theoretical physics and quantum computation.">
            <link rel="canonical" href="https://frontier-institute.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://frontier-institute.test/#org","name":"Frontier Research Foundation","url":"https://frontier-institute.test/"}</script>
            </head><body><header><nav><a href="/initiatives">Research Initiatives</a><a href="/apply-fellowship">Fellowship Application</a></nav></header>
            <main><h1>Theoretical Physics Research Fellowships</h1>
            <p>The Frontier Research Foundation awards full multi-year endowments to exceptional investigators pursuing fundamental questions in quantum topology, astrophysics, and computational complexity.</p>
            <p>Fellows receive unrestricted funding, dedicated lab computing resources, and access to international collaborative networks.</p>
            <p>Applications undergo rigorous double-blind evaluation by an international committee of distinguished senior researchers.</p>
            <a href="/apply-fellowship">Submit Fellowship Application</a></main></body></html>""",
            "https://frontier-institute.test/apply-fellowship": """<!DOCTYPE html><html><head><title>Apply for Fellowship - Frontier Foundation</title>
            <meta name="description" content="Online submission portal for postdoctoral research grant proposals.">
            <link rel="canonical" href="https://frontier-institute.test/apply-fellowship">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Fellowship Application"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Grant Proposal Portal</h1>
            <p>Candidates must provide a comprehensive five-page research proposal, curriculum vitae, and letters of recommendation from prior faculty advisors.</p>
            <p>The review committee convenes annually in autumn to select award recipients following blind peer evaluation.</p>
            <p>All funded researchers retain complete intellectual property ownership over their theoretical findings and published manuscripts.</p>
            <p>Applicants may submit supplemental scientific code or simulation datasets through the authenticated portal after registering.</p>
            <p>The advisory panel assesses theoretical rigor, originality, and long-term potential for breakthrough contributions to foundational scientific knowledge. Candidates are notified of preliminary review outcomes within six weeks of the submission deadline.</p>
            <button type="submit">Claim Research Grant</button></main></body></html>""",
            "https://frontier-institute.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://frontier-institute.test/</loc></url>
                <url><loc>https://frontier-institute.test/apply-fellowship</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 6. DECORATIVE ACCESSIBLE SVG (aria-hidden="true" and role="img")
    # Expected: 0 findings (decorative SVGs must NOT trigger SD-NONTEXT-001)
    # -----------------------------------------------------------------------
    {
        "id": "06_decorative_accessible_svg_studio",
        "url": "https://vector-studio.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://vector-studio.test/sitemap.xml\n",
        "pages": {
            "https://vector-studio.test/": """<!DOCTYPE html><html><head><title>VectorCraft Design Studio</title>
            <meta name="description" content="Boutique brand identity and interactive graphic design agency based in Zurich.">
            <link rel="canonical" href="https://vector-studio.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://vector-studio.test/#org","name":"VectorCraft","url":"https://vector-studio.test/"}</script>
            </head><body><header><nav><a href="/portfolio">Portfolio</a><a href="/work-with-us">Inquire</a></nav></header>
            <main><h1>Boutique Digital Brand Design</h1>
            <svg role="img" aria-label="VectorCraft Studio Emblem" width="120" height="40"><circle cx="20" cy="20" r="10"/><text x="40" y="25">VectorCraft</text></svg>
            <svg aria-hidden="true" width="24" height="24"><path d="M0 0h24v24H0z"/></svg>
            <p>We build timeless visual identities, custom typography systems, and high-performance digital products for category-defining technology brands worldwide.</p>
            <p>Every design system is crafted with rigorous attention to proportion, typographic hierarchy, and cross-platform accessibility.</p>
            <p>Our multidisciplinary team partners with forward-thinking founders to articulate distinct aesthetic narratives across web and print touchpoints.</p>
            <a href="/work-with-us">Initiate Design Dialogue</a></main></body></html>""",
            "https://vector-studio.test/portfolio": """<!DOCTYPE html><html><head><title>Portfolio - VectorCraft Studio</title>
            <meta name="description" content="Curated showcase of visual brand identities and design systems.">
            <link rel="canonical" href="https://vector-studio.test/portfolio">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"CollectionPage","name":"Studio Portfolio"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Selected Studio Works</h1>
            <svg aria-hidden="true" width="32" height="32"><circle cx="16" cy="16" r="12"/></svg>
            <p>A retrospective collection of international brand identity commissions spanning fintech, biotechnology, and autonomous robotics platforms.</p>
            <p>All client case studies demonstrate measurable uplift in market perception and brand consistency across diverse channels.</p>
            <p>Detailed project documentation showcases the typographic progression from initial sketch concepts to global asset deployment.</p>
            <p>Each project artifact includes high-resolution responsive vector exports, detailed color space specifications for digital screens and physical print, and comprehensive interactive motion design design guides.</p>
            <p>Our design agency collaborates with multidisciplinary production teams to oversee design implementation across global digital channels.</p>
            <p>Strategic brand design commissions empower innovative engineering organizations to differentiate their technical capabilities and establish compelling market leadership globally.</p>
            <a href="/work-with-us">Schedule Design Review</a></main></body></html>""",
            "https://vector-studio.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://vector-studio.test/</loc></url>
                <url><loc>https://vector-studio.test/portfolio</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 7. UNSUPPORTED PDF DOCUMENT
    # Expected: 0 findings (PDF must not emit HTML absence findings)
    # -----------------------------------------------------------------------
    {
        "id": "07_unsupported_pdf_whitepaper",
        "url": "https://whitepapers.test/report.pdf",
        "pages": {
            "https://whitepapers.test/report.pdf": (b"%PDF-1.7\n%\xbf\xf7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF", 200, "application/pdf"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 8. UNSUPPORTED RAW IMAGE
    # Expected: 0 findings (Image must not emit HTML absence findings)
    # -----------------------------------------------------------------------
    {
        "id": "08_unsupported_raw_image",
        "url": "https://media.test/diagram.jpg",
        "pages": {
            "https://media.test/diagram.jpg": (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00", 200, "image/jpeg"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 9. UNSUPPORTED BINARY STREAM
    # Expected: 0 findings (Binary stream must not emit HTML absence findings)
    # -----------------------------------------------------------------------
    {
        "id": "09_unsupported_binary_octet",
        "url": "https://downloads.test/binary.bin",
        "pages": {
            "https://downloads.test/binary.bin": (b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00", 200, "application/octet-stream"),
        },
        "expected_rules": set(),
    },

    # -----------------------------------------------------------------------
    # 10. PROTOCOL BLOCKED / 403 BOT CHALLENGE
    # Expected: {"CR-STATUS-001"}
    # -----------------------------------------------------------------------
    {
        "id": "10_blocked_bot_challenge_403",
        "url": "https://waf-protected.test/",
        "robots": "User-agent: *\nDisallow: /admin\n",
        "pages": {
            "https://waf-protected.test/": ("""<!DOCTYPE html><html><head><title>403 Forbidden</title></head>
            <body><h1>Access Denied</h1><p>Automated request blocked by perimeter defense.</p></body></html>""", 403, "text/html"),
        },
        "expected_rules": {"CR-STATUS-001"},
    },

    # -----------------------------------------------------------------------
    # 11. SOFT BLOCK / 200 CLOUDFLARE CHALLENGE
    # Expected: {"CQ-SOFT-BLOCK-001"}
    # -----------------------------------------------------------------------
    {
        "id": "11_soft_block_challenge_200",
        "url": "https://shielded-origin.test/",
        "robots": "User-agent: *\nAllow: /\n",
        "pages": {
            "https://shielded-origin.test/": """<!DOCTYPE html><html><head><title>Just a moment...</title></head>
            <body><div class="cf-challenge-running">Checking your browser before accessing the site.</div>
            <p>Security check: Please verify you are a human to continue. DDoS protection by Cloudflare.</p>
            <div>Ray ID: 7a8b9c0d1e2f3a4b</div></body></html>""",
        },
        "expected_rules": {"CQ-SOFT-BLOCK-001"},
    },

    # -----------------------------------------------------------------------
    # 12. SPA UNRENDERED SHELL (Browser Unavailable / Escalation Fails)
    # Expected: {"CR-RENDER-SPA-001"}
    # -----------------------------------------------------------------------
    {
        "id": "12_spa_unrendered_shell_failure",
        "url": "https://spa-unrendered.test/",
        "robots": "User-agent: *\nAllow: /\n",
        "pages": {
            "https://spa-unrendered.test/": """<!DOCTYPE html><html><head><title>Loading Application...</title></head>
            <body><div id="root"></div><script src="/static/js/bundle.main.js"></script></body></html>""",
        },
        "expected_rules": {"CR-RENDER-SPA-001"},
    },

    # -----------------------------------------------------------------------
    # 13. SPA BROWSER RECOVERY (Actual Headless Hydration Succeeded)
    # Expected: {"CR-RENDER-GAP-001"}
    # Escalation: attempted=1, recovered=1, unusable=0
    # Downstream consumed: H1, CTA, Schema.org all verified from rendered DOM!
    # -----------------------------------------------------------------------
    {
        "id": "13_spa_browser_recovery_success",
        "url": "https://spa-hydrated.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://spa-hydrated.test/sitemap.xml\n",
        "pages": {
            "https://spa-hydrated.test/": """<!DOCTYPE html><html><head><title>Loading Application...</title></head>
            <body><div id="root"></div><script src="/static/js/bundle.main.js"></script></body></html>""",
            "https://spa-hydrated.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://spa-hydrated.test/</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "rendered_pages": {
            "https://spa-hydrated.test/": """<!DOCTYPE html><html><head><title>CloudScale Enterprise Platform</title>
            <meta name="description" content="Next-generation cloud telemetry and automated microservice routing platform for hybrid infrastructure.">
            <link rel="canonical" href="https://spa-hydrated.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"CloudScale","applicationCategory":"BusinessApplication"}</script>
            </head><body><div id="root">
                <header><nav><a href="/getting-started">Getting Started</a><a href="/work-with-us">Contact Us</a></nav></header>
                <main><h1>Cloud Automation and Microservice Telemetry</h1>
                <p>Continuous distributed cluster state management across global availability zones. Zero-overhead container observability integrated with automated traffic failover and predictive workload scheduling.</p>
                <p>Ensure mission-critical reliability with deterministic health checks and automated failover routing across edge networks. Seamlessly integrate with modern CI/CD automation workflows and Kubernetes deployment manifests.</p>
                <p>Our distributed tracing infrastructure correlates logs, metrics, and network spans in real time to deliver actionable diagnostic intelligence during complex production outages across distributed hybrid cloud clusters.</p>
                <a href="/getting-started">Deploy Your Cluster Now</a></main>
            </div></body></html>""",
        },
        "expected_rules": {"CR-RENDER-GAP-001"},
    },

    # -----------------------------------------------------------------------
    # 14. DEEP NAVIGATION DEFECT (Depth 2 Discovery: Missing H1 & Meta)
    # Expected: {"ENG-H1-ZERO-001", "CQ-META-001"}
    # Crawler navigates: homepage -> /getting-started (depth 1) -> /client-portal/access-guide (depth 2)
    # -----------------------------------------------------------------------
    {
        "id": "14_deep_navigation_missing_h1_depth2",
        "url": "https://portal-docs.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://portal-docs.test/sitemap.xml\n",
        "pages": {
            "https://portal-docs.test/": """<!DOCTYPE html><html><head><title>Portal Documentation Gateway</title>
            <meta name="description" content="Comprehensive developer guides, authentication walkthroughs, and client access instructions.">
            <link rel="canonical" href="https://portal-docs.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Portal Docs","url":"https://portal-docs.test/"}</script>
            </head><body><header><nav><a href="/getting-started">Getting Started Guide</a><a href="/support">Support</a></nav></header>
            <main><h1>Developer Documentation Center</h1>
            <p>Welcome to our comprehensive developer documentation. Explore security architectures, SDK client libraries, and production API integration patterns across cloud platforms.</p>
            <p>Our guides provide concrete code samples and reference architectures to accelerate your engineering onboarding timeline.</p>
            <p>Stay informed regarding API deprecation timelines and backward-compatible schema evolutions through our developer newsletter.</p>
            <a href="/getting-started">Explore Integration Walkthrough</a></main></body></html>""",
            "https://portal-docs.test/getting-started": """<!DOCTYPE html><html><head><title>Getting Started - Portal Docs</title>
            <meta name="description" content="Initial setup steps and environment configuration for the client portal.">
            <link rel="canonical" href="https://portal-docs.test/getting-started">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Getting Started"}</script>
            </head><body><header><nav><a href="/">Home</a><a href="/client-portal/access-guide">Security Access Documentation</a></nav></header>
            <main><h1>Initial Environment Setup</h1>
            <p>Follow these initial instructions to authenticate your staging environment with the central authorization server before dispatching production payload requests.</p>
            <p>Generate your client credentials from the developer settings pane and configure your localized environment variables accordingly.</p>
            <p>Validate your network egress rules to ensure secure TLS connections can reach the telemetry ingestion gateways.</p>
            <p>Once initial authorization succeeds, configure client retries with exponential backoff and circuit breaking thresholds to prevent cascade failures.</p>
            <p>Verify network reachability and validate security credentials before attempting API calls from your local development environment. Detailed diagnostic logging assists engineers during initial environment troubleshooting.</p>
            <a href="/client-portal/access-guide">Explore Security Access Documentation</a></main></body></html>""",
            "https://portal-docs.test/client-portal/access-guide": """<!DOCTYPE html><html><head><title>Security Access Documentation</title>
            <link rel="canonical" href="https://portal-docs.test/client-portal/access-guide">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Access Documentation"}</script>
            </head><body><header><nav><a href="/getting-started">Back</a></nav></header>
            <main><p>This deep guide covers mandatory OAuth 2.0 mutual TLS certificate authentication protocols and token lifecycle renewals across enterprise ingress endpoints.</p>
            <p>Network engineers must configure reverse proxy listeners to terminate client TLS certificates and validate thumbprint digests against the central security registry.</p>
            <p>Audit logs record all access delegation requests to ensure full traceability under SOC 2 and ISO compliance frameworks.</p>
            <p>Certificate renewal workflows execute automatically thirty days prior to expiration to eliminate unexpected operational interruptions across production clusters.</p>
            <p>Automated telemetry alerts inform administrators regarding certificate renewal milestones and potential credential revocations. System engineers must maintain redundant ingress tunnels during security key rotation windows.</p>
            <a href="/getting-started">Inquire With Security Engineering Team</a></main></body></html>""",
            "https://portal-docs.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://portal-docs.test/</loc></url>
                <url><loc>https://portal-docs.test/getting-started</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"ENG-H1-ZERO-001", "CQ-META-001"},
    },

    # -----------------------------------------------------------------------
    # 15. SUBPAGE CONFLICTING H1 (Discovered via Semantic Anchor Text)
    # Expected: {"ENG-H1-MULTI-001"}
    # -----------------------------------------------------------------------
    {
        "id": "15_subpage_conflicting_h1",
        "url": "https://cluster-tech.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://cluster-tech.test/sitemap.xml\n",
        "pages": {
            "https://cluster-tech.test/": """<!DOCTYPE html><html><head><title>ClusterTech Computing Systems</title>
            <meta name="description" content="Next-generation high-performance computing hardware and orchestration nodes.">
            <link rel="canonical" href="https://cluster-tech.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://cluster-tech.test/#org","name":"ClusterTech","url":"https://cluster-tech.test/"}</script>
            </head><body><header><nav><a href="/platform/overview">Explore our unified computing substrate</a></nav></header>
            <main><h1>Unified High-Performance Computing</h1>
            <p>ClusterTech designs distributed hardware clusters tailored for petabyte-scale simulation, numerical modeling, and real-time inference workloads.</p>
            <p>Our interconnect fabric guarantees non-blocking bisection bandwidth and microsecond packet switching across tens of thousands of compute cores.</p>
            <p>Engineers deploy turnkey computing racks pre-configured with liquid cooling manifolds and redundant power supplies.</p>
            <a href="/platform/overview">Explore Platform Architecture</a></main></body></html>""",
            "https://cluster-tech.test/platform/overview": """<!DOCTYPE html><html><head><title>Platform Architecture Overview - ClusterTech</title>
            <meta name="description" content="Detailed architectural overview of our unified computing substrate and storage tiers.">
            <link rel="canonical" href="https://cluster-tech.test/platform/overview">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Architecture Overview"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Unified Computing Substrate</h1>
            <p>Our integrated hardware architecture combines ultra-dense compute nodes with coherent shared memory pools to eliminate inter-chassis networking bottlenecks.</p>
            <h1>Distributed Compute Engine</h1>
            <p>Engineers can dynamically partition physical compute resources into virtual topologies optimized for custom scientific workloads and tensor computations.</p>
            <p>High-throughput direct memory access channels accelerate cluster synchronization during parallel matrix multiplication routines.</p>
            <p>Low-latency telemetry collectors continuously sample thermal sensor outputs to optimize dynamic frequency scaling across active workloads.</p>
            <p>Dynamic interconnect balancing minimizes latency across distributed node groups and accelerates large-scale matrix operations. System administrators configure hardware partitions via programmatic RESTful APIs.</p>
            <p>Integrated diagnostic tooling continuously benchmarks communication latency across physical server racks.</p>
            <a href="/">Schedule Technical Architecture Demo</a></main></body></html>""",
            "https://cluster-tech.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://cluster-tech.test/</loc></url>
                <url><loc>https://cluster-tech.test/platform/overview</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"ENG-H1-MULTI-001"},
    },

    # -----------------------------------------------------------------------
    # 16. SUBPAGE BROKEN JSON-LD (Discovered Subpage Syntax Defect)
    # Expected: {"SD-SYNTAX-001"}
    # -----------------------------------------------------------------------
    {
        "id": "16_subpage_broken_jsonld_syntax",
        "url": "https://analytics-hub.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://analytics-hub.test/sitemap.xml\n",
        "pages": {
            "https://analytics-hub.test/": """<!DOCTYPE html><html><head><title>Analytics Hub Real-Time Telemetry</title>
            <meta name="description" content="Streaming analytics ingestion platform handling enterprise metric pipelines.">
            <link rel="canonical" href="https://analytics-hub.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://analytics-hub.test/#org","name":"Analytics Hub","url":"https://analytics-hub.test/"}</script>
            </head><body><header><nav><a href="/integrations/data-pipeline">Connect telemetry channels</a></nav></header>
            <main><h1>Real-Time Streaming Telemetry Hub</h1>
            <p>Process, aggregate, and visualize high-throughput system telemetry across globally distributed cloud infrastructure with sub-second dashboard rendering.</p>
            <p>Our columnar storage engine compresses time-series metrics efficiently while preserving granular raw query capabilities across long temporal windows.</p>
            <p>Built-in anomaly detection models continuously evaluate metric deviations to alert on-call teams before user-facing degradations manifest.</p>
            <a href="/integrations/data-pipeline">Explore Ingestion Options</a></main></body></html>""",
            "https://analytics-hub.test/integrations/data-pipeline": """<!DOCTYPE html><html><head><title>Data Pipeline Integration - Analytics Hub</title>
            <meta name="description" content="Configure managed data pipelines and real-time Kafka event streams.">
            <link rel="canonical" href="https://analytics-hub.test/integrations/data-pipeline">
            <script type="application/ld+json">{"@context": "https://schema.org",</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Telemetry Data Pipeline Integration</h1>
            <p>Connect your Apache Kafka, AWS Kinesis, or Google Cloud Pub/Sub topics to stream structured events directly into your analytics cluster with verified delivery semantics.</p>
            <p>Our ingestion workers automatically negotiate batch sizes and backpressure to ensure zero data loss during upstream traffic spikes.</p>
            <p>All pipeline connections enforce TLS 1.3 encryption and support automated schema registry verification across message formats.</p>
            <p>Enterprise connectors support bidirectional streaming synchronization with popular data warehouse destinations.</p>
            <p>Streaming workers execute real-time validation schemas and automatically quarantine malformed messages without interrupting downstream processing pipelines. Cluster health dashboards provide immediate visibility into throughput and lag metrics.</p>
            <a href="/">Register New Telemetry Pipeline</a></main></body></html>""",
            "https://analytics-hub.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://analytics-hub.test/</loc></url>
                <url><loc>https://analytics-hub.test/integrations/data-pipeline</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"SD-SYNTAX-001"},
    },

    # -----------------------------------------------------------------------
    # 17. SUBSTANTIVE SVG WITHOUT LABELING (Distinguished from Decorative)
    # Expected: {"SD-NONTEXT-001"}
    # -----------------------------------------------------------------------
    {
        "id": "17_substantive_svg_without_labeling",
        "url": "https://geometry-lab.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://geometry-lab.test/sitemap.xml\n",
        "pages": {
            "https://geometry-lab.test/": """<!DOCTYPE html><html><head><title>Geometry Computational Laboratory</title>
            <meta name="description" content="Advanced mathematical simulation of geometric manifolds and topological surfaces.">
            <link rel="canonical" href="https://geometry-lab.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","@id":"https://geometry-lab.test/#org","name":"Geometry Lab","url":"https://geometry-lab.test/"}</script>
            </head><body><header><nav><a href="/research">Research</a><a href="/publications">Publications</a></nav></header>
            <main><h1>Computational Topology and Manifolds</h1>
            <svg width="400" height="300"><polygon points="100,10 40,198 190,78 10,78 160,198"/><circle cx="100" cy="100" r="50"/></svg>
            <p>Our computational researchers investigate discrete differential geometry, mesh parameterization algorithms, and numerical methods for non-Euclidean manifolds.</p>
            <p>We publish open-source mathematical libraries supporting finite element simulations and real-time surface deformation across irregular domain boundaries.</p>
            <p>Researchers collaborate with international institutions to model complex fluid dynamics and structural mechanics problems.</p>
            <a href="/research">View Published Manuscripts and Research</a></main></body></html>""",
            "https://geometry-lab.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://geometry-lab.test/</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"SD-NONTEXT-001"},
    },

    # -----------------------------------------------------------------------
    # 18. DEEP DUPLICATE CONTENT (Cross-Endpoint Documentation Duplicate)
    # Expected: {"CQ-EXACT-DUP-001"}
    # Crawler must sample both /docs/v1 and /docs/v2 to detect SHA collision!
    # -----------------------------------------------------------------------
    {
        "id": "18_deep_duplicate_content",
        "url": "https://mirror-docs.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://mirror-docs.test/sitemap.xml\n",
        "pages": {
            "https://mirror-docs.test/": """<!DOCTYPE html><html><head><title>System Documentation Portal</title>
            <meta name="description" content="Central engineering portal for cloud architecture deployment specifications and release guides.">
            <link rel="canonical" href="https://mirror-docs.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"System Docs","url":"https://mirror-docs.test/"}</script>
            </head><body><header><nav><a href="/docs/v1/deploy-guide">Version 1 Documentation</a><a href="/docs/v2/deploy-guide">Version 2 Documentation</a></nav></header>
            <main><h1>Central Architecture Gateway</h1>
            <p>Welcome to our cloud operations architecture portal. Review deployment telemetry, infrastructure provisioning scripts, and distributed cluster status across global production availability zones. All configuration files follow declarative deployment specifications.</p>
            <p>Please select the active documentation stream matching your target environment version.</p>
            <p>Production engineering teams rely on our documentation to maintain consistent cluster operations worldwide.</p>
            <a href="/docs/v1/deploy-guide">Explore Version 1 Deployment Guide</a></main></body></html>""",
            "https://mirror-docs.test/docs/v1/deploy-guide": """<!DOCTYPE html><html><head><title>Production Deployment Guide</title>
            <meta name="description" content="Detailed deployment guide for production cloud clusters.">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Production Deployment"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Production Deployment Specification</h1>
            <h2>Cluster Architecture Overview</h2>
            <p>Identical replicated substantive engineering documentation paragraph repeated verbatim across separate URL endpoints without proper canonical configuration. Modern distributed cloud architecture relies on robust decoupled services communicating over asynchronous message brokers to maintain system resilience under peak load scenarios.</p>
            <p>Ensuring cluster health requires active health-checking across all secondary replicas, verified data consistency, and deterministic failover routing policies. Engineers must regularly audit network partitions and latency degradation to prevent cascade failures across isolated server groups.</p>
            <p>Automated alerting triggers failover procedures whenever heartbeat signals degrade across availability zones. Production workloads remain resilient when backup failover channels are pre-warmed and continuously validated against active traffic patterns.</p>
            <a href="/">Submit Deployment Validation Request</a></main></body></html>""",
            "https://mirror-docs.test/docs/v2/deploy-guide": """<!DOCTYPE html><html><head><title>Production Deployment Guide</title>
            <meta name="description" content="Detailed deployment guide for production cloud clusters.">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"TechArticle","headline":"Production Deployment"}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>Production Deployment Specification</h1>
            <h2>Cluster Architecture Overview</h2>
            <p>Identical replicated substantive engineering documentation paragraph repeated verbatim across separate URL endpoints without proper canonical configuration. Modern distributed cloud architecture relies on robust decoupled services communicating over asynchronous message brokers to maintain system resilience under peak load scenarios.</p>
            <p>Ensuring cluster health requires active health-checking across all secondary replicas, verified data consistency, and deterministic failover routing policies. Engineers must regularly audit network partitions and latency degradation to prevent cascade failures across isolated server groups.</p>
            <p>Automated alerting triggers failover procedures whenever heartbeat signals degrade across availability zones. Production workloads remain resilient when backup failover channels are pre-warmed and continuously validated against active traffic patterns.</p>
            <a href="/">Submit Deployment Validation Request</a></main></body></html>""",
            "https://mirror-docs.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://mirror-docs.test/</loc></url>
                <url><loc>https://mirror-docs.test/docs/v1/deploy-guide</loc></url>
                <url><loc>https://mirror-docs.test/docs/v2/deploy-guide</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"CQ-EXACT-DUP-001"},
    },

    # -----------------------------------------------------------------------
    # 19. CROSS-PAGE CONTRADICTORY PRICING (Corroboration Defect)
    # Expected: {"ENT-CONFLICT-PRICE-001"}
    # Homepage claims $49, subpage claims $149 for the exact same product!
    # -----------------------------------------------------------------------
    {
        "id": "19_cross_page_contradictory_pricing",
        "url": "https://saas-pricing-conflict.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://saas-pricing-conflict.test/sitemap.xml\n",
        "pages": {
            "https://saas-pricing-conflict.test/": """<!DOCTYPE html><html><head><title>CloudPro Observability Suite</title>
            <meta name="description" content="CloudPro provides enterprise infrastructure monitoring and metric log collection.">
            <link rel="canonical" href="https://saas-pricing-conflict.test/">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"CloudPro Suite","offers":{"@type":"Offer","price":"49.00","priceCurrency":"USD"}}</script>
            </head><body><header><nav><a href="/tiers-and-investment">Explore enterprise tiers and investment</a></nav></header>
            <main><h1>Enterprise Infrastructure Observability</h1>
            <p>CloudPro monitors distributed Kubernetes workloads, application latency, and database query throughput across hybrid infrastructure. Automated alerting and root-cause machine learning reduce incident triage time from hours to minutes.</p>
            <p>Our telemetry agents deploy in seconds via single-line Helm chart installation and automatically discover cluster endpoints.</p>
            <p>Thousands of cloud engineers trust our telemetry substrate to ensure high availability across global deployment footprints.</p>
            <a href="/tiers-and-investment">Explore Plan Investment Details</a></main></body></html>""",
            "https://saas-pricing-conflict.test/tiers-and-investment": """<!DOCTYPE html><html><head><title>Enterprise Tiers and Investment - CloudPro</title>
            <meta name="description" content="Transparent pricing tiers and enterprise capacity quotas for CloudPro Suite.">
            <link rel="canonical" href="https://saas-pricing-conflict.test/tiers-and-investment">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"CloudPro Suite","offers":{"@type":"Offer","price":"149.00","priceCurrency":"USD"}}</script>
            </head><body><header><nav><a href="/">Home</a></nav></header>
            <main><h1>CloudPro Enterprise Investment Plans</h1>
            <p>Select the operational capacity tier tailored to your organizational scale. Every deployment tier provides dedicated tenant data isolation, custom retention schemas, and guaranteed SLA response times.</p>
            <p>All subscription plans include automated security patch management and access to our technical customer success engineering team.</p>
            <p>Organizations benefit from dedicated onboarding engineering, custom metrics retention tiers, and priority incident escalations.</p>
            <p>Annual billing agreements include quarterly operational reviews conducted by senior site reliability engineering architects.</p>
            <p>Subscribers receive dedicated onboarding engineering, custom metrics retention tiers, and priority incident escalations. Tailored infrastructure quotas ensure predictable operating costs as your enterprise deployment scales globally.</p>
            <a href="/">Order Enterprise CloudPro License</a></main></body></html>""",
            "https://saas-pricing-conflict.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://saas-pricing-conflict.test/</loc></url>
                <url><loc>https://saas-pricing-conflict.test/tiers-and-investment</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"ENT-CONFLICT-PRICE-001"},
    },

    # -----------------------------------------------------------------------
    # 20. QUERY-ROUTED SPA BROWSER RECOVERY (Query Routing + Headless Render)
    # Expected: {"CR-RENDER-GAP-001"}
    # Escalation: attempted=1, recovered=1, unusable=0
    # -----------------------------------------------------------------------
    {
        "id": "20_spa_recovery_query_routed_catalog",
        "url": "https://vue-catalog.test/?view=catalog",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://vue-catalog.test/sitemap.xml\n",
        "pages": {
            "https://vue-catalog.test/?view=catalog": """<!DOCTYPE html><html><head><title>Catalog Loading...</title></head>
            <body><div id="app"></div><script>window.__VUE_DATA__={route:"catalog"};</script><script src="/vue.min.js"></script></body></html>""",
            "https://vue-catalog.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://vue-catalog.test/?view=catalog</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "rendered_pages": {
            "https://vue-catalog.test/?view=catalog": """<!DOCTYPE html><html><head><title>VueStore Industrial Hardware Catalog</title>
            <meta name="description" content="Dynamic e-commerce catalog featuring certified industrial IoT sensors and wireless telemetry gateways.">
            <link rel="canonical" href="https://vue-catalog.test/?view=catalog">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Industrial Sensor Node Pro","offers":{"@type":"Offer","price":"299.00","priceCurrency":"USD"}}</script>
            </head><body><div id="app">
                <header><nav><a href="/?view=home">Home</a><a href="/?view=support">Support</a></nav></header>
                <main><h1>Industrial IoT Wireless Sensor Nodes</h1>
                <p>Ultra-low power wireless sensor node designed for harsh industrial manufacturing environments. Real-time vibration monitoring, thermal dissipation telemetry, and acoustic anomaly detection over mesh wireless networks.</p>
                <p>Continuous vibration analysis and acoustic fault detection with onboard machine learning anomaly classification directly at the machine edge. Ruggedized enclosure meets IP67 ingress protection standards.</p>
                <p>Our long-range mesh radio transceivers transmit telemetry data up to two kilometers in dense steel-reinforced concrete industrial environments without repeaters.</p>
                <p>Integrated cryptographic hardware accelerators ensure secure over-the-air firmware updates and tamper-resistant device identity attestation.</p>
                <a href="/?action=purchase">Order Hardware Evaluation Kit</a></main>
            </div></body></html>""",
        },
        "expected_rules": {"CR-RENDER-GAP-001"},
    },

    # -----------------------------------------------------------------------
    # 21. MULTI-HOP REDIRECT CHAIN (Production redirect-following path)
    # Expected: {"CR-REDIRECT-CHAIN-001"}
    # The seed URL returns 301 → hop1 returns 302 → hop2 returns 301 → final 200.
    # The production _safe_fetch_url loop follows Location headers and builds
    # redirect_chain naturally. _check_redirect_chain then fires on len >= 2.
    # -----------------------------------------------------------------------
    {
        "id": "21_multi_hop_redirect_chain",
        "url": "https://legacy-portal.test/",
        "robots": "User-agent: *\nAllow: /\nSitemap: https://legacy-portal.test/sitemap.xml\n",
        "pages": {
            "https://legacy-portal.test/": ("", 301, "text/html", {"Location": "https://legacy-portal.test/v2/"}),
            "https://legacy-portal.test/v2/": ("", 302, "text/html", {"Location": "https://legacy-portal.test/v3/home"}),
            "https://legacy-portal.test/v3/home": ("", 301, "text/html", {"Location": "https://legacy-portal.test/v3/dashboard"}),
            "https://legacy-portal.test/v3/dashboard": """<!DOCTYPE html><html><head><title>Legacy Portal Dashboard</title>
            <meta name="description" content="Centralized operations dashboard for legacy enterprise portal migration.">
            <link rel="canonical" href="https://legacy-portal.test/v3/dashboard">
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"Legacy Portal","url":"https://legacy-portal.test/v3/dashboard"}</script>
            </head><body><header><nav><a href="/v3/about">About</a></nav></header>
            <main><h1>Enterprise Operations Dashboard</h1>
            <p>Consolidated infrastructure monitoring and workload orchestration for hybrid cloud deployments. Real-time telemetry from distributed sensor networks feeds into our anomaly detection engine.</p>
            <p>Migration from legacy portal v1 through v2 is now complete. All operational endpoints have been consolidated under the v3 namespace.</p>
            <a href="/v3/contact">Contact Operations Team</a></main></body></html>""",
            "https://legacy-portal.test/sitemap.xml": ("""<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://legacy-portal.test/v3/dashboard</loc></url>
            </urlset>""", 200, "application/xml"),
        },
        "expected_rules": {"CR-REDIRECT-CHAIN-001"},
    },
]


def run_blind_evaluation():
    results = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_runtime = 0.0
    max_runtime = 0.0
    total_pages_sampled = 0
    total_depth_0 = 0
    total_depth_1 = 0
    total_depth_2 = 0
    subpage_defects_discovered = 0

    total_escalations_attempted = 0
    total_escalations_recovered = 0
    total_escalations_unusable = 0

    for case in EVAL_CASES:
        t0 = time.monotonic()
        mock_open = make_site_mock(case["pages"], default_robots=case.get("robots"))
        rendered_map = case.get("rendered_pages", {})

        def mock_render(url, *args, **kwargs):
            nonlocal total_escalations_attempted, total_escalations_recovered, total_escalations_unusable
            total_escalations_attempted += 1
            if url in rendered_map:
                total_escalations_recovered += 1
                return (rendered_map[url], True, None)
            total_escalations_unusable += 1
            return (None, False, "no_rendered_content")

        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            with patch.object(run_audit, "render_with_browser", side_effect=mock_render):
                report = run_audit.run_pipeline(case["url"], enhanced=True, max_pages=5)

        duration = round(time.monotonic() - t0, 3)
        total_runtime += duration
        max_runtime = max(max_runtime, duration)

        cov = report.get("coverage", {})
        ev_cov = report.get("evidence_coverage", {})
        pages_sampled = cov.get("urls_fetched", 0)
        total_pages_sampled += pages_sampled
        rendered_count = cov.get("urls_rendered", 0) or cov.get("browser_pages", 0)
        fetch_failures = cov.get("urls_failed", 0)
        crawl_completed = cov.get("stop_reason") in ("source_exhaustion", "crawl_complete", "page_budget_exhausted")

        # Track depth distribution
        inspected = ev_cov.get("pages_inspected", []) or cov.get("pages_inspected", [])
        d0 = sum(1 for p in inspected if p.get("depth") == 0)
        d1 = sum(1 for p in inspected if p.get("depth") == 1)
        d2 = sum(1 for p in inspected if p.get("depth", 0) >= 2)
        total_depth_0 += d0
        total_depth_1 += d1
        total_depth_2 += d2

        findings = report.get("findings", [])
        actual_rules = {f.get("rule_id") for f in findings if f.get("rule_id")}

        # Check if defect was discovered from a subpage
        for f in findings:
            src = f.get("source_url") or ""
            if src and src != case["url"]:
                subpage_defects_discovered += 1

        sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in sev_dist:
                sev_dist[sev] += 1

        expected = case["expected_rules"]

        # Strict ground-truth scoring:
        # TP = expected findings that were emitted
        # FN = expected findings that were missed
        # FP = emitted findings that were NOT expected (strictly penalizes unpredicted noise)
        tp_rules = expected & actual_rules
        fn_rules = expected - actual_rules
        fp_rules = actual_rules - expected

        tp = len(tp_rules)
        fn = len(fn_rules)
        fp = len(fp_rules)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        results.append({
            "id": case["id"],
            "runtime_s": duration,
            "pages_sampled": pages_sampled,
            "depth_distribution": {"depth_0": d0, "depth_1": d1, "depth_2": d2},
            "crawl_completed": crawl_completed,
            "rendered_pages": rendered_count,
            "fetch_failures": fetch_failures,
            "finding_count": len(findings),
            "severity_distribution": sev_dist,
            "expected_rules": sorted(list(expected)),
            "actual_rules": sorted(list(actual_rules)),
            "tp_rules": sorted(list(tp_rules)),
            "fp_rules": sorted(list(fp_rules)),
            "fn_rules": sorted(list(fn_rules)),
            "findings_detail": findings,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        })

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    fpr = total_fp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    avg_runtime = total_runtime / len(EVAL_CASES) if EVAL_CASES else 0.0
    avg_pages = total_pages_sampled / len(EVAL_CASES) if EVAL_CASES else 0.0
    render_escalation_rate = total_escalations_attempted / total_pages_sampled if total_pages_sampled > 0 else 0.0

    summary = {
        "cases_evaluated": len(EVAL_CASES),
        "total_runtime_s": round(total_runtime, 3),
        "average_runtime_s": round(avg_runtime, 3),
        "max_runtime_s": round(max_runtime, 3),
        "crawl_performance": {
            "total_pages_sampled": total_pages_sampled,
            "average_pages_sampled": round(avg_pages, 2),
            "depth_0_pages": total_depth_0,
            "depth_1_pages": total_depth_1,
            "depth_2_pages": total_depth_2,
            "subpage_defects_discovered": subpage_defects_discovered,
        },
        "render_performance": {
            "pages_escalated": total_escalations_attempted,
            "pages_recovered": total_escalations_recovered,
            "pages_unusable": total_escalations_unusable,
            "render_escalation_rate": round(render_escalation_rate, 4),
        },
        "accuracy_metrics": {
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
        },
        "case_details": results,
    }
    return summary


def test_blind_evaluation_execution():
    """Pytest execution hook for continuous verification."""
    summary = run_blind_evaluation()
    assert summary["cases_evaluated"] == 21
    assert summary["accuracy_metrics"]["true_positives"] >= 10
    assert summary["accuracy_metrics"]["false_positives"] == 0
    assert summary["accuracy_metrics"]["false_negatives"] == 0
    assert summary["accuracy_metrics"]["recall"] == 1.0
    assert summary["render_performance"]["pages_recovered"] >= 2


if __name__ == "__main__":
    summary = run_blind_evaluation()
    print("=" * 76)
    print("SYNTHETIC/ADVERSARIAL GENERALIZATION BENCHMARK — 21 ARCHETYPES")
    print("Notice: Validates robustness across deliberately varied unseen-like")
    print("        site structures. Does not by itself prove arbitrary real-world performance.")
    print("=" * 76)
    print(f"Cases Evaluated:                 {summary['cases_evaluated']}")
    print(f"Total Evaluation Runtime:        {summary['total_runtime_s']:.3f}s")
    print(f"Average Runtime per Case:        {summary['average_runtime_s']:.3f}s")
    print(f"Max Single-Case Runtime:         {summary['max_runtime_s']:.3f}s")
    print("-" * 76)
    print("1. CRAWL-DISCOVERY PERFORMANCE:")
    cp = summary["crawl_performance"]
    print(f"  Total Pages Sampled:           {cp['total_pages_sampled']}")
    print(f"  Average Pages Sampled / Case:  {cp['average_pages_sampled']}")
    print(f"  Depth 0 (Root) Pages:          {cp['depth_0_pages']}")
    print(f"  Depth 1 Discovered Pages:      {cp['depth_1_pages']}")
    print(f"  Depth 2 Discovered Pages:      {cp['depth_2_pages']}")
    print(f"  Subpage Defects Discovered:    {cp['subpage_defects_discovered']}")
    print("-" * 76)
    print("2. BROWSER-RENDER RECOVERY PERFORMANCE:")
    rp = summary["render_performance"]
    print(f"  Pages Escalated to Browser:    {rp['pages_escalated']}")
    print(f"  Pages Successfully Recovered:  {rp['pages_recovered']}")
    print(f"  Pages Remaining Unusable:      {rp['pages_unusable']}")
    print(f"  Render Escalation Rate:        {rp['render_escalation_rate'] * 100:.1f}%")
    print("-" * 76)
    print("3. STRICT GROUND-TRUTH ACCURACY METRICS:")
    m = summary["accuracy_metrics"]
    print(f"  True Positives (TP):           {m['true_positives']}")
    print(f"  False Positives (FP):          {m['false_positives']}")
    print(f"  False Negatives (FN):          {m['false_negatives']}")
    print(f"  Precision:                     {m['precision'] * 100:.2f}%")
    print(f"  Recall:                        {m['recall'] * 100:.2f}%")
    print(f"  False Positive Rate:           {m['false_positive_rate'] * 100:.2f}%")
    print("=" * 76)
    print("\nPER-CASE BREAKDOWN:")
    for c in summary["case_details"]:
        status = "PASS" if c["fp"] == 0 and c["fn"] == 0 else f"FP={c['fp']} FN={c['fn']}"
        d_info = f"d0={c['depth_distribution']['depth_0']}, d1={c['depth_distribution']['depth_1']}, d2={c['depth_distribution']['depth_2']}"
        print(f"  [{status:<12}] {c['id']:<40} (time: {c['runtime_s']:.3f}s, sampled: {c['pages_sampled']} [{d_info}], findings: {c['finding_count']})")
        if c["fp_rules"]:
            print(f"      FP rules emitted: {c['fp_rules']}")
            for f in c.get("findings_detail", []):
                if f.get("rule_id") in c["fp_rules"]:
                    print(f"        -> {f.get('rule_id')}: {f.get('evidence')}")
        if c["fn_rules"]:
            print(f"      FN rules missed:  {c['fn_rules']}")
    print("=" * 76)
    _metrics = summary["accuracy_metrics"]
    if (_metrics["false_positives"] != 0
            or _metrics["false_negatives"] != 0
            or _metrics["recall"] != 1.0):
        raise SystemExit(1)
