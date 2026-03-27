# config.py
# ─────────────────────────────────────────────────────────────
# ÚNICA FUENTE DE VERDAD — ajusta solo este archivo
# ─────────────────────────────────────────────────────────────
from pathlib import Path

# ── Raíz del proyecto ──────────────────────────────────────
BASE_DIR = Path(r"C:\Users\albae\Documents\Doctorado DCyE\5to semestre\RAG NORMATIVO\RAG_CWE_CVE")

# ── Datos crudos (READ-ONLY, nunca se modifican) ───────────
DATA_CRUDE_DIR = BASE_DIR / "DATA CRUDE"

# Subcarpetas por fuente (deben coincidir con lo que tienes en disco)
SOURCE_DIRS = {
    "nvd":   DATA_CRUDE_DIR / "National Vulnerability Database",
    "cwe":   DATA_CRUDE_DIR / "cwe",
    "owasp": DATA_CRUDE_DIR / "OWASP",
    "capec": DATA_CRUDE_DIR / "CAPEC",
}

# ── Salidas del pipeline (se crean automáticamente) ────────
OUTPUT_DIR       = BASE_DIR / "pipeline_output"
CURATED_CHUNKS   = OUTPUT_DIR / "curated_chunks.jsonl"
CURATION_REPORT  = OUTPUT_DIR / "curation_report.json"
CHROMA_DIR       = OUTPUT_DIR / "chroma_db"
BM25_PATH        = OUTPUT_DIR / "bm25_index.pkl"
CWE_ENRICHED     = OUTPUT_DIR / "cwe_enriched.json"

# ── Modelo de embeddings ───────────────────────────────────
# e5-base-v2: mejor balance calidad/velocidad para texto técnico
# Alternativa ligera  : "all-MiniLM-L6-v2"
# Alternativa potente : "BAAI/bge-large-en-v1.5"
EMBEDDING_MODEL = "intfloat/e5-base-v2"

# Batch size para GPU — ajusta según tu VRAM
#   4 GB  → 64
#   8 GB  → 128
#   16 GB → 256
EMBEDDING_BATCH_SIZE = 128

# ── Parámetros de curación ─────────────────────────────────
MIN_DESC_LEN = 30          # mínimo de chars para una descripción válida
CHROMA_COLLECTION = "nvd_vulnerabilities"

# ── Mapeo CWE-ID → tipo de vulnerabilidad ─────────────────
# Usado por el retriever condicionado (Capa 2)
CWE_TO_VULN_TYPE: dict[str, str] = {
    # Injection
    "CWE-89":  "injection", "CWE-77":  "injection", "CWE-78":  "injection",
    "CWE-94":  "injection", "CWE-917": "injection", "CWE-74":  "injection",
    "CWE-1236":"injection",
    # XSS
    "CWE-79":  "xss", "CWE-80": "xss", "CWE-87": "xss", "CWE-116": "xss",
    # Memory corruption
    "CWE-119": "memory_corruption", "CWE-120": "memory_corruption",
    "CWE-121": "memory_corruption", "CWE-122": "memory_corruption",
    "CWE-125": "memory_corruption", "CWE-787": "memory_corruption",
    "CWE-415": "memory_corruption", "CWE-416": "memory_corruption",
    "CWE-476": "memory_corruption", "CWE-190": "memory_corruption",
    "CWE-191": "memory_corruption",
    # Path traversal
    "CWE-22":  "path_traversal", "CWE-23": "path_traversal",
    "CWE-35":  "path_traversal", "CWE-36": "path_traversal",
    # Access control / Auth
    "CWE-862": "access_control", "CWE-863": "access_control",
    "CWE-284": "access_control", "CWE-285": "access_control",
    "CWE-306": "access_control", "CWE-287": "access_control",
    "CWE-269": "access_control", "CWE-732": "access_control",
    # Info disclosure
    "CWE-200": "info_disclosure", "CWE-201": "info_disclosure",
    "CWE-203": "info_disclosure", "CWE-209": "info_disclosure",
    "CWE-312": "info_disclosure", "CWE-313": "info_disclosure",
    # CSRF
    "CWE-352": "csrf",
    # SSRF
    "CWE-918": "ssrf",
    # Deserialización
    "CWE-502": "deserialization",
    # Race condition
    "CWE-362": "race_condition", "CWE-367": "race_condition",
    # Crypto
    "CWE-327": "crypto", "CWE-326": "crypto",
    "CWE-330": "crypto", "CWE-338": "crypto", "CWE-295": "crypto",
    # DoS
    "CWE-400": "dos", "CWE-770": "dos",
    "CWE-674": "dos",  "CWE-835": "dos",
    # XXE
    "CWE-611": "xxe",
    # Open redirect
    "CWE-601": "open_redirect",
    # File upload
    "CWE-434": "file_upload",
}

# CWEs sin información semántica útil (se filtran)
NOINFO_CWES = {"NVD-CWE-noinfo", "NVD-CWE-Other"}

# ── Configuración del retriever por tipo de tarea ──────────
# Cada modo define: top-k, pesos dense/sparse, filtros opcionales
# Esto es lo que Proto-MAML condiciona en la Capa 2
TASK_RETRIEVER_CONFIG = {
    "detect": {
        "top_k":         5,
        "dense_weight":  0.6,
        "sparse_weight": 0.4,   # más peso léxico para IDs exactos
        "description":   "Detectar tipo de vulnerabilidad en código/descripción",
    },
    "explain": {
        "top_k":         8,
        "dense_weight":  0.8,
        "sparse_weight": 0.2,   # más peso semántico para explicaciones ricas
        "description":   "Explicar una vulnerabilidad con contexto normativo",
    },
    "classify": {
        "top_k":         3,
        "dense_weight":  0.7,
        "sparse_weight": 0.3,
        "rerank":        True,  # reranking adicional para precisión CVSS
        "description":   "Clasificar severidad CVSS de una vulnerabilidad",
    },
}
