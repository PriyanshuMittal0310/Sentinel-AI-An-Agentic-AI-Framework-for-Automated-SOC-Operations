"""
Context Agent — SENTINEL-AI MITRE ATT&CK Knowledge Enrichment (Phase 2)

Builds retrieval query from triage output and fetches top relevant MITRE techniques
from ChromaDB using semantic similarity.
"""

import logging
from typing import Dict, Any, List

try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

logger = logging.getLogger(__name__)


class ContextAgent:
    """Phase 2 context retrieval agent backed by ChromaDB."""

    def __init__(self, chroma_path: str = "./knowledge_base/chroma_store", collection_name: str = "mitre_attack"):
        self.chroma_path = chroma_path
        self.collection_name = collection_name
        self.client = None
        self.collection = None

        if CHROMADB_AVAILABLE:
            self._initialize_chromadb()

    def _initialize_chromadb(self) -> None:
        try:
            self.client = chromadb.PersistentClient(
                path=self.chroma_path,
                settings=Settings(anonymized_telemetry=False),
            )
            self.collection = self.client.get_collection(name=self.collection_name)
            logger.info("ContextAgent connected to collection '%s' (%s docs)", self.collection_name, self.collection.count())
        except Exception as exc:
            logger.warning("ContextAgent fallback mode: %s", exc)
            self.collection = None

    def build_query(self, triage_result: Dict[str, Any]) -> str:
        parts: List[str] = []

        sev = str(triage_result.get("severity", "")).strip()
        tactic = str(triage_result.get("mitre_tactic", "")).strip()
        technique = str(triage_result.get("mitre_technique", "")).strip()
        event_type = str(triage_result.get("event_type", "")).strip()
        rationale = str(triage_result.get("triage_rationale", "")).strip()
        payload = str(triage_result.get("raw_payload", "")).strip()

        if event_type:
            parts.append(f"attack type {event_type}")
        if sev:
            parts.append(f"severity {sev}")
        if tactic and tactic != "Unknown":
            parts.append(f"mitre tactic {tactic}")
        if technique and technique != "T0000":
            parts.append(f"mitre technique {technique}")
        if rationale:
            parts.append(rationale[:180])
        if payload:
            parts.append(payload[:180])

        query = " | ".join(parts) if parts else "network intrusion technique"
        return query

    def _score_result(self, distance: float) -> float:
        # Chroma distance is lower-is-better; convert to bounded similarity-ish score.
        score = 1.0 / (1.0 + max(distance, 0.0))
        return round(score, 4)

    def retrieve_techniques(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        if not self.collection:
            return self._get_mock_techniques()

        try:
            results = self.collection.query(query_texts=[query], n_results=n_results)
            techniques: List[Dict[str, Any]] = []

            ids = results.get("ids", [[]])[0]
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0] if results.get("distances") else [0.5] * len(ids)

            for idx in range(len(ids)):
                meta = metas[idx] if idx < len(metas) else {}
                dist = dists[idx] if idx < len(dists) else 0.5
                doc = docs[idx] if idx < len(docs) else ""

                techniques.append(
                    {
                        "technique_id": meta.get("technique_id", "T0000"),
                        "name": meta.get("name", "Unknown"),
                        "tactics": meta.get("tactics", "Unknown"),
                        "platforms": meta.get("platforms", "Unknown"),
                        "document": doc,
                        "distance": dist,
                        "relevance_score": self._score_result(dist),
                    }
                )

            techniques.sort(key=lambda x: x["relevance_score"], reverse=True)
            return techniques
        except Exception as exc:
            logger.error("ContextAgent retrieval failed: %s", exc)
            return self._get_mock_techniques()

    def _get_mock_techniques(self) -> List[Dict[str, Any]]:
        return [
            {
                "technique_id": "T1046",
                "name": "Network Service Scanning",
                "tactics": "Discovery",
                "platforms": "Windows, Linux, macOS",
                "document": "Fallback context: reconnaissance over open services.",
                "distance": 0.5,
                "relevance_score": 0.6667,
            },
            {
                "technique_id": "T1499.002",
                "name": "Network Denial of Service",
                "tactics": "Impact",
                "platforms": "Network Devices, Linux, Windows",
                "document": "Fallback context: service disruption attack pattern.",
                "distance": 0.6,
                "relevance_score": 0.625,
            },
        ]

    def enrich_alert(self, alert_data: Dict[str, Any], triage_result: Dict[str, Any]) -> Dict[str, Any]:
        merged = {**alert_data, **triage_result}
        query = self.build_query(merged)
        techniques = self.retrieve_techniques(query, n_results=3)

        return {
            "context_query": query,
            "retrieved_techniques": techniques,
            "context_metadata": {
                "source": "chromadb" if self.collection else "fallback",
                "n_retrieved": len(techniques),
                "collection": self.collection_name,
            },
        }
