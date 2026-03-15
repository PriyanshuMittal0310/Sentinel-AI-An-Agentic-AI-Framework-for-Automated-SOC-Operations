"""
MITRE ATT&CK Lookup Tool — SENTINEL-AI Triage Tool

Provides fast, offline lookup of MITRE ATT&CK technique details from
the locally cached STIX 2.1 bundle (knowledge_base/mitre_attack_cache.json).

Used by the Triage Agent's ReAct loop to enrich determistic classification
results with authoritative technique descriptions, detection guidance, and
related subtechnique information.
"""

import json
import logging
import re
from pathlib import Path
from functools import lru_cache
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Default path — resolved relative to the project root
_DEFAULT_CACHE_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "mitre_attack_cache.json"


# ---------------------------------------------------------------------------
# Cache loader
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_techniques(cache_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Load the MITRE ATT&CK STIX bundle and index attack-pattern objects
    by their external technique ID (e.g. 'T1046', 'T1499.002').

    Returns a dict: technique_id → technique_dict
    """
    path = Path(cache_path)
    if not path.exists():
        logger.warning("MITRE cache not found at %s — using empty index", cache_path)
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as exc:
        logger.error("Failed to load MITRE cache: %s", exc)
        return {}

    index: Dict[str, Dict[str, Any]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # Pull the MITRE external reference (first entry with source_name == 'mitre-attack')
        ext_refs = obj.get("external_references", [])
        technique_id = None
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "").strip()
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # Extract kill-chain tactic names
        tactics: List[str] = [
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        index[technique_id] = {
            "technique_id": technique_id,
            "name": obj.get("name", "Unknown"),
            "description": obj.get("description", "")[:500],   # truncate to keep context small
            "tactics": tactics,
            "url": url,
            "is_subtechnique": "." in technique_id,
        }

    logger.info("MITRE lookup index built with %d techniques", len(index))
    return index


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class MitreLookup:
    """Offline MITRE ATT&CK technique lookup backed by local STIX cache."""

    def __init__(self, cache_path: Optional[str] = None) -> None:
        self._cache_path = cache_path or str(_DEFAULT_CACHE_PATH)
        self._index = _load_techniques(self._cache_path)

    # ── Lookup by ID ──────────────────────────────────────────────────────

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Return full technique record for *technique_id* (e.g. 'T1046').
        Returns None if not found.
        """
        return self._index.get(technique_id.strip())

    def get_tactics(self, technique_id: str) -> List[str]:
        """Return the list of tactic names for a technique, or empty list."""
        t = self.get_technique(technique_id)
        return t.get("tactics", []) if t else []

    def get_name(self, technique_id: str) -> str:
        """Return the technique name, or 'Unknown' if not in cache."""
        t = self.get_technique(technique_id)
        return t.get("name", "Unknown") if t else "Unknown"

    def get_description(self, technique_id: str) -> str:
        """Return the (truncated) technique description, or empty string."""
        t = self.get_technique(technique_id)
        return t.get("description", "") if t else ""

    # ── Fuzzy / tactic-based search ──────────────────────────────────────

    def search_by_tactic(self, tactic_name: str, max_results: int = 5) -> List[Dict[str, Any]]:
        """
        Return up to *max_results* techniques that belong to *tactic_name*.
        Matching is case-insensitive.
        """
        normalised = tactic_name.lower().replace("-", " ").replace("_", " ")
        results: List[Dict[str, Any]] = []

        for technique in self._index.values():
            tactics_lower = [t.lower() for t in technique.get("tactics", [])]
            if any(normalised in t for t in tactics_lower):
                results.append(technique)
                if len(results) >= max_results:
                    break

        return results

    def search_by_name(self, keyword: str, max_results: int = 5) -> List[Dict[str, Any]]:
        """Return techniques whose name contains *keyword* (case-insensitive)."""
        kw = keyword.lower()
        results: List[Dict[str, Any]] = []
        for technique in self._index.values():
            if kw in technique.get("name", "").lower():
                results.append(technique)
                if len(results) >= max_results:
                    break
        return results

    # ── Triage helper ────────────────────────────────────────────────────

    def enrich_triage_result(self, technique_id: str, tactic: str) -> str:
        """
        Return a concise one-line enrichment string for use in the Triage Agent
        ReAct reasoning prompt.
        """
        t = self.get_technique(technique_id)
        if t:
            tactic_str = ", ".join(t.get("tactics", [tactic])) or tactic
            return (
                f"MITRE {technique_id} — '{t['name']}' "
                f"[tactic: {tactic_str}]: "
                f"{t['description'][:200]}..."
            )

        # Technique not in cache — fall back to tactic-based search
        alternates = self.search_by_tactic(tactic, max_results=1)
        if alternates:
            alt = alternates[0]
            return (
                f"Technique {technique_id} not cached. "
                f"Related: {alt['technique_id']} '{alt['name']}' "
                f"(tactic: {tactic})."
            )
        return f"No MITRE enrichment available for {technique_id} / {tactic}."

    @property
    def technique_count(self) -> int:
        """Number of techniques currently indexed."""
        return len(self._index)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_lookup: Optional[MitreLookup] = None


def get_lookup() -> MitreLookup:
    global _lookup
    if _lookup is None:
        _lookup = MitreLookup()
    return _lookup


def mitre_enrich(technique_id: str, tactic: str = "Unknown") -> str:
    """
    Convenience function: return a one-line MITRE enrichment string.
    Used by TriageAgent's ReAct loop.
    """
    return get_lookup().enrich_triage_result(technique_id, tactic)
