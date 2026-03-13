"""
Context Agent — SENTINEL-AI MITRE ATT&CK Knowledge Enrichment

Converts triage results into ChromaDB query and retrieves top-3 relevant 
MITRE ATT&CK techniques using semantic similarity search.

Output: Enriched context with technique descriptions, detection guidance,
and recommended mitigations.

Week 1: Scaffold with ChromaDB integration
Week 2: Full semantic search with nomic-embed-text embeddings
"""

import logging
from typing import Dict, Any, List, Optional
import os

# ChromaDB imports
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logging.warning("ChromaDB not available - Context Agent will use mock data")

# Set up logging
logger = logging.getLogger(__name__)


class ContextAgent:
    """
    Context Agent that retrieves MITRE ATT&CK techniques from ChromaDB.
    
    Uses semantic similarity search to find techniques relevant to 
    the triage agent's classification output.
    
    Week 1: ChromaDB integration initialized
    Week 2: Full semantic search implementation
    """
    
    def __init__(self, chroma_path: str = "./knowledge_base/chroma_store", 
                 collection_name: str = "mitre_attack"):
        """
        Initialize the Context Agent.
        
        Args:
            chroma_path: Path to ChromaDB persistent storage
            collection_name: Name of ChromaDB collection with MITRE data
        """
        self.chroma_path = chroma_path
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        
        if CHROMADB_AVAILABLE:
            self._initialize_chromadb()

    def _initialize_chromadb(self) -> None:
        """Initialize ChromaDB client and collection."""
        try:
            self.client = chromadb.PersistentClient(
                path=self.chroma_path,
                settings=Settings(anonymized_telemetry=False)
            )
            
            self.collection = self.client.get_collection(name=self.collection_name)
            count = self.collection.count()
            logger.info(f"✅ Context Agent connected to ChromaDB ({count} techniques available)")
            
        except Exception as e:
            logger.warning(f"⚠️  ChromaDB connection failed: {e}. Will use mock data.")
            self.collection = None

    def build_query(self, triage_result: Dict[str, Any]) -> str:
        """
        Convert triage result into an effective ChromaDB search query.
        
        Args:
            triage_result: Output from Triage Agent
            
        Returns:
            Query string for semantic search
        """
        mitre_tactic = triage_result.get('mitre_tactic', '')
        mitre_technique = triage_result.get('mitre_technique', '')
        event_type = triage_result.get('event_type', '')
        triage_rationale = triage_result.get('triage_rationale', '')
        
        # Build query combining multiple fields for better semantic matching
        query_parts = []
        
        if mitre_tactic and mitre_tactic != 'Unknown':
            query_parts.append(f"MITRE tactic: {mitre_tactic}")
        
        if mitre_technique and mitre_technique != 'T0000':
            query_parts.append(f"technique ID: {mitre_technique}")
        
        if event_type and event_type != 'Unknown':
            query_parts.append(f"attack type: {event_type}")
        
        if triage_rationale:
            query_parts.append(triage_rationale[:100])  # First 100 chars
        
        query = " ".join(query_parts) if query_parts else "network attack technique"
        
        logger.info(f"Built ChromaDB query: '{query[:80]}...' ")
        return query

    def retrieve_techniques(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieve relevant MITRE techniques from ChromaDB.
        
        Args:
            query: Search query string
            n_results: Number of top results to retrieve
            
        Returns:
            List of relevant technique dictionaries
        """
        if not self.collection:
            logger.warning("ChromaDB collection unavailable - returning mock data")
            return self._get_mock_techniques()
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            techniques = []
            for i in range(len(results['ids'][0])):
                technique = {
                    'technique_id': results['metadatas'][0][i].get('technique_id', 'Unknown'),
                    'name': results['metadatas'][0][i].get('name', 'Unknown'),
                    'tactics': results['metadatas'][0][i].get('tactics', 'Unknown'),
                    'platforms': results['metadatas'][0][i].get('platforms', 'Unknown'),
                    'document': results['documents'][0][i],
                    'relevance_score': 1.0 - (results['distances'][0][i] if 'distances' in results else 0.5)
                }
                techniques.append(technique)
            
            logger.info(f"✅ Retrieved {len(techniques)} techniques from ChromaDB")
            return techniques
            
        except Exception as e:
            logger.error(f"ChromaDB retrieval error: {e}")
            return self._get_mock_techniques()

    def _get_mock_techniques(self) -> List[Dict[str, Any]]:
        """Return mock techniques when ChromaDB is unavailable."""
        return [
            {
                "technique_id": "T1046",
                "name": "Network Service Scanning",
                "tactics": "Discovery",
                "platforms": "Windows, Linux, macOS",
                "document": "Mock: Network reconnaissance technique",
                "relevance_score": 0.5
            }
        ]

    def enrich_alert(self, alert_data: Dict[str, Any], triage_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main method: Enrich an alert with MITRE ATT&CK context.
        
        Args:
            alert_data: Original alert data
            triage_result: Output from Triage Agent
            
        Returns:
            Context enrichment results
        """
        # Build search query
        combined_data = {**alert_data, **triage_result}
        query = self.build_query(combined_data)
        
        # Retrieve relevant techniques
        techniques = self.retrieve_techniques(query, n_results=3)
        
        return {
            "context_query": query,
            "retrieved_techniques": techniques,
            "context_metadata": {
                "source": "chromadb",
                "n_retrieved": len(techniques),
                "collection": self.collection_name
            }
        }