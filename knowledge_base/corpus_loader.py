"""
MITRE ATT&CK Corpus Loader for SENTINEL-AI

Downloads and processes MITRE ATT&CK framework data into ChromaDB vector store
for semantic retrieval by the Context Agent.
"""

import json
import logging
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
import chromadb
from chromadb.config import Settings
import chromadb.errors
import hashlib
import time
from datetime import datetime
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorpusLoader:
    """Loads MITRE ATT&CK data into ChromaDB vector database."""
    
    def __init__(self, chroma_path: str, collection_name: str = "mitre_attack"):
        """
        Initialize the corpus loader.
        
        Args:
            chroma_path: Path to ChromaDB persistent storage
            collection_name: Name of ChromaDB collection to create/use
        """
        self.chroma_path = Path(chroma_path)
        self.collection_name = collection_name
        self.chroma_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.chroma_path),
            settings=Settings(anonymized_telemetry=False)
        )
        
        # MITRE ATT&CK data source
        self.mitre_stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.local_cache_file = self.chroma_path.parent / "mitre_attack_cache.json"
        
        # Initialize collection
        self.collection = None
        self._initialize_collection()

    def _initialize_collection(self):
        """Initialize or get existing ChromaDB collection."""
        try:
            # Try to get existing collection
            self.collection = self.client.get_collection(name=self.collection_name)
            logger.info(f"Using existing collection: {self.collection_name}")
        except (ValueError, chromadb.errors.NotFoundError):
            # Create new collection with embedding function
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "MITRE ATT&CK Enterprise Matrix techniques and tactics"}
            )
            logger.info(f"Created new collection: {self.collection_name}")

    def download_mitre_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Download MITRE ATT&CK STIX data from GitHub.
        
        Args:
            force_refresh: Force download even if cache exists
            
        Returns:
            Dictionary containing STIX data
        """
        # Check if cached version exists and is recent (< 7 days)
        if (not force_refresh and 
            self.local_cache_file.exists() and 
            (time.time() - self.local_cache_file.stat().st_mtime) < 7 * 24 * 3600):
            
            logger.info("Using cached MITRE ATT&CK data")
            with open(self.local_cache_file, 'r') as f:
                return json.load(f)
        
        # Download fresh data
        logger.info("Downloading MITRE ATT&CK data from GitHub...")
        
        try:
            response = requests.get(self.mitre_stix_url, timeout=30)
            response.raise_for_status()
            
            stix_data = response.json()
            
            # Cache the data
            with open(self.local_cache_file, 'w') as f:
                json.dump(stix_data, f, indent=2)
            
            logger.info(f"Downloaded MITRE ATT&CK data ({len(stix_data.get('objects', []))} objects)")
            return stix_data
            
        except Exception as e:
            logger.error(f"Failed to download MITRE data: {e}")
            
            # Fall back to cached version if available
            if self.local_cache_file.exists():
                logger.info("Falling back to cached data")
                with open(self.local_cache_file, 'r') as f:
                    return json.load(f)
            else:
                # Create synthetic MITRE data for demonstration
                return self._create_synthetic_mitre_data()

    def _create_synthetic_mitre_data(self) -> Dict[str, Any]:
        """Create synthetic MITRE ATT&CK data for demonstration purposes."""
        logger.info("Creating synthetic MITRE ATT&CK data for demonstration")
        
        synthetic_techniques = [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--T1046",
                "name": "Network Service Scanning",
                "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
                "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                "x_mitre_tactics": ["Discovery"],
                "x_mitre_technique_id": "T1046",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]
            },
            {
                "type": "attack-pattern", 
                "id": "attack-pattern--T1499.002",
                "name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.",
                "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                "x_mitre_tactics": ["Impact"],
                "x_mitre_technique_id": "T1499.002",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--T1110.001", 
                "name": "Password Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                "x_mitre_tactics": ["Credential Access"],
                "x_mitre_technique_id": "T1110.001",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--T1190",
                "name": "Exploit Public-Facing Application", 
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                "x_mitre_tactics": ["Initial Access"],
                "x_mitre_technique_id": "T1190",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                "x_mitre_tactics": ["Execution"],
                "x_mitre_technique_id": "T1059",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
            }
        ]
        
        return {"objects": synthetic_techniques}

    def extract_techniques(self, stix_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attack patterns (techniques) from STIX data."""
        techniques = []
        
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Extract key information
                technique = {
                    "id": obj.get("id", ""),
                    "technique_id": obj.get("external_references", [{}])[0].get("external_id", "T0000"),
                    "name": obj.get("name", "Unknown Technique"),
                    "description": obj.get("description", "No description available"),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [phase.get("phase_name", "").replace("-", " ").title()
                                for phase in obj.get("kill_chain_phases", [])
                                if phase.get("kill_chain_name") == "mitre-attack"],
                    "detection": obj.get("x_mitre_detection", "No detection guidance available"),
                    "mitigation": obj.get("x_mitre_mitigation", "No mitigation guidance available"),
                    "kill_chain_phases": [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]
                }
                
                # Clean up fields
                technique["technique_id"] = technique["technique_id"] if technique["technique_id"].startswith("T") else "T0000"
                technique["description"] = self._clean_text(technique["description"])
                
                techniques.append(technique)
        
        logger.info(f"Extracted {len(techniques)} techniques from STIX data")
        return techniques

    def _clean_text(self, text: str) -> str:
        """Clean and normalize text for better embedding."""
        if not text:
            return ""
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove STIX references like (Citation: ...)
        text = re.sub(r'\(Citation:[^)]+\)', '', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()

    def create_embeddings_content(self, technique: Dict[str, Any]) -> str:
        """Create text content for embedding generation."""
        # Combine multiple fields for rich semantic content
        content_parts = [
            f"Technique: {technique['name']}",
            f"ID: {technique['technique_id']}",
            f"Description: {technique['description']}",
            f"Tactics: {', '.join(technique['tactics'])}",
            f"Platforms: {', '.join(technique['platforms'])}"
        ]
        
        if technique.get('detection'):
            content_parts.append(f"Detection: {technique['detection']}")
        
        return " | ".join(content_parts)

    def populate_chromadb(self, techniques: List[Dict[str, Any]]) -> int:
        """
        Populate ChromaDB with MITRE techniques.
        
        Args:
            techniques: List of technique dictionaries
            
        Returns:
            Number of techniques added to ChromaDB
        """
        logger.info("Populating ChromaDB with MITRE ATT&CK techniques...")
        
        # Check if collection already has data
        existing_count = self.collection.count()
        if existing_count > 0:
            logger.info(f"Collection already contains {existing_count} items")
            logger.info("Skipping population - using existing data")
            return existing_count
        
        # Prepare data for ChromaDB
        documents = []
        metadatas = []
        ids = []
        
        for technique in techniques:
            # Create embedding content
            doc_content = self.create_embeddings_content(technique)
            documents.append(doc_content)
            
            # Create metadata (everything except the content)
            metadata = {
                "technique_id": technique["technique_id"],
                "name": technique["name"],
                "tactics": ", ".join(technique["tactics"]),
                "platforms": ", ".join(technique["platforms"]),
                "kill_chain_phases": ", ".join(technique["kill_chain_phases"])
            }
            metadatas.append(metadata)
            
            # Create unique ID
            technique_hash = hashlib.md5(technique["technique_id"].encode()).hexdigest()[:8]
            ids.append(f"mitre_{technique['technique_id']}_{technique_hash}")
        
        # Add to ChromaDB in batches
        batch_size = 100
        total_added = 0
        
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i+batch_size]
            batch_metas = metadatas[i:i+batch_size]
            batch_ids = ids[i:i+batch_size]
            
            try:
                self.collection.add(
                    documents=batch_docs,
                    metadatas=batch_metas,
                    ids=batch_ids
                )
                total_added += len(batch_docs)
                logger.info(f"Added batch {i//batch_size + 1}: {total_added}/{len(documents)} techniques")
                
            except Exception as e:
                logger.error(f"Error adding batch {i//batch_size + 1}: {e}")
                continue
        
        logger.info(f"Successfully populated ChromaDB with {total_added} techniques")
        return total_added

    def test_retrieval(self, query: str = "network scanning reconnaissance", n_results: int = 3) -> List[Dict]:
        """
        Test ChromaDB retrieval functionality.
        
        Args:
            query: Test query string
            n_results: Number of results to retrieve
            
        Returns:
            List of retrieved results
        """
        logger.info(f"Testing retrieval with query: '{query}'")
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            # Format results for display
            formatted_results = []
            for i in range(len(results['ids'][0])):
                result = {
                    'id': results['ids'][0][i],
                    'distance': results['distances'][0][i] if 'distances' in results else None,
                    'metadata': results['metadatas'][0][i],
                    'document': results['documents'][0][i][:200] + "..." if len(results['documents'][0][i]) > 200 else results['documents'][0][i]
                }
                formatted_results.append(result)
            
            logger.info(f"Retrieved {len(formatted_results)} results")
            
            # Log top result for verification
            if formatted_results:
                top_result = formatted_results[0]
                logger.info(f"Top result: {top_result['metadata']['name']} ({top_result['metadata']['technique_id']})")
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error during retrieval test: {e}")
            return []

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the ChromaDB collection."""
        try:
            count = self.collection.count()
            
            # Get a sample of techniques to analyze
            sample_results = self.collection.query(
                query_texts=["attack technique"],
                n_results=min(10, count)
            )
            
            # Count tactics distribution
            tactics_count = {}
            if sample_results['metadatas']:
                for metadata in sample_results['metadatas'][0]:
                    tactics = metadata.get('tactics', '').split(', ')
                    for tactic in tactics:
                        if tactic.strip():
                            tactics_count[tactic.strip()] = tactics_count.get(tactic.strip(), 0) + 1
            
            return {
                'total_techniques': count,
                'collection_name': self.collection_name,
                'sample_tactics': dict(list(tactics_count.items())[:5]),  # Top 5 tactics
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {'error': str(e)}

    def run(self, force_refresh: bool = False) -> bool:
        """
        Run the complete corpus loading pipeline.
        
        Args:
            force_refresh: Force refresh of MITRE data
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Starting MITRE ATT&CK corpus loading pipeline")
        
        try:
            # Download MITRE data
            stix_data = self.download_mitre_data(force_refresh)
            
            # Extract techniques
            techniques = self.extract_techniques(stix_data)
            
            if not techniques:
                logger.error("No techniques extracted from MITRE data")
                return False
            
            # Populate ChromaDB
            added_count = self.populate_chromadb(techniques)
            
            if added_count == 0:
                logger.warning("No techniques were added to ChromaDB")
                return False
            
            # Test retrieval
            test_results = self.test_retrieval()
            
            if not test_results:
                logger.error("Retrieval test failed")
                return False
            
            # Generate stats
            stats = self.get_collection_stats()
            logger.info(f"Corpus loading completed successfully. Stats: {stats}")
            
            return True
            
        except Exception as e:
            logger.error(f"Corpus loading pipeline failed: {e}")
            return False


# Test function for standalone execution
def main():
    """Test function to run the corpus loader."""
    import os
    from dotenv import load_dotenv
    
    # Load environment variables
    load_dotenv()
    
    # Default configuration
    chroma_path = os.getenv('CHROMADB_PATH', './knowledge_base/chroma_store')
    collection_name = os.getenv('CHROMADB_COLLECTION_NAME', 'mitre_attack')
    
    # Run corpus loader
    loader = CorpusLoader(chroma_path, collection_name)
    success = loader.run(force_refresh=False)
    
    if success:
        print("✅ MITRE ATT&CK corpus loading completed successfully!")
        
        # Display stats
        stats = loader.get_collection_stats()
        print(f"\nCollection Stats:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Test retrieval with different queries
        test_queries = [
            "network scanning reconnaissance",
            "brute force password attack",
            "SQL injection web application",
            "denial of service attack"
        ]
        
        print("\nTesting retrieval with sample queries:")
        for query in test_queries:
            results = loader.test_retrieval(query, n_results=2)
            if results:
                print(f"\nQuery: '{query}'")
                print(f"  Top result: {results[0]['metadata']['name']} ({results[0]['metadata']['technique_id']})")
    else:
        print("❌ MITRE ATT&CK corpus loading failed!")


if __name__ == "__main__":
    main()