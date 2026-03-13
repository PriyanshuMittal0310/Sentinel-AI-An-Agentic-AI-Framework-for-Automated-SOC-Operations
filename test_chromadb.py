"""
Test script to verify ChromaDB setup and MITRE ATT&CK corpus loading.
This implements the Week 1 Checkpoint: verify ChromaDB returns results for a test query.
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Set up environment
from dotenv import load_dotenv
load_dotenv()

from knowledge_base.corpus_loader import CorpusLoader
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_chromadb_setup():
    """Test ChromaDB setup and MITRE ATT&CK corpus loading."""
    
    print("🔍 SENTINEL-AI Week 1 Checkpoint Test")
    print("="*50)
    
    try:
        # Initialize corpus loader
        chroma_path = os.getenv('CHROMADB_PATH', './knowledge_base/chroma_store')
        collection_name = os.getenv('CHROMADB_COLLECTION_NAME', 'mitre_attack')
        
        print(f"📂 ChromaDB Path: {chroma_path}")
        print(f"📊 Collection Name: {collection_name}")
        
        loader = CorpusLoader(chroma_path, collection_name)
        
        # Run corpus loading pipeline
        print("\n📥 Loading MITRE ATT&CK corpus...")
        success = loader.run(force_refresh=False)
        
        if not success:
            print("❌ Corpus loading failed!")
            return False
        
        print("✅ Corpus loading successful!")
        
        # Get collection statistics
        print("\n📊 Collection Statistics:")
        stats = loader.get_collection_stats()
        for key, value in stats.items():
            print(f"  • {key}: {value}")
        
        # Test queries - Week 1 checkpoint requirement
        print("\n🔍 Testing Retrieval (Week 1 Checkpoint):")
        test_queries = [
            "network scanning reconnaissance discovery",
            "brute force credential access password",
            "SQL injection web application exploit", 
            "denial of service network attack",
            "lateral movement remote access"
        ]
        
        all_tests_passed = True
        
        for i, query in enumerate(test_queries, 1):
            print(f"\n  Test {i}: '{query}'")
            results = loader.test_retrieval(query, n_results=2)
            
            if results:
                print(f"    ✅ Retrieved {len(results)} results")
                print(f"    🎯 Top match: {results[0]['metadata']['name']}")
                print(f"       Technique ID: {results[0]['metadata']['technique_id']}")
                print(f"       Tactics: {results[0]['metadata']['tactics']}")
            else:
                print(f"    ❌ No results returned")
                all_tests_passed = False
        
        # Week 1 Checkpoint Summary
        print("\n" + "="*50)
        print("📋 WEEK 1 CHECKPOINT SUMMARY")
        print("="*50)
        
        if all_tests_passed and stats.get('total_techniques', 0) > 0:
            print("✅ CHECKPOINT PASSED!")
            print("✅ ChromaDB initialized successfully")
            print("✅ MITRE ATT&CK data loaded")
            print("✅ Retrieval queries working")
            print(f"✅ {stats.get('total_techniques', 0)} techniques available")
        else:
            print("❌ CHECKPOINT FAILED!")
            if stats.get('total_techniques', 0) == 0:
                print("❌ No techniques loaded in ChromaDB")
            if not all_tests_passed:
                print("❌ Some retrieval tests failed")
        
        return all_tests_passed and stats.get('total_techniques', 0) > 0
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run the test."""
    success = test_chromadb_setup()
    
    if success:
        print("\n🎉 Week 1 Task 6 completed successfully!")
        print("   Ready to proceed with LangGraph StateGraph skeleton.")
    else:
        print("\n💥 Week 1 Task 6 failed. Please check the logs and fix issues.")
    
    return success


if __name__ == "__main__":
    main()