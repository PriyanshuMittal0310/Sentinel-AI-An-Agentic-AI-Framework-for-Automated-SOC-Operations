# Changelog 📝

All notable changes to the SENTINEL-AI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] 🚧

### Week 4 Planned
- Streamlit dashboard with live monitoring
- Formal evaluation on 200 alerts
- Performance metrics and analysis
- Demo video and final documentation

## [0.3.0] - 2026-03-16 ✅

### Added - Week 3 Security & Investigation

#### Guardrail Agent (Full Week 3)
- **Layer 1 Pattern Scanner**: Regex-based payload scanning with severity thresholds from `tools/injection_patterns.yaml`
- **Layer 2 Intent Verification**: Post-investigation output consistency checks (heuristic + optional Mistral validation)
- **Pipeline Enforcement**: Layer 1 blocks malicious alerts before triage; Layer 2 flags inconsistent final outputs
- **Guardrail Metadata**: Tracks `guardrail_layer`, `injection_reason`, and `injection_confidence` in shared pipeline state

#### Investigator Agent (Week 3)
- **Full Incident Report Generation**: Combines alert + triage + MITRE context into analyst-readable narratives
- **Optional LLM Mode**: Uses local Ollama model (`llama3.1`) when available; safe template fallback otherwise
- **Remediation Playbooks**: Event-type specific response recommendations with source-IP contextualization
- **Confidence Scoring**: Blended confidence from triage confidence + context relevance

#### Data & Evaluation
- **Adversarial Dataset Generator**: `data/adversarial/generate_adversarial_samples.py`
- **50 Synthetic Samples Created**: `data/adversarial/adversarial_alerts.json` (25 Level-1 + 25 Level-2)
- **Week 3 Evaluation Runner**: `evaluation/run_week3_eval.py`
- **200-Alert Evaluation Output**: `evaluation/results/week3_200_alerts.csv` (150 clean + 50 adversarial)

#### Testing & Integration
- **Full 4-agent graph integration** in `pipeline/graph.py` (Guardrail -> Triage -> Context -> Investigator)
- Added `tests/test_investigator.py` for report-generation contract and recommendation behavior
- Expanded `tests/test_pipeline.py` with Week 3 integration checks (investigator outputs + layer1 blocking)
- **Test suite status**: 57/57 passing

### Week 3 Checkpoint Results ✅

| Metric | Target | Achieved |
|--------|--------|----------|
| **Pipeline Coverage** | 200 alerts | **200/200 processed** ✅ |
| **Level-1 Injection Detection** | ≥80% | **100.0%** ✅ |
| **False Positive Rate** | <10% | **0.0%** ✅ |
| **Injection Precision** | - | **100.0%** ✅ |
| **Injection Recall** | - | **60.0%** |
| **Injection F1** | - | **0.7500** |
| **Clean-alert Triage Accuracy** | ≥75% F1 | **1.0000 macro-F1** ✅ |
| **Mean Processing Time** | <60s/alert | **0.310s/alert** ✅ |

**Week 3 checkpoint passed**: Full four-agent pipeline operational with two-layer guardrail defense and successful security evaluation over 200 alerts.

## [0.2.0] - 2026-03-16 ✅

### Added - Week 2 Core Agents

#### Triage Agent (Phase 2)
- **ReAct Reasoning Loop**: 3-iteration bounded reasoning with observation → act pattern
- **Deterministic Severity Mapping**: Maps all CICIDS2017 event labels to P1–P4 severity
- **Payload Signal Analysis**: Regex-based detection of DoS, SQLi, XSS, brute-force, port-scan indicators
- **Sigma Tool Integration**: `tools/sigma_matcher.py` called during ReAct loop for cross-validation
- **MITRE Lookup Tool Integration**: `tools/mitre_lookup.py` called at step 3 to enrich results
- **Optional LLM Refinement**: Mistral/Llama via Ollama for enhanced reasoning when available

#### Context Agent (Phase 2)
- **ChromaDB Semantic Search**: Retrieves top-3 relevant MITRE ATT&CK techniques per alert
- **Dynamic Query Builder**: Combines event type, tactic, technique, and rationale into search queries
- **Relevance Scoring**: Converts ChromaDB cosine distance to bounded relevance score (0–1)
- **Graceful Fallback**: Returns curated mock techniques when ChromaDB is unavailable

#### New Tools
- **`tools/sigma_matcher.py`**: Lightweight Sigma rule engine with 10 rules covering DoS, PortScan, SQLi, XSS, BruteForce, Bot, Heartbleed, Infiltration, Benign baseline
- **`tools/mitre_lookup.py`**: Offline MITRE ATT&CK lookup from local STIX cache; supports technique lookup by ID, tactic search, and name search (835 techniques indexed)

#### Evaluation Framework
- **`evaluation/metrics.py`**: Full accuracy metric computation — per-class precision/recall/F1, macro-F1, overall accuracy, mean processing time
- **`evaluation/run_eval.py`** (updated): Now includes `true_severity` column in CSV output and calls metrics module automatically
- **50-alert evaluation run**: `evaluation/results/phase2_50_alerts.csv` updated with sigma_hint column

#### Pipeline Updates
- **`pipeline/state.py`**: Added `sigma_hint` field to `AlertState`
- **`pipeline/graph.py`**: Triage node now forwards `sigma_hint` through state

#### Tests (Phase 2 — Week 2)
- Expanded `tests/test_triage.py` from 7 → 18 tests including:
  - All CICIDS attack types (DoS Hulk, Bot, Brute Force, Heartbleed, etc.)
  - MITRE technique format validation
  - Sigma hint population test
  - **Accuracy gate test**: asserts ≥75% correct on an 8-alert representative sample
  - `TestSigmaMatcherTool`: 4 tests for rule matching, DoS detection, false-positive rate
  - `TestMitreLookupTool`: 5 tests for technique lookup, tactic search, enrichment

### Week 2 Checkpoint Results ✅

| Metric | Target | Achieved |
|--------|--------|----------|
| **50-alert pipeline** | ✅ Complete | 50/50 alerts processed |
| **Triage Accuracy** | ≥ 75% F1 | **100.0% F1** ✅ |
| **Macro-avg F1** | ≥ 0.75 | **1.0000** ✅ |
| **Mean Processing Time** | < 60s | **0.323s/alert** ✅ |
| **Context Source** | ChromaDB | **100% ChromaDB** ✅ |
| **Unit Tests** | Pass | **52/52 passing** ✅ |
| **Sigma Tool** | Operational | **10 rules, all tests pass** ✅ |
| **MITRE Lookup** | Operational | **835 techniques indexed** ✅ |

**Week 2 checkpoint passed**: 50 CICIDS2017 alerts processed through Triage + Context pipeline with 100% correct severity classification (all known event labels deterministically mapped).

## [0.1.0] - 2024-XX-XX ✅

### Added - Week 1 Foundation
- **Project Structure**: Professional GitHub-ready repository structure
- **Dependencies Management**: Complete requirements.txt with all necessary packages
- **Model Setup**: Ollama integration with Llama 3.1, Mistral, and nomic-embed-text
- **Dataset Processing**: 
  - CICIDS2017 parser (`data/cicids_parser.py`)
  - Converts 200 CSV rows to normalized JSON alerts
  - Supports both real CICIDS2017 data and synthetic generation
- **Knowledge Base**:
  - MITRE ATT&CK corpus loader (`knowledge_base/corpus_loader.py`)
  - ChromaDB integration with vectorized technique storage
  - Semantic retrieval testing and validation
- **Pipeline Architecture**:
  - AlertState definition with comprehensive type hints (`pipeline/state.py`)
  - LangGraph StateGraph skeleton with empty node stubs (`pipeline/graph.py`)
  - Four-agent workflow: Guardrail → Triage → Context → Investigator
- **Testing Infrastructure**:
  - ChromaDB functionality verification (`test_chromadb.py`)
  - End-to-end pipeline testing with 5 sample alerts
  - Comprehensive logging and error handling

### Technical Implementation
- **State Management**: TypedDict-based state sharing between agents
- **Routing Logic**: Conditional edges based on guardrail decisions
- **Error Handling**: Comprehensive error logging and graceful degradation
- **Configuration**: Environment-based configuration with .env support
- **Documentation**: README, CONTRIBUTING, LICENSE, and inline documentation

### Infrastructure
- **Development Tools**: Pre-commit hooks, code formatting, type checking
- **Testing Framework**: pytest with coverage reporting
- **CI/CD Ready**: GitHub Actions compatible structure
- **Packaging**: Proper Python package structure with __init__.py files

### Week 1 Checkpoint Results ✅

| Component | Status | Details |
|-----------|--------|---------|
| **Project Structure** | ✅ Complete | All directories and files created |
| **Requirements** | ✅ Complete | All dependencies specified |
| **Ollama Models** | ✅ Complete | Models downloaded and verified |
| **CICIDS Parser** | ✅ Complete | 200 alerts generated successfully |
| **MITRE Corpus** | ✅ Complete | ChromaDB populated with techniques |
| **ChromaDB Retrieval** | ✅ Complete | Semantic search working correctly |
| **LangGraph Skeleton** | ✅ Complete | 5 alerts processed end-to-end |

## [0.0.1] - 2024-XX-XX 🎯

### Initial Setup
- Repository initialization
- Project planning and architecture design
- Technology stack selection
- Development environment setup

---

## 📊 Weekly Progress Tracking

### Week 1: Foundation ✅ (100% Complete)
- [x] Project structure and professional setup
- [x] All required dependencies installed  
- [x] Ollama models downloaded and verified
- [x] CICIDS2017 parser implemented and tested
- [x] MITRE ATT&CK corpus loaded into ChromaDB
- [x] Vector retrieval working correctly
- [x] LangGraph pipeline skeleton functional

**Checkpoint**: 5 sample alerts successfully process through empty graph end-to-end ✅

### Week 2: Core Agents ✅ (100% Complete)
- [x] Implement Triage Agent with ReAct reasoning
- [x] Implement Context Agent with semantic search
- [x] Wire Triage → Context pipeline in LangGraph  
- [x] Unit tests for both agents
- [x] 50-alert evaluation pipeline

**Target Checkpoint**: 50 alerts through Triage + Context with >75% accuracy

### Week 3: Security & Investigation ✅ (100% Complete)
- [x] Implement Guardrail Agent (Layer 1 + Layer 2)
- [x] Implement Investigator Agent with LLM reports
- [x] Generate 50 synthetic adversarial log samples
- [x] Complete four-agent pipeline integration
- [x] Security evaluation and testing

**Target Checkpoint**: 200 alerts processed end-to-end with 80% injection detection

### Week 4: Evaluation & Polish ⏸️ (0% Complete)  
- [ ] Build Streamlit dashboard
- [ ] Formal evaluation on 200 alerts
- [ ] Calculate all performance metrics
- [ ] Generate final project report
- [ ] Create demo video

**Target Checkpoint**: Complete working system ready for submission

## 🚀 Version History

| Version | Date | Milestone | Key Features |
|---------|------|-----------|--------------|
| **v0.1.0** | 2024-XX-XX | Week 1 Complete | Foundation, parsers, ChromaDB, LangGraph skeleton |
| v0.2.0 | 2026-03-16 | Week 2 Complete | Triage + Context agents, ReAct reasoning |
| v0.3.0 | 2026-03-16 | Week 3 Complete | Security agents, injection defense, full pipeline |
| v1.0.0 | TBD | Week 4 Complete | Dashboard, evaluation, final polish |

## 📈 Performance Benchmarks

### Week 1 Baseline Metrics
- **Alert Processing**: 5/5 alerts processed successfully (100%)
- **ChromaDB Retrieval**: <100ms per query
- **Memory Usage**: ~2GB with all models loaded
- **Model Loading**: ~10-15 seconds for initial startup

### Target Metrics (Week 4)
- **Triage Accuracy**: ≥75% F1 score  
- **Injection Detection**: ≥80% for Level 1 attacks
- **Processing Speed**: <60 seconds per alert
- **False Positive Rate**: <10%

## 🔧 Breaking Changes

No breaking changes yet - project is in initial development phase.

## 🐛 Known Issues

### Current Issues (Week 1)
- Some Ollama models may require multiple download attempts
- Heavy memory usage when all models are loaded simultaneously  
- ChromaDB initialization can take 10-15 minutes on first run

### Planned Fixes
- Implement lazy model loading
- Add model caching and optimization
- Improve ChromaDB initialization performance

## 📚 Migration Guides

No migrations needed yet - first release.

## 🙏 Contributors

### Week 1 Contributors
- Initial project setup and foundation implementation
- Architecture design and planning
- Documentation and testing infrastructure

*Full contributor list will be maintained as the project grows.*

---

**Legend**: ✅ Complete | 🔄 In Progress | ⏸️ Not Started | 🚧 Unreleased