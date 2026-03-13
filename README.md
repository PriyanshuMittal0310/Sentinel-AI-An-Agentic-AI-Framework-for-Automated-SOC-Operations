# SENTINEL-AI 🛡️

> **An Agentic AI Framework for Automated Security Operations Centre (SOC) Triage and Investigation**  
> *Securing Agents Against Indirect Prompt Injection via Adversarial Logs*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## 🎯 Project Overview

SENTINEL-AI is a prototype multi-agent system that automates the triage and investigation of security alerts in a Security Operations Centre (SOC). What makes this project unique is its dual focus: **AI for Security** (automated threat analysis) and **Security for AI** (protecting AI agents from adversarial manipulation).

The system uses four cooperating AI agents powered by locally-running Large Language Models (LLMs):

- 🛡️ **Guardrail Agent**: Protects against indirect prompt injection attacks
- 📋 **Triage Agent**: Classifies alert severity using ReAct reasoning  
- 📚 **Context Agent**: Retrieves relevant MITRE ATT&CK knowledge
- 📝 **Investigator Agent**: Generates comprehensive incident reports

## ✨ Key Features

- **🔒 Zero External Dependencies**: Runs entirely on local LLMs via Ollama (no API keys required)
- **🧠 Semantic Knowledge Base**: MITRE ATT&CK framework stored in ChromaDB for contextual retrieval
- **🛡️ Injection-Resistant**: Novel two-layer defense against adversarial log manipulation
- **📊 Real Dataset Integration**: Evaluated on CICIDS2017 intrusion detection dataset
- **🔄 Stateful Multi-Agent Pipeline**: Built with LangGraph for complex workflows
- **📈 Live Dashboard**: Streamlit interface for real-time alert monitoring

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Guardrail     │───▶│     Triage      │───▶│     Context     │───▶│  Investigator   │
│     Agent       │    │     Agent       │    │     Agent       │    │     Agent       │
│                 │    │                 │    │                 │    │                 │
│ • Layer 1: Regex│    │ • ReAct Loop    │    │ • ChromaDB      │    │ • LLM Report    │
│ • Layer 2: LLM  │    │ • MITRE Mapping │    │ • Vector Search │    │ • Remediation   │
│ • Blocks Malicious│    │ • Confidence    │    │ • Top-3 Results │    │ • Actions       │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼  
    Injection                Severity               MITRE ATT&CK           Incident Report
    Detection              Classification           Techniques              & Recommendations
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** 
- **8GB+ RAM** (16GB recommended)
- **Ollama** installed ([Download here](https://ollama.com))

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/sentinel-ai.git
   cd sentinel-ai
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Download required models**:
   ```bash
   ollama pull llama3.1
   ollama pull mistral  
   ollama pull nomic-embed-text
   ```

4. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env file with your preferences (optional)
   ```

5. **Initialize knowledge base**:
   ```bash
   python knowledge_base/corpus_loader.py
   ```

6. **Run Week 1 tests**:
   ```bash
   python pipeline/graph.py
   python test_chromadb.py
   ```

### 🏃‍♂️ Running the System

**Process sample alerts**:
```bash
python data/cicids_parser.py  # Generate sample alerts
python pipeline/graph.py      # Test the pipeline
```

**Launch dashboard** (Coming in Week 4):
```bash
streamlit run dashboard/app.py
```

## 📂 Project Structure

```
sentinel-ai/
├── 📁 agents/              # AI agent implementations
├── 📁 data/                # Dataset processing and storage  
│   ├── raw/                # CICIDS2017 CSV files (not in git)
│   ├── processed/          # Normalized JSON alerts
│   └── adversarial/        # Synthetic injection samples
├── 📁 knowledge_base/      # MITRE ATT&CK management
├── 📁 pipeline/            # LangGraph orchestration
├── 📁 tools/               # Agent tools and utilities
├── 📁 evaluation/          # Testing and metrics
├── 📁 dashboard/           # Streamlit web interface
├── 📁 tests/               # Unit tests
├── 📄 requirements.txt     # Python dependencies
└── 📄 .env.example         # Configuration template
```

## 🛠️ Development Roadmap

### ✅ Week 1: Foundation (COMPLETED)
- [x] Project structure and dependencies
- [x] Ollama model setup (Llama 3.1, Mistral, nomic-embed-text)
- [x] CICIDS2017 parser (200 sample alerts)
- [x] MITRE ATT&CK corpus loader
- [x] ChromaDB initialization and retrieval testing
- [x] LangGraph StateGraph skeleton with empty nodes

**📋 Week 1 Checkpoint**: ✅ 5 sample alerts pass through empty graph end-to-end

### 🔄 Week 2: Core Agents (IN PROGRESS)
- [ ] Triage Agent with ReAct reasoning loop
- [ ] Context Agent with ChromaDB semantic search
- [ ] Full two-agent pipeline (Triage → Context)
- [ ] Unit tests and 50-alert evaluation

### 🛡️ Week 3: Security & Investigation  
- [ ] Guardrail Agent (Layer 1: regex, Layer 2: LLM)
- [ ] Investigator Agent with incident report generation
- [ ] 50 synthetic adversarial log samples
- [ ] Complete four-agent pipeline testing

### 🎯 Week 4: Evaluation & Polish
- [ ] Streamlit dashboard with live results
- [ ] Formal evaluation on 200 alerts (150 clean + 50 adversarial)
- [ ] Performance metrics and analysis
- [ ] Final documentation and demo video

## 📊 Evaluation Metrics (Target Week 4)

| Metric | Target | Purpose |
|--------|--------|---------|
| Triage Accuracy | ≥75% F1 | Correct severity classification |
| Injection Detection | ≥80% (Level 1) | Security defense effectiveness |  
| False Positive Rate | <10% | Minimize analyst alert fatigue |
| Processing Speed | <60s/alert | Operational efficiency |
| MITRE Retrieval Quality | Manual review | Knowledge base relevance |

## 🔧 Configuration

Key settings in `.env`:

```bash
# Models
OLLAMA_TRIAGE_MODEL=llama3.1
OLLAMA_GUARDRAIL_MODEL=mistral  
OLLAMA_EMBEDDING_MODEL=nomic-embed-text

# Database
CHROMADB_PATH=./knowledge_base/chroma_store
CHROMADB_COLLECTION_NAME=mitre_attack

# Processing
MAX_ITERATIONS=3
CONFIDENCE_THRESHOLD=0.7
```

## 🧪 Testing

Run all tests:
```bash
pytest tests/
```

Individual component tests:
```bash
python test_chromadb.py           # Knowledge base
python pipeline/graph.py          # Full pipeline  
python data/cicids_parser.py      # Dataset processing
```

## 📚 Dataset Information

**CICIDS2017**: Canadian Institute for Cybersecurity Intrusion Detection System Dataset
- **Source**: University of New Brunswick
- **Content**: 2.8M labeled network flows, 14 attack types
- **Usage**: 200 samples (100 benign + 100 attacks) for evaluation
- **Download**: [Official Site](https://www.unb.ca/cic/datasets/ids-2017.html)

## 🛡️ Security Features

### Indirect Prompt Injection Defense

**Layer 1 - Pattern Scanning**: Fast regex detection of injection triggers
```regex
ignore (all |previous |prior )?instructions?
disregard (the |your |all )?previous
override (security|classification|severity)
```

**Layer 2 - Intent Verification**: LLM consistency checking
- Separate Mistral 7B model validates output coherence  
- Flags inconsistent responses (e.g., whitelisting attackers)
- Defense-in-depth approach: prevention + detection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)  
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 References

- [ReAct: Reasoning and Acting in Language Models](https://arxiv.org/abs/2210.03629) - Core agent reasoning pattern
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Threat intelligence knowledge base
- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) - Evaluation benchmark
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/) - Multi-agent orchestration

## 📞 Support

- 📧 **Issues**: [GitHub Issues](https://github.com/yourusername/sentinel-ai/issues)
- 📖 **Documentation**: [Wiki](https://github.com/yourusername/sentinel-ai/wiki) 
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/sentinel-ai/discussions)

---

<p align="center">
  <strong>Built with ❤️ for cybersecurity and AI research</strong><br>
  <em>A college project exploring the intersection of AI agents and security operations</em>
</p>