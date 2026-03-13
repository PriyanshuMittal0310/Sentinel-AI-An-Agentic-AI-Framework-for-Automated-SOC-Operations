# Contributing to SENTINEL-AI 🤝

Thank you for your interest in contributing to SENTINEL-AI! This document provides guidelines for contributing to this cybersecurity AI research project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)  
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)

## 📜 Code of Conduct

This project adheres to a code of conduct adapted for academic and research environments:

- **Be Respectful**: Treat all contributors with respect, regardless of experience level
- **Be Collaborative**: This is a learning project - help others learn and grow
- **Be Constructive**: Provide helpful feedback and suggestions
- **Be Patient**: Remember this is a college project with learning objectives

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:
- Python 3.10 or higher
- Git installed and configured
- Ollama installed with required models
- Basic understanding of AI/ML and cybersecurity concepts

### Setting Up Development Environment

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/yourusername/sentinel-ai.git
   cd sentinel-ai
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development tools
   ```

4. **Set up pre-commit hooks**:
   ```bash
   pre-commit install
   ```

## 🔄 Development Workflow

### Branching Strategy

- `main`: Stable, working code (protected)
- `develop`: Integration branch for new features  
- `feature/*`: Individual feature development
- `bugfix/*`: Bug fixes
- `week-*`: Weekly milestone branches

### Creating a Feature Branch

```bash
git checkout -b feature/your-feature-name
# Make your changes
git add .
git commit -m "Add meaningful commit message"
git push origin feature/your-feature-name
```

## 🎯 Areas for Contribution

### Week 1 Enhancements
- [ ] Improve error handling in CICIDSParser
- [ ] Add more comprehensive unit tests
- [ ] Enhance ChromaDB retrieval performance
- [ ] Better logging and monitoring

### Week 2 Development  
- [ ] ReAct reasoning implementation for Triage Agent
- [ ] Advanced semantic search in Context Agent
- [ ] Agent communication optimization
- [ ] Performance benchmarking

### Week 3 Security Features
- [ ] Enhanced injection pattern detection
- [ ] Advanced LLM guardrails
- [ ] Adversarial sample generation
- [ ] Security testing framework

### Week 4 Polish & Evaluation
- [ ] Streamlit dashboard improvements
- [ ] Advanced analytics and visualization  
- [ ] Documentation enhancements
- [ ] Performance optimization

## 📏 Code Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- **Line Length**: 100 characters (not 79)
- **Formatting**: Use `black` for automatic formatting
- **Import Sorting**: Use `isort` for import organization
- **Type Hints**: Required for all public functions
- **Docstrings**: Google-style docstrings for all classes and functions

### Example Function

```python
def classify_alert_severity(
    alert_data: Dict[str, Any],
    confidence_threshold: float = 0.7
) -> Tuple[str, float]:
    """
    Classify the severity of a security alert.
    
    Args:
        alert_data: Dictionary containing alert information
        confidence_threshold: Minimum confidence for classification
        
    Returns:
        Tuple of (severity_level, confidence_score)
        
    Raises:
        ValueError: If alert_data is missing required fields
    """
    # Implementation here
    pass
```

### File Structure Conventions

- **Agents**: `agents/agent_name.py`
- **Tools**: `tools/tool_name.py`  
- **Tests**: `tests/test_component_name.py`
- **Utilities**: `utils/utility_name.py`

## 🧪 Testing Guidelines

### Test Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Critical Components**: 90% coverage (agents, security features)
- **Test Types**: Unit tests, integration tests, end-to-end tests

### Writing Tests

```python
import pytest
from agents.triage_agent import TriageAgent

class TestTriageAgent:
    """Test cases for the Triage Agent."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.agent = TriageAgent()
    
    def test_severity_classification_benign(self):
        """Test classification of benign traffic."""
        alert = {
            "event_type": "BENIGN",
            "source_ip": "192.168.1.1"
        }
        severity, confidence = self.agent.classify(alert)
        
        assert severity == "P4"
        assert confidence > 0.8
    
    def test_invalid_input_handling(self):
        """Test handling of invalid input data."""
        with pytest.raises(ValueError):
            self.agent.classify({})
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=agents --cov-report=html

# Run specific test file  
pytest tests/test_triage_agent.py

# Run tests for specific component
pytest -k "triage"
```

## 📝 Submitting Changes

### Pull Request Process

1. **Update Documentation**: Ensure README and docstrings are updated
2. **Add Tests**: Include tests for new functionality  
3. **Run Quality Checks**:
   ```bash
   black .                    # Format code
   isort .                    # Sort imports  
   flake8 .                   # Check style
   mypy .                     # Type checking
   pytest                     # Run tests
   ```
4. **Create Meaningful Commits**: Follow conventional commit format
5. **Submit PR**: Use the pull request template

### Commit Message Format

```
type(scope): brief description

Longer description if needed

- Bullet points for details
- Reference issues: Fixes #123
```

**Types**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`  
**Scopes**: `agents`, `pipeline`, `tools`, `data`, `dashboard`

### Pull Request Template

```markdown
## 📋 Changes Description
Brief description of what this PR does.

## 🎯 Motivation  
Why are these changes needed?

## 🧪 Testing
- [ ] Unit tests pass
- [ ] Integration tests pass  
- [ ] Manual testing completed

## 📚 Documentation
- [ ] README updated (if needed)
- [ ] Docstrings added/updated
- [ ] Comments added for complex logic

## ✅ Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added for new functionality
- [ ] No breaking changes (or clearly documented)
```

## 🐛 Bug Reports

When reporting bugs, please include:

- **Environment**: Python version, OS, Ollama version
- **Steps to Reproduce**: Clear, numbered steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Error Messages**: Full error output and logs
- **Additional Context**: Screenshots, configuration files

## 💡 Feature Requests

For new features, please provide:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Impact**: Who benefits and how?

## 📚 Documentation Contributions

Documentation improvements are always welcome:

- Fix typos and grammar
- Improve clarity and examples
- Add missing API documentation
- Create tutorials and guides
- Translate documentation

## 🎓 Learning Resources

For contributors new to the technologies used:

- **LangGraph**: [Official Documentation](https://langchain-ai.github.io/langgraph/)
- **ChromaDB**: [Getting Started Guide](https://docs.trychroma.com/)
- **MITRE ATT&CK**: [Framework Documentation](https://attack.mitre.org/)
- **Ollama**: [Model Documentation](https://ollama.com/library)

## 🆘 Getting Help

If you need help:

- 🐛 **Bug Reports**: [Create an Issue](https://github.com/yourusername/sentinel-ai/issues)
- 💬 **Questions**: [Start a Discussion](https://github.com/yourusername/sentinel-ai/discussions)
- 📖 **Documentation**: Check the [Wiki](https://github.com/yourusername/sentinel-ai/wiki)

## 🏆 Recognition

Contributors will be recognized in:
- README contributors section
- Release notes and changelogs  
- Academic paper acknowledgments (if published)

Thank you for helping make SENTINEL-AI better! 🚀