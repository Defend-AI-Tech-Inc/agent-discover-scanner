# Contributing to AgentDiscover Scanner

Thank you for your interest in contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Make your changes
4. Add tests for new features
5. Run tests: `uv run pytest tests/ -v`
6. Commit with clear messages
7. Push and create a Pull Request

## Adding New Framework Detection

To add support for a new AI framework:

1. Update `src/agent_discover_scanner/signatures.py`
2. Create test fixtures in `tests/fixtures/`
3. Add tests in `tests/test_scanner.py`

## Code Style

- Python 3.12+ with type hints
- Use `ruff` for linting: `uv run ruff check .`
- Follow existing patterns in the codebase

## Questions?

Open an issue or discussion on GitHub!
