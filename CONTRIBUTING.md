# Contributing to PAuth

Thank you for your interest in contributing to PAuth! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate in all interactions.

## Getting Started

### Prerequisites

- Python 3.12 or higher
- Poetry (for dependency management)
- Git

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/pauth.git
   cd pauth
   ```

3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/utkarsh5026/pauth.git
   ```

4. **Install Poetry** (if not already installed):
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

5. **Install dependencies**:
   ```bash
   poetry install --with dev
   ```

6. **Activate the virtual environment**:
   ```bash
   poetry shell
   ```

## Development Workflow

### Creating a Branch

Create a new branch for your work:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test improvements
- `chore/` - Maintenance tasks

### Making Changes

1. **Write code** following our style guidelines (see below)

2. **Add tests** for your changes:
   ```bash
   # Run tests
   poetry run pytest

   # Run tests with coverage
   poetry run pytest --cov=src --cov-report=term-missing
   ```

3. **Format your code**:
   ```bash
   # Format with Black
   poetry run black .

   # Sort imports with isort
   poetry run isort .
   ```

4. **Check for linting issues**:
   ```bash
   # Run Flake8
   poetry run flake8 src/

   # Run MyPy (type checking)
   poetry run mypy src/
   ```

### Committing Changes

1. **Stage your changes**:
   ```bash
   git add .
   ```

2. **Commit with a descriptive message**:
   ```bash
   git commit -m "feat: add support for new OAuth provider"
   ```

   Commit message format:
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `style:` - Code style changes (formatting, etc.)
   - `refactor:` - Code refactoring
   - `test:` - Test changes
   - `chore:` - Maintenance tasks

3. **Keep commits atomic** - one logical change per commit

### Submitting a Pull Request

1. **Push your changes** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub:
   - Fill out the PR template completely
   - Link any related issues
   - Describe your changes clearly
   - Add screenshots if applicable

3. **Wait for review**:
   - Address any feedback from reviewers
   - Make requested changes in new commits
   - Push updates to your branch

4. **Merge**:
   - Once approved, a maintainer will merge your PR
   - Delete your branch after merging

## Code Style Guidelines

### Python Code Style

We follow PEP 8 with some modifications:

- **Line length**: 88 characters (Black default)
- **Indentation**: 4 spaces
- **Quotes**: Prefer double quotes for strings
- **Type hints**: Use type hints for all functions

Example:

```python
from typing import Optional

def get_authorization_url(
    scope: list[str],
    state: Optional[str] = None,
    use_pkce: bool = False,
) -> str:
    """
    Generate an authorization URL.

    Args:
        scope: List of OAuth scopes to request
        state: Optional state parameter for CSRF protection
        use_pkce: Whether to use PKCE flow

    Returns:
        The authorization URL

    Raises:
        ValueError: If scope is empty
    """
    if not scope:
        raise ValueError("Scope cannot be empty")

    # Implementation here
    return auth_url
```

### Documentation

- **Docstrings**: Use Google style docstrings
- **Comments**: Explain why, not what
- **README**: Update if adding new features
- **Type hints**: Always include type hints

### Testing

- **Coverage**: Maintain or improve test coverage
- **Test organization**: Mirror source code structure
- **Test naming**: Use descriptive names (`test_should_raise_error_when_scope_empty`)
- **Assertions**: Use specific assertions

Example test:

```python
import pytest
from src.client import OAuth2Client
from src.exceptions import InvalidScopeError

class TestOAuth2Client:
    """Test cases for OAuth2Client."""

    def test_should_raise_error_when_scope_empty(self):
        """Test that empty scope raises ValueError."""
        client = OAuth2Client(...)

        with pytest.raises(InvalidScopeError, match="Scope cannot be empty"):
            client.get_authorization_url(scope=[])

    def test_should_generate_pkce_pair_when_enabled(self):
        """Test PKCE pair generation when use_pkce is True."""
        client = OAuth2Client(..., use_pkce=True)
        url = client.get_authorization_url(scope=["openid"])

        assert "code_challenge" in url
        assert "code_challenge_method=S256" in url
```

## Adding a New OAuth Provider

To add a new OAuth provider:

1. **Create a provider file** in `src/providers/`:
   ```python
   # src/providers/newprovider.py
   from src.providers.base import BaseProvider

   class NewProviderOAuth(BaseProvider):
       """OAuth provider for NewProvider."""

       authorization_url = "https://provider.com/oauth/authorize"
       token_url = "https://provider.com/oauth/token"
       user_info_url = "https://provider.com/oauth/userinfo"

       # Implement required methods
   ```

2. **Add tests** in `src/tests/`:
   ```python
   # src/tests/test_newprovider.py
   import pytest
   from src.providers.newprovider import NewProviderOAuth

   class TestNewProviderOAuth:
       # Add comprehensive tests
   ```

3. **Update exports** in `src/providers/__init__.py`:
   ```python
   from .newprovider import NewProviderOAuth

   __all__ = [..., "NewProviderOAuth"]
   ```

4. **Add documentation** to README.md

5. **Add example** in `src/examples/`

## Running Tests

```bash
# Run all tests
poetry run pytest

# Run specific test file
poetry run pytest src/tests/test_client.py

# Run with coverage
poetry run pytest --cov=src --cov-report=html

# Run with verbose output
poetry run pytest -v

# Run only failed tests
poetry run pytest --lf
```

## Building and Publishing

### Local Build

```bash
# Build the package
poetry build

# Check the build
poetry run twine check dist/*
```

### Publishing (Maintainers Only)

Publishing is automated via GitHub Actions when a release is created.

## Reporting Issues

When reporting issues, please include:

1. **PAuth version**: `pip show pauth`
2. **Python version**: `python --version`
3. **Operating system**: Windows/macOS/Linux
4. **Full error message** and traceback
5. **Minimal code sample** to reproduce
6. **Expected vs actual behavior**

## Feature Requests

We welcome feature requests! Please:

1. **Check existing issues** first
2. **Describe the problem** you're trying to solve
3. **Propose a solution** if you have one
4. **Provide use cases** and examples
5. **Indicate willingness** to contribute

## Questions?

- **Documentation**: Check the [README](README.md)
- **Discussions**: Use [GitHub Discussions](https://github.com/utkarsh5026/pauth/discussions)
- **Email**: utkarshpriyadarshi5026@gmail.com

## License

By contributing to PAuth, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to PAuth! Your help makes this project better for everyone.
