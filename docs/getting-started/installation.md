# Installation

## Requirements

PAuth requires Python 3.12 or higher.

## Basic Installation

Install PAuth using pip:

```bash
pip install pauth
```

## Framework-Specific Installation

If you're using a specific web framework, install PAuth with the appropriate extras:

### Flask

```bash
pip install pauth[flask]
```

This includes Flask and all necessary dependencies for Flask integration.

### Django

```bash
pip install pauth[django]
```

This includes Django and all necessary dependencies for Django integration.

### All Frameworks

To install support for all frameworks:

```bash
pip install pauth[all]
```

## Development Installation

If you want to contribute to PAuth or run the tests, install the development dependencies:

```bash
# Clone the repository
git clone https://github.com/utkarsh5026/pauth.git
cd pauth

# Install with Poetry (recommended)
poetry install

# Or with pip
pip install -e ".[dev]"
```

## Verifying Installation

Verify that PAuth is installed correctly:

```python
import pauth
print(pauth.__version__)
```

You should see the version number printed without any errors.

## Next Steps

Now that you have PAuth installed, check out the [Quick Start](quick-start.md) guide to create your first OAuth integration!
