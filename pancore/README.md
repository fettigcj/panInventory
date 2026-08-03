pancore
=======

Core utilities shared across pan* projects.

Status
- Python: 3.11+
- Packaging: PEP 621 (pyproject.toml via setuptools)

Install (from Git)
- pip install git+https://github.com/fettigcj/pancore@main

Local development
- python -m pip install -U pip build
- python -m pip install -e .

Usage example

```python
from pancore import __version__
print(__version__)
```

License
- MIT (see pyproject.toml)
