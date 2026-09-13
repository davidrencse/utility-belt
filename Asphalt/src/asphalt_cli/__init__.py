# CLI package 
"""
Asphalt CLI package.
Exports the main CLI group and commands.
"""

__all__ = ['cli']

def __getattr__(name):
    """Lazy import to avoid circular import issues."""
    if name == 'cli':
        from .main import cli
        return cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")