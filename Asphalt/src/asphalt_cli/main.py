"""
Asphalt CLI - main entry point.
"""
import click
from .capture import capture
from .decode import decode
from .capture_decode import capture_decode
from .analyze import analyze

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

cli.add_command(capture)
cli.add_command(decode)
cli.add_command(capture_decode)
cli.add_command(analyze)

if __name__ == "__main__":
    cli()
