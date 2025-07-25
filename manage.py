import subprocess

import click

from alembic import command
from alembic.config import Config


@click.group()
def cli():
    """Command-line interface for managing the application."""

    pass


@cli.command()
@click.option("--message", "-m", required=True, help="Migration message")
def makemigrations(message):
    """Create a new Alembic migration with the given message."""

    alembic_cfg = Config("alembic.ini")
    command.revision(alembic_cfg, autogenerate=True, message=message)
    click.echo(f"Migration created: {message}")


@cli.command()
def migrate():
    """Apply all pending Alembic migrations."""

    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    click.echo("Migrations completed")


@cli.command()
def runserver():
    """Run the FastAPI development server."""

    subprocess.check_call(["python3", "main.py"])


@cli.command()
def clean():
    """Remove Python cache and Ruff cache directories."""

    subprocess.check_call(
        "find . -name '__pycache__' -type d -exec rm -rf {} +", shell=True
    )
    subprocess.check_call(
        "find . -name '.ruff_cache' -type d -exec rm -rf {} +", shell=True
    )
    subprocess.check_call("find . -name '.pyc' -type d -exec rm -rf {} +", shell=True)


if __name__ == "__main__":
    cli()
