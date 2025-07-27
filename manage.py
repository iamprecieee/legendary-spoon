import click


def import_from_alembic():
    """Import Alembic command and config."""
    from alembic import command, config

    alembic_cfg = config.Config("alembic.ini")
    return command, alembic_cfg


@click.group()
def cli():
    """Command-line interface for managing the application."""

    pass


@cli.command()
@click.option("--message", "-m", required=True, help="Migration message")
def makemigrations(message):
    """Create a new Alembic migration with the given message."""

    command, alembic_cfg = import_from_alembic()

    command.revision(alembic_cfg, autogenerate=True, message=message)
    click.echo(f"Migration created: {message}")


@cli.command()
def migrate():
    """Apply all pending Alembic migrations."""

    command, alembic_cfg = import_from_alembic()

    command.upgrade(alembic_cfg, "head")
    click.echo("Migrations completed")


@cli.command()
def runserver():
    """Run the FastAPI development server."""

    import runpy

    runpy.run_module("main", run_name="__main__")


@cli.command()
def clean():
    """Remove Python cache and Ruff cache directories."""

    import os
    import shutil

    for root, dirs, files in os.walk("."):
        for dir_name in dirs:
            if dir_name == "__pycache__" or dir_name == ".ruff_cache":
                shutil.rmtree(os.path.join(root, dir_name))
        for file_name in files:
            if file_name.endswith(".pyc"):
                os.remove(os.path.join(root, file_name))

    click.echo("Cleaned Python cache and Ruff cache directories.")


if __name__ == "__main__":
    cli()
