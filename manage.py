import click


def import_from_alembic():
    """Import and configure Alembic command interface.

    Centralizes Alembic imports and configuration setup to ensure consistent migration
    handling across all management commands.

    Returns
    -------
    Tuple[command.Command, config.Config]
        Alembic command module and configured Config instance for executing migrations.
    """
    from alembic import command, config

    alembic_cfg = config.Config("alembic.ini")
    return command, alembic_cfg


@click.group()
def cli():
    """Management command interface for the application.

    Provides subcommands for database migration management, server control,
    and project maintenance utilities.
    """
    pass


@cli.command()
@click.option("--message", "-m", required=True, help="Migration message")
def makemigrations(message):
    """Generate new Alembic migration from model changes.

    Analyzes current SQLModel definitions against database schema
    and creates a new migration file with detected changes.
    Requires a descriptive message for migration identification.

    Parameters
    ----------
    message: str
        Descriptive message explaining the migration purpose.
        Should be concise but informative (e.g., "Add user authentication").

    Examples
    --------
    Create migration for new user table:
        $ python manage.py makemigrations -m "Add user table"

    Create migration for column changes:
        $ python manage.py makemigrations -m "Add email verification field"
    """
    command, alembic_cfg = import_from_alembic()
    command.revision(alembic_cfg, autogenerate=True, message=message)
    click.echo(f"Migration created: {message}")


@cli.command()
def migrate():
    """Apply all pending database migrations.

    Executes unapplied migrations in chronological order to bring database schema
    up to date with current model definitions.

    Raises
    ------
    AlembicError
        If migration conflicts exist or database connection fails.
    """
    command, alembic_cfg = import_from_alembic()
    command.upgrade(alembic_cfg, "head")
    click.echo("Migrations completed")


@cli.command()
def runserver():
    """Start a FastAPI development server instance.

    Launches the application using the main module's entry point
    with development-optimized settings including auto-reload
    and debug logging when configured.
    Uses `runpy` to execute the `main.py` module as a script.
    """
    import runpy

    runpy.run_module("main", run_name="__main__")


@cli.command()
def clean():
    """Remove Python cache and build artifacts.

    Recursively removes __pycache__ directories, .pyc files,
    and Ruff cache directories to resolve import issues and remove clutter
    from development environment.
    """
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
    """CLI entry point for direct script execution.

    Initializes Click command group and processes command-line arguments
    for development task execution.
    """
    cli()
