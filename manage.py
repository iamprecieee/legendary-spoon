import click


def import_from_alembic():
    """Imports Alembic command and configuration objects.

    This helper function centralizes the import logic for Alembic,
    ensuring that the `command` module and `Config` object are readily available
    for various migration operations.

    Returns:
        A tuple containing the Alembic `command` module and the initialized `Config` object.
    """
    from alembic import command, config

    alembic_cfg = config.Config("alembic.ini")
    return command, alembic_cfg


@click.group()
def cli():
    """Command-line interface for managing the application.

    This CLI provides various subcommands for database migrations, running the server,
    and cleaning project artifacts.
    """

    pass


@cli.command()
@click.option("--message", "-m", required=True, help="Migration message")
def makemigrations(message):
    """Creates a new Alembic migration script.

    This command generates a new migration file based on changes detected in the database models.
    A descriptive message for the migration is required.

    Args:
        message: A string describing the purpose of the migration (e.g., "Add users table").
    """

    command, alembic_cfg = import_from_alembic()

    command.revision(alembic_cfg, autogenerate=True, message=message)
    click.echo(f"Migration created: {message}")


@cli.command()
def migrate():
    """Applies all pending Alembic migrations to the database.

    This command upgrades the database schema to the latest version defined by the migration scripts.
    """

    command, alembic_cfg = import_from_alembic()

    command.upgrade(alembic_cfg, "head")
    click.echo("Migrations completed")


@cli.command()
def runserver():
    """Runs the FastAPI development server.

    This command starts the Uvicorn server, which hosts the FastAPI application.
    It uses `runpy` to execute the `main.py` module as a script.
    """

    import runpy

    runpy.run_module("main", run_name="__main__")


@cli.command()
def clean():
    """Removes Python cache directories (__pycache__) and Ruff cache directories.

    This command helps in cleaning up generated build artifacts and cache files
    which can sometimes cause issues or consume unnecessary disk space.
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
    """Entry point for the command-line interface.

    When `manage.py` is executed directly, this block initiates the Click CLI application.
    """
    cli()
