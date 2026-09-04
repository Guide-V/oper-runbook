"""Top-level ``mongoops`` command. Each operational script is mounted as a sub-command group."""

from __future__ import annotations

import typer
from dotenv import load_dotenv

from mongoops import __version__
from mongoops.regex_finder.cli import app as regex_finder_app

app = typer.Typer(
    name="mongoops",
    help="MongoDB operations scripts (Atlas and Enterprise Advanced).",
    rich_markup_mode="rich",
)
app.add_typer(regex_finder_app, name="regex-finder")


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    env_file: str = typer.Option(
        ".env", "--env-file", help="dotenv file with API keys (optional)."
    ),
    version: bool = typer.Option(False, "--version", is_eager=True, help="Show version and exit."),
) -> None:
    if version:
        typer.echo(f"mongoops {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()
    load_dotenv(env_file, override=False)


if __name__ == "__main__":
    app()
