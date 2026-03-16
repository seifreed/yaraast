"""Main entry point for yaraast package."""


def main() -> None:
    """Main function for yaraast."""
    from yaraast.cli.main import cli

    cli()


if __name__ == "__main__":
    main()
