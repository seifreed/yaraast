"""Main entry point for yaraast package."""

import sys


def main():
    """Main function for yaraast."""
    try:
        from yaraast.cli.main import cli

        return cli()
    except ImportError:
        # Fallback if CLI is not available
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
