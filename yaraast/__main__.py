"""Main entry point for yaraast package."""

import sys


def main():
    """Main function for yaraast."""
    try:
        from yaraast.cli.main import cli

        return cli()
    except ImportError:
        # Fallback if CLI is not available
        print("YARAAST - YARA Abstract Syntax Tree toolkit")
        print("Version: 0.1.0")
        print("\nCLI module not available. Please install with: pip install yaraast[cli]")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
