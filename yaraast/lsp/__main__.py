"""Entry point for the YARAAST Language Server."""


def main() -> None:
    from yaraast.lsp.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
