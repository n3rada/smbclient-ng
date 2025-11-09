# Built-in imports
import argparse
import sys

# Third party library imports
from loguru import logger

# Local library imports
from smbclientng import __version__
from smbclientng.utils import banner
from smbclientng.utils import logbook
from smbclientng.core.InteractiveShell import InteractiveShell
from smbclientng.core.SessionsManager import SessionsManager
from smbclientng.types.Config import Config
from smbclientng.types.Credentials import Credentials


def build_parser() -> argparse.ArgumentParser:
    """
    Parse command-line arguments.

    This function sets up the argument parser and defines the command-line options for the SMB client console.
    It handles configuration, authentication, and session options, and validates the provided arguments.
    """

    parser = argparse.ArgumentParser(
        prog="smbclientng",
        description="smbclient-ng, a fast and user-friendly way to interact with SMB shares.",
        add_help=True,
        exit_on_error=True,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit.",
    )

    group_config = parser.add_argument_group("Config")

    group_config.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=3,
        help="Timeout for SMB connections (default: 3s)",
    )
    group_config.add_argument(
        "-a", "--advertised-name", type=str, help="Advertised machine name."
    )

    group_commands = parser.add_argument_group("Commands")
    group_commands.add_argument(
        "-C",
        "--command",
        default=[],
        action="append",
        help="smbclient-ng commands to execute.",
    )
    group_commands.add_argument(
        "-S", "--startup-script", type=str, help="Startup script with commands."
    )
    group_commands.add_argument(
        "-N", "--not-interactive", action="store_true", help="Non-interactive mode."
    )

    # Target arguments
    group_target = parser.add_argument_group("Target")
    group_target.add_argument(
        "host",
        type=str,
        help="Target SMB Server IP or hostname.",
    )
    group_target.add_argument(
        "-P",
        "--port",
        type=int,
        required=False,
        default=445,
        help="Target SMB Server port (default: 445).",
    )

    # Authentication arguments
    group_auth = parser.add_argument_group("Authentication & Connection")
    group_auth.add_argument(
        "-d", "--domain", default=".", type=str, help="Authentication domain."
    )
    group_auth.add_argument(
        "-u", "--user", type=str, default="", help="Username for authentication."
    )
    group_auth.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos authentication."
    )
    group_auth.add_argument(
        "--kdcHost",
        type=str,
        help="Fully qualified domain name (FQDN) of key distribution center (KDC) for Kerberos.",
    )

    # Password & Hashes
    group_secrets = parser.add_argument_group("Secrets")
    group_creds = group_secrets.add_mutually_exclusive_group()
    group_creds.add_argument(
        "-p", "--password", type=str, default="", nargs="?", help="Password."
    )
    group_creds.add_argument(
        "--no-pass", action="store_true", help="Do not prompt for a password."
    )
    group_creds.add_argument(
        "--hashes", type=str, metavar="[LMHASH:]NTHASH", help="NT/LM hashes."
    )
    group_creds.add_argument(
        "--aes-key",
        type=str,
        metavar="HEXKEY",
        help="AES key for Kerberos authentication.",
    )

    advanced_group = parser.add_argument_group(
        "Advanced Options", "Additional advanced or debugging options."
    )

    advanced_group.add_argument(
        "--no-colors", action="store_true", help="Disable colored output."
    )
    advanced_group.add_argument("-l", "--logfile", type=str, help="Log file path.")

    advanced_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (shortcut for --log-level DEBUG).",
    )

    advanced_group.add_argument(
        "--log-level",
        type=str,
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Set the logging level explicitly (overrides --debug).",
    )

    return parser


def run() -> int:
    """
    Main function to run the SMB client console.

    This function parses command-line arguments, initializes the configuration, logger, and session manager,
    and starts the interactive shell for the SMB client. It handles authentication and session creation based
    on the provided options.

    Steps:
    1. Parse command-line arguments.
    2. Validate and handle specific options (e.g., non-interactive mode, Kerberos authentication).
    3. Initialize configuration and logger.
    4. Create a new SMB session if authentication details are provided.
    5. Start the interactive shell if a session is successfully created.

    Returns:
        None
    """
    print(banner.display_banner())

    parser = build_parser()
    options = parser.parse_args()

    # Show help if no cli args provided
    if len(sys.argv) <= 1:
        parser.print_help()
        return 1

    if options.not_interactive and (
        options.startup_script is None and len(options.command) == 0
    ):
        print("[+] Option --not-interactive requires --startup-script or --command.")
        sys.exit(1)

    if options.user and not (options.password or options.no_pass or options.hashes):
        from getpass import getpass

        options.password = getpass(
            f"  | Provide a password for '{options.domain}\\{options.user}': "
        )

    if options.aes_key:
        options.kerberos = True

    if options.hashes and ":" not in options.hashes:
        options.hashes = ":" + options.hashes

    config = Config()
    config.debug = options.debug
    config.no_colors = options.no_colors
    config.not_interactive = options.not_interactive
    config.startup_script = options.startup_script
    config.commands = options.command

    # Determine log level based on debug flag
    log_level = "DEBUG" if options.debug else "INFO"

    logbook.setup_logging(
        level=log_level, logfile=options.logfile, no_colors=options.no_colors
    )

    sessions_manager = SessionsManager(config=config)

    if any(
        [
            options.domain != ".",
            options.user,
            options.password,
            options.hashes,
            options.no_pass,
        ]
    ):
        credentials = Credentials(
            domain=options.domain,
            username=options.user,
            password=options.password,
            hashes=options.hashes,
            use_kerberos=options.kerberos,
            aesKey=options.aes_key,
            kdcHost=options.kdcHost,
        )
        session_created = sessions_manager.create_new_session(
            credentials=credentials,
            host=options.host,
            port=options.port,
            timeout=options.timeout,
            advertisedName=options.advertised_name,
        )

        # Exit if session creation failed
        if session_created is False:
            return 1

    if sessions_manager.current_session is None:
        logger.error("No active session. Please authenticate first.")
        return 1

    shell = InteractiveShell(sessionsManager=sessions_manager, config=config)

    return shell.run()
