#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : tail.py
# Author             : Podalirius (@podalirius_)
# Date created       : 18 mar 2025

import charset_normalizer
from loguru import logger
from impacket.smb3 import SessionError as SMB3SessionError
from impacket.smbconnection import SessionError as SMBConnectionSessionError

from smbclientng.types.Command import Command
from smbclientng.types.CommandArgumentParser import CommandArgumentParser
from smbclientng.utils import resolve_remote_files
from smbclientng.utils.decorators import active_smb_connection_needed, smb_share_is_set


class Command_tail(Command):
    name = "tail"
    description = "Get the last <n> lines of a remote file."

    HELP = {
        "description": [description, "Syntax: 'tail <file>'"],
        "subcommands": [],
        "autocomplete": ["remote_file"],
    }

    def setupParser(self) -> CommandArgumentParser:
        parser = CommandArgumentParser(prog=self.name, description=self.description)
        parser.add_argument(
            "-n", "--lines", type=int, default=10, help="Number of lines to display"
        )
        parser.add_argument("files", nargs="*", help="Files or directories to get")
        return parser

    @active_smb_connection_needed
    @smb_share_is_set
    def run(self, interactive_shell, arguments: list[str], command: str):
        # Command arguments required   : Yes
        # Active SMB connection needed : Yes
        # SMB share needed             : Yes

        self.options = self.processArguments(arguments=arguments)
        if self.options is None:
            return

        if len(self.options.files) == 0:
            self.options.files = ["*"]

        # Parse wildcards
        files_and_directories = resolve_remote_files(
            interactive_shell.sessionsManager.current_session, arguments
        )

        for path_to_file in files_and_directories:

            if len(files_and_directories) > 1:
                logger.info((path_to_file + " ").ljust(80, "="))

            if interactive_shell.sessionsManager.current_session.path_isfile(
                pathFromRoot=path_to_file
            ):
                # Read the file
                try:
                    rawcontents = (
                        interactive_shell.sessionsManager.current_session.read_file(
                            path=path_to_file
                        )
                    )

                    if rawcontents is not None:
                        encoding = charset_normalizer.detect(rawcontents)["encoding"]

                        if encoding is not None:
                            filecontent = rawcontents.decode(encoding).rstrip()
                            lines = filecontent.split("\n")
                            if len(lines) > self.options.lines:
                                filecontent = "\n".join(lines[-self.options.lines :])
                            if len(files_and_directories) > 1:
                                logger.info((path_to_file + " ").ljust(80, "="))
                            logger.info(filecontent)

                        else:
                            logger.error(
                                "Could not detect charset of '%s'." % path_to_file
                            )

                except (SMBConnectionSessionError, SMB3SessionError) as err:
                    logger.error("SMB Error: %s" % err)
