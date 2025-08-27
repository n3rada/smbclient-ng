#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Module.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025

from __future__ import annotations

import argparse
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from smbclientng.core.Logger import Logger
    from smbclientng.core.SMBSession import SMBSession
    from smbclientng.types.Config import Config


class Module(object):
    """
    A parent class for all modules in the smbclient-ng tool.

    This class provides common attributes and methods that are shared among different modules.
    """

    name: str = ""
    description: str = ""
    smbSession: SMBSession = None
    options: argparse.Namespace = None

    def __init__(self, smbSession: SMBSession, config: Config, logger: Logger):
        self.smbSession = smbSession
        self.config = config
        self.logger = logger

    def parseArgs(self):
        raise NotImplementedError("Subclasses must implement this method")

    def run(self):
        """
        Placeholder method for running the module.

        This method should be implemented by subclasses to define the specific behavior of the module.
        """
        raise NotImplementedError("Subclasses must implement this method")

    def processArguments(
        self, parser: argparse.ArgumentParser, arguments
    ) -> argparse.Namespace:
        if isinstance(arguments, list):
            arguments = " ".join(arguments)

        __iterableArguments = shlex.split(arguments)

        try:
            self.options = parser.parse_args(__iterableArguments)
        except SystemExit:
            pass

        return self.options
