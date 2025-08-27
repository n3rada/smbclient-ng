#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : CommandArgumentParser.py
# Author             : Podalirius (@podalirius_)
# Date created       : 17 mar 2025


import argparse
import sys


class CommandArgumentParserError(Exception):
    """
    A custom exception class for handling errors specific to the CommandArgumentParser class.
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class CommandArgumentParser(argparse.ArgumentParser):
    """
    A custom argument parser for handling Command-specific command-line arguments in the smbclientng application.

    This class extends the argparse.ArgumentParser and provides custom error handling specific to the needs of smbclientng Commands.
    It is designed to provide clear and user-friendly command-line interfaces for various Commands within the smbclientng suite.

    Attributes:
        None

    Methods:
        error(message: str):
            Overrides the default error handling to provide a more informative error message and display the help text.
    """

    exit_on_error: bool = False

    def __init__(self, *args, **kwargs):
        # Initialize the parent class with exit_on_error set to False
        kwargs["exit_on_error"] = self.exit_on_error
        super().__init__(*args, **kwargs)

    def parse_args(self, args=None, namespace=None):
        """
        Overrides the default parse_args method of argparse.ArgumentParser to provide a custom error message and help display.
        """

        do_help = False
        for arg in ["-h", "--help"]:
            if arg in args:
                do_help = True
                break

        if do_help:
            self.print_help()
            return None

        return super().parse_args(args, namespace)

    def error(self, message: str):
        """
        Overrides the default error handling of argparse.ArgumentParser to provide a custom error message and help display.

        This method is called when ArgumentParser encounters an error. It displays the help message and writes the error message
        to stderr.

        Args:
            message (str): The error message to be displayed.
        """

        self.print_help()
        sys.stderr.write("\n[!] Error: %s\n" % message)
        raise CommandArgumentParserError(message)
