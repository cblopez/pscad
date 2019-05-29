# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

from sys import exit

BLUE = '\033[94m'
SUCCESS = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'


def print_success(line):
    """Prints a line with the green color.

        :param line: line to print
        :type line: str
    """
    print('[' + SUCCESS + '+' + ENDC + '] ' + line)


def print_warning(line):
    """Prints a line with the yellow color.

        :param line: line to print
        :type line: str
    """
    print('[' + WARNING + '*' + ENDC + '] ' + line)


def print_fail(line):
    """Prints a line with the red color.

        :param line: line to print
        :type line: str
    """
    print('[' + FAIL + '!' + ENDC + '] ' + line)


def halt_fail(line):
    """Exits the program with an error message, all printed in red color.

    :param line: Line to print
    :type line: str
    """
    exit(FAIL + '[!] ' + line + ENDC)


