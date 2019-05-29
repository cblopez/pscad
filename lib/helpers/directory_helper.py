# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import os
import re

from lib.helpers.colors import *


def is_a_directory(directory):
    """ Validates a string meant to be a used as a directory path.

        :param directory: Path to match
        :type directory: str
        :returns: True if the directory is correctly formed, False if not.
        :rtype: bool
    """

    if re.search("^(\.{1,2}/|/)([^/]+/)*([^/]+/?)?$", directory) is not None:
        return True
    else:
        return False


def test_directory(directory):
    """ Asks if there is an existing directory with that path.
    If there is not a directory, it asks the user if he wants to create it.
    If the user doesn't create it, then the app shuts down and asks for a valid directory and
    creates it if the user agrees. It controls the EEXISTS error, which may be raised due
    to a race condition when checking the directory.

        :param directory: Directory to create.
        :type directory: str
        :returns: The directory itself, without the last backlash.
        :rtype: str
    """
    # If invalid directory, print error and exit.
    if not is_a_directory(directory):
        halt_fail("Invalid directory: {} . Enter a valid one.".format(directory))
    # Delete last backslash
    directory = process_directory(directory)
    # If directory exists, print a success message
    if os.path.exists(directory):
        print_success("Valid directory: {}".format(directory))
    else:
        print_warning("Attempting directory creation.")
        try:
            os.makedirs(directory)
        except OSError as e:
            # If Exception is not about 'directory already exists'
            if e.errno != e.errno.EEXIST:
                halt_fail('Unable to create directory {}.\nUnexpected error: {}'.format(directory, e))
        print_success("Directory created successfully.")

    # Return the directory
    return directory


def process_directory(directory):
    """ Deletes the last backslash at the end of a directory, if there's one.

        :param directory: Directory to process.
        :type directory: str
        :returns: Directory without last backslash.
        :rtype: str
    """
    if directory.endswith("/"):
        return directory[:-1]
    else:
        return directory


