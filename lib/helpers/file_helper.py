# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019


def check_file_existence(file_to_check):
    """Checks if the given file exists on the system.

        :param file_to_check: File to check for existance
        :type file_to_check: str
        :returns: True if file exists, false if not.
        :rtype: bool
    """
    try:
        temp = open(file_to_check, 'r')
    except EnvironmentError:
        return False

    temp.close()
    return True
