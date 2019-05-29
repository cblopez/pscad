# -*- coding: utf8 -*-

# Copyright (C) Christian Barral López - All Rights Reserved
# Unauthorized copyright of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Christian Barral <cbarrallopez@gmail.com>, May 2019

import os
import sys
import subprocess as s

from lib.helpers.colors import *


def permissions_error(err):
    """ Checks if an error is caused by lack of user permissions.

        :param err: Error to check
        :type err: tuple
        :return: True if the error is about permissions.
        :return: False if the error is not about permissions
        :rtype: bool
    """

    if ('permitted' in err or 'permissions' in err) and 'DEPRECATION' not in err:
        return True
    return False


def install_nmap():
    """ Linux system based nmap installation.
    """

    pkt_dir = './packages/os'
    nmap_file = None

    # Check for nmap file
    try:
        nmap_file = [f for f in os.listdir(pkt_dir) if 'nmap' in f][0]
    except IndexError:
        halt_fail('Nmap(.deb) package not found under ./packages/os')

    # Execute RPM file installation with yum, Red Hat distribution
    nmap_install = s.Popen(['dpkg', '-i', pkt_dir + '/' + nmap_file], shell=True, stderr=s.PIPE)
    _, errors = nmap_install.communicate()
    # If errors, it probably means it is a Debian based SO
    if len(errors):
        if permissions_error(errors):
            print_fail('Popped error about permissions, try executing "sudo python offline_install.py":\n{}'
                       .format(errors))
        else:
            halt_fail('Could not install nmap, STDERR says:\n{}'.format(errors))

    else:
        print_success('Successfully installed nmap')


def install_module(pkg):
    """ Installs a given package using the pip command.

        :param pkg: Package to install
        :type pkg: str
    """

    mod_install = s.Popen(['pip', 'install', 'packages/' + pkg], stderr=s.PIPE)
    _, errors = mod_install.communicate()
    # If errors when installing module
    if len(errors):
        if permissions_error(errors):
            print_fail('Popped error about permissions, try executing "sudo python offline_install.py": {}'
                       .format(errors))
        elif 'DEPRECATION' in errors:
            print_fail('Deprecation warning when installing {}. STDERR says:\n{}'.format(pkg, errors))

        else:
            halt_fail('Could not install {}, STDERR says:\n{}'.format(pkg, errors))

    else:
        print_success('Successfully installed module from {}'.format(pkg))


def main():
    """ Install the dependencies, including system applications and python modules.
    """
    pkg_dir = './packages'

    try:
        with open('/dev/null', 'w') as null_file:
            s.check_call(['nmap',  '-h'], shell=True, stdout=null_file)
        print_success('Nmap found on the system.')
    except s.CalledProcessError:
        print_fail('Nmap not found on the system, attempting installation...')
        install_nmap()

    # Get all packages under the ./packages directory. All files under './packages' that are not python executable
    # Do not search recursively
    packages = [f for f in os.listdir(pkg_dir) if os.path.isfile(os.path.join(pkg_dir, f)) and
                '.py' not in f]

    # Install all packages
    for pkg in packages:
        print pkg
        install_module(pkg)

    print_success('All packages have been successfully installed.')


if __name__ == '__main__':
    main()
