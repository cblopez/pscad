from setuptools import find_packages, setup
from PSCAD.lib.core.__version__ import __version__

# Open README.md for long description
with open('README.md', 'r') as readme:
    setup(
        name="PSCAD",
        license="GPLv3",
        description="A network toolkit that can be used "
                    "to scan, sniff and discover hosts.",
        long_description=readme.read(),
        long_description_content_type="text/markdown",
        author="cblopez",
        version=__version__,
        url="https://github.com/cblopez/pscad",
        packages=find_packages(),
        package_data={'': ['*.txt']},
        entry_points={
            'console_scripts': [
                'pscad = PSCAD.pscad:main'
            ]
        },
        classifiers=[
            'Programming Language :: Python :: 3',
            'Topic :: Security',
            'Topic :: System :: Networking :: Monitoring',
            'Operating System :: Unix',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)'
        ],
        install_requires=['scapy',
                          'configparser',
                          'python-nmap',
                          'netifaces',
                          'reportlab'],
        include_package_data=True
    )
