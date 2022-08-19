# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.2] - 2022-08-19
- Added GitHub workflows for Bandit, Flake8, Black and Pytest

## [3.1.0] - 2022-08-16
- Bump to minor version to prevent conflicts in dependency resolution when using
Poetry

## [3.0.0] - 2022-07-14
- The Packet Sniffer is now available as a library on PyPI under the name "net-sniffer".
- Changes were made to the application's structure to allow the correct namespaces 
when importing.
- The application code itself was subjected to a major restructuring that achieves 
better modularity and maintainability.
- An "executor" script named sniffer.py was added to the root directory of the project 
with the intent of making the execution of the application easier for users who are 
not familiarized with the manipulation of the PYTHONPATH environment variable. This 
configuration is done automatically by the interpreter by running the sniffer.py file 
from the root directory.
- The packaging functionality that involved the use of the PyInstaller package was 
excluded from the application itself. It now remains as the sole responsibility of 
the user to package it as a binary, if he so wishes.

## [2.1.0] - 2022-07-08
- The application was restructured for ease of use. The new layout dispenses with 
the need of passing the PYTHONPATH environment variable to `sudo` during execution.
- Updates were made to the documentation and requirements files.

## [2.0.1] - 2022-07-05
- Updated the README.md file to include the dependency on NETProtocols.
- Added support for ICMPv4 and ICMPv6.
- Removed the distribution of a pre-packaged binary file.

## [2.0.0] - 2022-02-22
- All manipulation of protocol logic was removed from the application. The 
"protocols" directory was removed and replace with the importing of the 
"netprotocols" library, available at PyPI.

## [1.1.1] - 2021-12-16
- Moved 'arp.py' file from 'src/protocols/layer3' to 'src/protocols/layer2' in
compliance with the OSI model.
