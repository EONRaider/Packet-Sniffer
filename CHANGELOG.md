# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
