# Python 3 Network Packet Sniffer

![Python Version](https://img.shields.io/badge/python-3.6+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/EONRaider/Packet-Sniffer?label=CodeFactor&logo=codefactor&style=for-the-badge)](https://www.codefactor.io/repository/github/eonraider/packet-sniffer)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EONRaider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)
[![Twitter](https://img.shields.io/badge/Twitter-eon__raider-38A1F3?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

A Network Packet Sniffer developed in Python 3. Packets are disassembled
as they arrive at a given network interface controller and their information
is displayed on the screen.

This application maintains no dependencies on third-party modules and can be
run by any Python 3.6+ interpreter.

## Demo
![demo](https://github.com/EONRaider/static/blob/02a36787c0c2253e26c0e934b7c57a54181ccd55/packet-sniffer/demo.gif)

## Running the Application
### I. Execute the binary
Download the Network Packet Sniffer from the dist directory and run it. 
Administrative privileges are required due to the use of `socket.SOCK_RAW` by the
decoder.
```shell
user@host:~$ sudo ./packet_sniffer
```

### II. (Optional) Build your own binary
What if you don't trust third-party binaries running with `sudo` on your system? In this 
case the `build.py` file can be used to compile your own binary.

Building the binary requires the `PyInstaller` package. You just need to install all dependencies and build. 
Dependency management works with both [Poetry](https://python-poetry.org/) (recommended) and [Virtualenv](https://virtualenv.pypa.io/en/latest/). 
```shell
user@host:~$ git clone https://github.com/EONRaider/Packet-Sniffer.git
user@host:~$ cd Packet-Sniffer
user@host:~/Packet-Sniffer$ poetry install <--or--> pip install -r requirements.txt
user@host:~/Packet-Sniffer$ python3 build.py
```

### III. (Optional) Development Mode
It's also possible to run the application *without any third-party dependencies or 
manipulation of binaries.* Simply clone this repository with `git clone` and execute the `packet_sniffer.py` file. 
```shell
user@host:~$ git clone https://github.com/EONRaider/Packet-Sniffer.git
user@host:~$ sudo python3 packet_sniffer.py
```

## Usage
```
packet_sniffer.py [-h] [-i INTERFACE] [-d]

Network Packet Sniffer

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface from which packets will be captured (monitors
                        all available interfaces by default).
  -d, --displaydata     Output packet data during capture.
```

## Legal Disclaimer
The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state and
federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources. In this context the term "compromise" is
henceforth understood as the leverage of exploitation of known or unknown vulnerabilities
present in said systems, including, but not limited to, the implementation of
security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
