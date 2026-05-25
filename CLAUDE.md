# High Level Overview
Syslog implementations like rsyslog are useful for unstructured and
structured audit and log messages.
Features like RELP provide cryptographic integrity for data in transit and other guarantees
about the transmission of audit and log data.
Rsyslog + RELP does not provide cryptographic integrity of stored audit records, which is
mandated by NIST SP 800-92, DoD, and IC requirements.
Other high assurance audit and log systems like JALoP provide digest/hash chaining and signatures
to meet these requirements, but performance is terrible.
JALoP's non-syslog-compliant approach has a heavy development burden for applications
and integrators.

This mmhashchainsigs project aims to provide a rsyslog plugin module to help tackle this problem on
rsyslog-based systems.
The module could hash individual messages or large blocks of messages, whichever is more performant.
Periodically, the module can sign the last hash and inject the signature into a log message.
The authenticity and integrity of the log messages must be verifiable by a receiver with a stored
copy of the log data and the public key corresponding to the signature.

This project also provides a command-line tool to verify stored log data.

Target operating systems are:
* RHEL 10
* Ubuntu 24.04 LTS

# Implementation Goals
C is chosen for compatibility with rsyslog modules.
Stability and performance are paramount.
Other dependencies should be kept to a minimum and they should only be used when they meet the other goals and when they greatly simplify the implementation.

