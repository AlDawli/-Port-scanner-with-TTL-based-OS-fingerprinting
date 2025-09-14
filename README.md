# -Port-scanner-with-TTL-based-OS-fingerprinting
The scanner emphasizes responsible use while providing powerful fingerprinting capabilities. It's designed to be both a practical security tool and an educational resource for understanding network-based OS detection techniques.

Core Capabilities

Port Scanning:
TCP and UDP port scanning with configurable threading
Multiple scan states: open, closed, filtered, error
Configurable timeouts and port ranges

OS Fingerprinting:
TTL analysis with hop count estimation
TCP window size correlation
IP ID behavior analysis
Bayesian-style scoring with confidence levels

Data Collection:
Observed TTL values and estimated initial TTLs
TCP window sizes and MSS values
IP ID sequencing patterns
Response timing characteristics

OS Signature Database The scanner includes signatures for:
Linux (various distributions)
Windows (7/8, 10/11)
FreeBSD, OpenBSD, macOS
Cisco IOS
Embedded Linux systems
Each signature includes expected TTL values, window sizes, and behavioral patterns.

Output Features
Detailed reasoning for each OS guess
Confidence percentages
Export to JSON/CSV formats
Visual formatting for human readability
