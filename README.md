stnc - Network Communication Tool

stnc is a command-line tool that enables network communication and performance testing over various protocols. It provides chat functionality for two-way communication and allows users to measure the performance of different communication styles.

Features:

- Chat functionality for two-way communication over a network using IPv4 TCP protocol.
- Performance testing utility to measure the time it takes to transmit data using different communication styles:
  - IPv4 TCP
  - IPv4 UDP
  - IPv6 TCP
  - IPv6 UDP
  - Mmap a file
  - Named pipe
  - Unix Domain Socket (UDS) stream
  - Unix Domain Socket (UDS) datagram

Usage:

Chat Communication:

Client Side:
stnc -c IP PORT

Server Side:
stnc -s PORT

Performance Test:

Client Side:
stnc -c IP PORT -p <type> <param>

Server Side:
stnc -s PORT -p -q

Installation:

1. Clone the repository:
git clone https://github.com/your-username/stnc.git

2. Build the project:
cd stnc
make

3. Run the tool:
./stnc -c IP PORT  # for chat communication as a client
./stnc -s PORT  # for chat communication as a server
./stnc -c IP PORT -p <type> <param>  # for performance testing as a client
./stnc -s PORT -p -q  # for performance testing as a server

Requirements:

- C compiler
- Make utility

Contributing:

Contributions are welcome! If you find any issues or have suggestions for improvement, please open an issue or submit a pull request.

License:

This project is licensed under the MIT License.

Acknowledgements:

- The Beej IPC Guide (https://beej.us/guide/bgipc/html/) for valuable information on network programming and IPC.
- Chat GPT

Contact:

Made by Arieh Norton and Leead Jacobowitz
