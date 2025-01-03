# No DPI [Ver. 3] ALPHA
Unfinished modification of https://github.com/theo0x0/nodpi2

Transmits parts of TLS handshake to be sent from another computer as a row IPv6 packet.
This data is being transmitted through the internet as a DNS query for further resistance.
From user's computer sends random/fake data to bypass DPI.

## Usage

Run server.py on a remote pc (Pc1)

In fake.py modify address parameter to the address of Pc1

Make sure you're connection though ipv6 and it's available on your machines.

## Known Bugs

- Not every network allows modification of src IP
- Didn't always work (possible synchronization problems)
