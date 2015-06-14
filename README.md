# ro-wireshark

A collection of wireshark dissectors to parse the Ragnarok Online Protocol.
This is a work in progress.

## Installation

* Clone the repository and copy the files to your wireshark root directory.
* Add `dofile("/ro.lua");` to the end of your `init.lua`


## Usage

By default, ports `6900`, `6121` and `5121` are dissected. You can add ports
directly to the dissector table, or use "decode as..." if your server uses different
ports.

## Contributing

A lot of the packets are identified by name, but do not have an actual dissector
function associated to them. Pull requests with per-packet dissection are more
than welcome.

## TODO

Add hooks for supporting encryption/decryption of packets on servers that use it.