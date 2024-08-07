Need dependency: `apt-get install libpcap-dev`

Compile: `go build -w cascap`

This program allows you to capture and display data exchange between the CAS and the scrambler.

Copy the binary file to: `/usr/bin/..`

Usage: `cascap 192.168.1.70`, where 192.168.1.70 - ths scrambler ip-address.

**cascap** must be launched on the computer where the CAS is installed.

The second parameter can be used to add filtering by a specific port:
`cascap 192.168.1.70 42000`

![Screenshot cascap](https://github.com/unidiag/cascap/blob/main/Screenshot.jpg)
