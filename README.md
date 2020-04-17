# la-por
Linear algebra-based Proof of Retrievability protocol for ensuring data integrity

**Authors**: Michael Hanling and Dr. Daniel Roche

1. Requirements:
	- MPI
	- OpenSSL (minimum 1.1.1.1f)
	- CMake (minimum 3.13)

2. Credit (LINKS)
	- TinyMT
	- Flint 

2. Installation:
	1. create a build directory from top level
	`mkdir build; cd build/`
	2. run cmake
	`cmake ..`
	3. run make
	`make`
	4. switch to the binary directory
	`cd bin/`
	5. initialize the protocol
	`./init /path/to/client/config /path/to/server/config /path/to/merkle/config
	/path/to/merkle/tree`
	-- OR --
	`./client_init /path/to/client/config /path/to/merkle/config /path/to/merkle/tree`
	AND (above on client machine, below on remote machine)
	`./server_init /path/to/server/config /path/to/merkle/config /path/to/merkle/tree`

