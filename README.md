# la-por
Linear algebra-based Proof of Retrievability protocol for ensuring data integrity

**Authors**: Michael Hanling and Dr. Daniel Roche

*   Requirements:

	- MPI
	- OpenSSL (minimum 1.1.1.1f)
	- CMake (minimum 3.13)

    On Debian, based systems, you can get all these by running (as root)

        apt install cmake libssl-dev openmpi-bin

*   Sub-packaged software components
    (no extra download needed, just crediting the authors!):

	- [TinyMT](https://github.com/MersenneTwister-Lab/TinyMT)
	- [Flint](http://flintlib.org/)

*   Installation and running:

	1.  Create a build directory from top level:
	    `mkdir build; cd build/`

	2.  Run cmake:
	    `cmake ..`

	3.  Compile with
	    `make`

        4.  (Optional, for testing) create random datafile

            ```bash
            bin/random_file /path/to/datafile size_spec
            ```

        5.  Initialize config files:

            ```bash
            # create client and server config simultaneously
            bin/dual_init /path/to/datafile /path/to/client_config /path/to/server_config /path/to/merkle_config /path/to/merke_tree
            # (then copy files to client/server)

            #### --OR-- ####

            # create client config
            bin/client_init /path/to/datafile /path/to/client_config /path/to/merkle_config /path/to/merke_tree
            # create server config
            bin/server_init /path/to/datafile /path/to/server_config /path/to/merkle_config /path/to/merke_tree
            ```

        6.  Start server

            ```bash
            # note, server must be run from build directory because of MPI
            bin/server [-p PORT] [-h MPI_HOSTFILE] /path/to/server_config /path/to/merkle_config
            ```

        7.  Connect with client

            ```bash
            bin/client [-s SERVER_HOSTNAME] [-p PORT] /path/to/client_config /path/to/merkle_config
            # follow screen prompts to audit, read, or update
            ```
