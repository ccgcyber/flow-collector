FLOW COLLECTOR
==============

Netflow datagram collector and parser with integration with NMAP :: API and REPUTATION :: API.


Installation
----------

To use the FLOW COLLECTOR 

* [Readonly](https://metacpan.org/pod/Readonly) -- Used to generate the constants
* [Net::Syslog](https://metacpan.org/pod/Net::Syslog) -- Used for sending events via syslog
* [Sys::Syslog](https://metacpan.org/pod/Sys::Syslog) -- Used for sending events locally
* [Net::Subnet](https://metacpan.org/pod/Net::Subnet) -- Used to match IP addresses
* [Mojo::UserAgent](https://metacpan.org/pod/Mojo::UserAgent) -- Used to send data to the REPUTATION :: API and NMAP :: data collection API

If you are installing to test only, you can run:

	cpanm Readonly Net::Syslog Sys::Syslog Net:Subnet Mojo::UserAgent

If you are installing the application for a production environment, it is recommended that you make use of the [local::lib](https://metacpan.org/pod/local::lib) to not modify Perl installed on your system. Another alternative is to use the [perlbrew](http://perlbrew.pl/).

To install locallib it is recommended that you create a limited user for your application, in this case, you can create a user called `flow_collector` and install the [local::lib](https://metacpan.org/pod/local::lib) in this user's home.

	cpanm local::lib

After installing it is necessary to add in the file `.bashrc` or `.profile` the environment variables for your application. To get them, execute `perl -Mlocal::lib`.


Configuration
------------

The API configuration is done by environment variables. An example configuration can be seen below:

	export FLOW_COLLECTOR_LOG="LOCAL"
	export FLOW_COLLECTOR_PORT="9993"
	export FLOW_COLLECTOR_IPTYPE="IPV4"

	export FLOW_CONNECTOR_NMAP_API_USER="user"
	export FLOW_CONNECTOR_NMAP_API_PASS="pass"
	export FLOW_CONNECTOR_NMAP_API_HOST="192.168.150.102"
	export FLOW_CONNECTOR_NMAP_API_PROTOCOL="https"

	export FLOW_CONNECTOR_REPUTATION_API_USER="user"
	export FLOW_CONNECTOR_REPUTATION_API_PASS="pass"
	export FLOW_CONNECTOR_REPUTATION_API_HOST="localhost"
	export FLOW_CONNECTOR_REPUTATION_API_PROTOCOL="http"
	export FLOW_CONNECTOR_REPUTATION_API_PORT="3000"

	export FLOW_CONNECTOR_NETWORK="10.0.0.0/8"
	export FLOW_CONNECTOR_SRC_TRUSTED="10.10.10.1"
	export FLOW_CONNECTOR_HONEYPOTS="10.10.0.0/24 10.10.3.0/24"
	export FLOW_CONNECTOR_DST_TRUSTED="8.8.8.8 10.10.0.0/16"
	export FLOW_CONNECTOR_DARKNET="10.11.0.0/16"

In this example, we put the events to be generated locally, so a folder called `log`.

In the following example, we set up for sending events to a remote collector:

	export FLOW_COLLECTOR_LOG="NET"
	export FLOW_COLLECTOR_SYSLOG_PORT="514"
	export FLOW_COLLECTOR_SYSLOG_HOST="192.168.0.32"
	export FLOW_COLLECTOR_PORT="9993"
	export FLOW_COLLECTOR_IPTYPE="IPV4"

	export FLOW_CONNECTOR_NMAP_API_USER="user"
	export FLOW_CONNECTOR_NMAP_API_PASS="pass"
	export FLOW_CONNECTOR_NMAP_API_HOST="192.168.150.102"
	export FLOW_CONNECTOR_NMAP_API_PROTOCOL="https"

	export FLOW_CONNECTOR_REPUTATION_API_USER="user"
	export FLOW_CONNECTOR_REPUTATION_API_PASS="pass"
	export FLOW_CONNECTOR_REPUTATION_API_HOST="localhost"
	export FLOW_CONNECTOR_REPUTATION_API_PROTOCOL="http"
	export FLOW_CONNECTOR_REPUTATION_API_PORT="3000"

	export FLOW_CONNECTOR_NETWORK="10.0.0.0/8"
	export FLOW_CONNECTOR_SRC_TRUSTED="10.10.10.1"
	export FLOW_CONNECTOR_HONEYPOTS="10.10.0.0/24 10.10.3.0/24"
	export FLOW_CONNECTOR_DST_TRUSTED="8.8.8.8 10.10.0.0/16"
	export FLOW_CONNECTOR_DARKNET="10.11.0.0/16"

In this example, events will be sent via Syslog to host 192.168.0.32, on port 514.

Use
---

The use is quite simple just run the application and configure the network equipment to send the flows to the port defined in LOW_COLLECTOR_PORT.


Limitations
--------------------

* The application is only capable of receiving flows in version 1 and in version 5. In future versions will be implemented the ability to receive new versions.
* The application also only checks the TCP protocol flows with flags.

Licensing
-------------

This software is free and should be distributed over the terms of Apache License v2.


Autor
-----

Copyright [Manoel Domingues Junior](http://github.com/mdjunior) <manoel at ufrj dot br>

