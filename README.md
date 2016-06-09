I. Overview

Regexbench is a benchmacking tool for measuring matching
throughput among various regex expression matching engines. Currently it
supports rematch, hyperscan, pcre2, pcre2jit and re2.

II. Usage

`regexbench` is a commandline application. It is designed to
work with libpcap. The typical usage is:

`./regexbench myre.re mypcap.pcap`

* myre.re - regular expression rule file, the rule format is in pcre
  format '/abc/'.

* mypcap.pcap - pcap file of packets to match

After match, `regexbench` will stop and display statistics, it will
also write the result to a json file (default `output.json`).

regexbench supports the following options:

* -h help info.

* -e engine to perform the matching. Currently it supports `rematch`,
   `hyperscan`, `pcre2`, `pcre2jit`, `re2`.

* -r repeat pcap multiple times.

* -c concatnate pcre2 rules. To turn on, one should specify `-c 1`,
   default off.

* -o output json file, default (`output.json`)

II. Output
TotalMatches
TotalMatchedPackets
UserTime
SystemTime
TotalTime
TotalBytes
TotalPackets
Mbps
Mpps
MaximumMemoryUsed(kB)
