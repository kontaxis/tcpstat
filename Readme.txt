# This program counts the number of packets per protocol port.
# Can be used for instance to get an idea of how much HTTP (TCP 80)
# vs HTTPS (TCP 443) traffic is present in the network.
#
# For TCP it makes sense to set a BPF* to count flows instead of total packets.
# For UDP we don't have that option. TODO implement conntrack.
# For ICMP all packets are mapped to port 0.
#
# Important! A BPF MUST limit packet capture to a single protocol (e.g., TCP)
# otherwise counts for the same port in different protocols will be aggregated.
#
# *: If no BPF is set the default filter captures HTTP/HTTPS flows.
#    To run with an empty BPF (no recommended) use: -f ""
#
# kontaxis 2014-11-03

# Build
make

# Clean
make clean

# Run on an ethernet interface.
sudo ./tcpstat -i eth0

# Run on an ethernet interface. (debug/verbose)
# All packets processed will be written to file ./eth0.pcap
sudo ./tcpstat_dbg -i eth0

# Run on a raw IP interface. (e.g., P-t-P tunnel)
sudo ./tcpstat_noether -i tun0

# Run on a raw IP interface. (e.g., P-t-P tunnel) (debug/verbose)
# All packets processed will be written to file ./tun0.pcap
sudo ./tcpstat_noether_dbg -i tun0

# Signals: receipt of SIGUSR1 will print current packet counts to stdout
sudo pkill --signal SIGUSR1 -x tcpstat
