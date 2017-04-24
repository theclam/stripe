#!/usr/bin/env bash

TRACES=(tcp_ip_gtp_udp_ipv6_gre_ip_sll)

for t in "${TRACES[@]}"; do
	diff "${t}.decap.pcap" <(../stripe -f -r "${t}.pcap" -w -)
	if [[ "$?" -ne "0" ]]; then
		echo "error on trace ${t}.pcap"
	fi
done
