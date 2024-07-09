#!/bin/bash

# Disables IP forwarding to avoid ICMP Redirect packets
# when using ARP spoofing
sysctl -w net.ipv4.ip_forward=0
