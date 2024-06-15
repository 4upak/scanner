# ICMP/TCP Scanner

This is a multithreaded ICMP/TCP scanner written in Python.

## Usage

./scanner.py -i <ip_range> -p <ports> -t <threads> --interface <interface>

## Example

sudo python scanner.py -i 192.168.0.1/24 -p 22 80 443 -t 10
