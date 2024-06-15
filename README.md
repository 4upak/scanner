# ICMP/TCP Scanner

This is a multithreaded ICMP/TCP scanner written in Python. It allows you to scan a range of IP addresses for live hosts and open TCP ports.

## Features

- Multithreaded scanning for fast performance
- ICMP scanning to identify live hosts
- TCP scanning to detect open ports
- Easy-to-use command-line interface

## Requirements

- Python 3.6+
- Scapy library
- tqdm library

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/4upak/scanner.git
    ```

2. **Navigate to the project directory:**

    ```sh
    cd scanner
    ```

3. **Install the required dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the scanner with the following command:

```sh
./scanner.py -i <ip_range> -p <ports> -t <threads> --interface <interface>

## example

sudo ./scanner.py -i 192.168.1.0/24 -p 22 80 443 -t 4 --interface eth0
