#!/usr/bin/env python3

import threading
import queue
import argparse
import ipaddress
import random
import time
import warnings
import logging
from tqdm import tqdm
from scapy.all import sr1, IP, ICMP, TCP, conf, get_if_list, get_if_addr

# Отключение предупреждений Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0  # Отключение подробного вывода Scapy

# Объявляем очереди глобально
ip_queue = queue.Queue()
scan_results = {}
results_lock = threading.Lock()

# Функция для сканирования ICMP
def icmp_scan(ip, pbar_icmp):
    pkt = IP(dst=str(ip)) / ICMP()
    reply = sr1(pkt, timeout=2, verbose=False)
    if reply:
        with results_lock:
            if str(ip) not in scan_results:
                scan_results[str(ip)] = {'icmp': True, 'open_ports': []}
    pbar_icmp.update(1)

# Функция для сканирования TCP
def tcp_scan(ip, port):
    ttl = random.randint(64, 128)
    flags = "S"  # Использование SYN-флага для TCP сканирования
    pkt = IP(dst=str(ip), ttl=ttl) / TCP(dport=port, flags=flags, seq=random.randint(1000, 65535))
    reply = sr1(pkt, timeout=3, verbose=False)  # Увеличен таймаут до 3 секунд
    if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:
        with results_lock:
            if str(ip) in scan_results:
                scan_results[str(ip)]['open_ports'].append(port)
        # Отправляем RST, чтобы закрыть соединение
        sr1(IP(dst=str(ip)) / TCP(dport=port, flags="R"), timeout=3, verbose=False)  # Увеличен таймаут до 3 секунд

# Функция для многопоточного сканирования ICMP
def worker_icmp(pbar_icmp):
    while not ip_queue.empty():
        ip = ip_queue.get()
        icmp_scan(ip, pbar_icmp)
        ip_queue.task_done()

# Функция для многопоточного сканирования TCP
def worker_tcp(ip, ports, pbar_tcp):
    for port in ports:
        tcp_scan(ip, port)
        pbar_tcp.update(1)

def main():
    global num_threads  # Объявляем глобальную переменную для количества потоков
    parser = argparse.ArgumentParser(description="Multithreaded ICMP/TCP Scanner")
    parser.add_argument('-i', '--iprange', required=True, help='IP range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', nargs='+', type=int, required=True, help='List of TCP ports to scan')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of threads to use')
    parser.add_argument('--interface', help='Network interface to use', required=False)

    args = parser.parse_args()

    ip_range = args.iprange
    ports = args.ports
    num_threads = args.threads
    network_interface = args.interface

    # Скрытие предупреждений Scapy
    warnings.filterwarnings("ignore", category=UserWarning)

    # Вывод доступных интерфейсов, если интерфейс не указан
    if not network_interface:
        print("Available interfaces:")
        interfaces = [iface for iface in get_if_list() if get_if_addr(iface) != '0.0.0.0']
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface} ({get_if_addr(iface)})")

        iface_index = int(input("Select the interface number: "))
        network_interface = interfaces[iface_index]

    # Устанавливаем интерфейс для Scapy
    conf.iface = network_interface
    print(f"Using interface: {network_interface} with IP {get_if_addr(network_interface)}")

    # Генерация IP-адресов из диапазона
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        ips = list(network.hosts())
        for ip in ips:
            ip_queue.put(ip)
    except ValueError as e:
        print(f"Invalid IP range: {e}")
        return

    # Сканирование ICMP
    with tqdm(total=len(ips), desc="ICMP Scan") as pbar_icmp:
        # Запускаем потоки для сканирования IP-адресов (ICMP)
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=worker_icmp, args=(pbar_icmp,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    # Подготовка к TCP сканированию
    tcp_ips = [ip for ip, result in scan_results.items() if result['icmp']]

    print(f"Found {len(tcp_ips)} live hosts. Starting TCP scan...")

    # Сканирование TCP
    with tqdm(total=len(tcp_ips) * len(ports), desc="TCP Scan") as pbar_tcp:
        threads = []
        for ip in tcp_ips:
            t = threading.Thread(target=worker_tcp, args=(ip, ports, pbar_tcp))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    # Добавление задержки перед завершением скрипта
    time.sleep(5)

    print("Scanning completed.")

    # Выводим результаты
    for ip, result in scan_results.items():
        if result['icmp']:
            print(f"{ip} is up (ICMP)")
        if result['open_ports']:
            print(f"{ip} has open ports: {', '.join(map(str, result['open_ports']))}")

if __name__ == "__main__":
    main()