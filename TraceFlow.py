import os
import requests
import webbrowser
import json
import re
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from colorama import Fore, Style


def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + r"""
_____________________    _____  _________ ______________________.____    ________  __      __ 
\__    ___/\______   \  /  _  \ \_   ___ \\_   _____/\_   _____/|    |   \_____  \/  \    /  \
  |    |    |       _/ /  /_\  \/    \  \/ |    __)_  |    __)  |    |    /   |   \   \/\/   /
  |    |    |    |   \/    |    \     \____|        \ |     \   |    |___/    |    \        / 
  |____|    |____|_  /\____|__  /\______  /_______  / \___  /   |_______ \_______  /\__/\  /  
                   \/         \/        \/        \/      \/            \/       \/      \/ 

                         TraceFlow v1.0 - By ValiasXD
""" + Style.RESET_ALL)


def help_menu():
    print(Fore.YELLOW + """
Available Commands:
────────────────────────────────────────────────────────────────────────────
username <name>            - Search username on 50+ websites
username -s <site> <name>  - Search specific platform (e.g. github, reddit)
username -k <name>         - Search major known platforms
username -l <name>         - Extended search (slow, deep)
username -a -f <name>      - Combine search flags

email <email>              - Check for breached accounts (HIBP placeholder)

domain <domain>            - WHOIS domain info
geoip <ip>                 - Locate IP with Google Maps
ip -m <ip>                 - Open Google Maps directly for IP
ip -w <ip>                 - Webcam search near IP
ip -s <ip>                 - Passive info (ASN, ISP, etc.)

exif <image>               - Extract EXIF and GPS data from image
reverseimg <image>         - Reverse image search (opens browser)
imgmeta <image>            - Advanced image metadata summary

webcam <ip|country>        - Search for public webcams

datacollect -F <name>      - Collect OSINT on a target
datacollect -l <list>      - Accept links, usernames, and metadata for a report
datacollect -a             - Includes breach check, EXIF, IP, username
datacollect -p             - Outputs PDF/json report

help                       - Show this menu
exit                       - Exit the tool
""" + Style.RESET_ALL)


def explain_error(e):
    print(f"[!] Error: {e}\nPossible causes include invalid input, API limits, network errors, or unsupported formats.")


def validate_ip(ip):
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip)


def geo_ip_lookup(ip):
    print(f"\n[+] Geolocating IP: {ip}")
    if not validate_ip(ip):
        print("  [!] Invalid IP format.")
        return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data["status"] == "success":
                print(f"  IP       : {data['query']}")
                print(f"  Country  : {data['country']} ({data['countryCode']})")
                print(f"  Region   : {data['regionName']}")
                print(f"  City     : {data['city']}")
                print(f"  ISP      : {data['isp']}")
                print(f"  Lat,Long : {data['lat']}, {data['lon']}")
                maps_url = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
                print(f"  [🌍] Google Maps: {maps_url}")
                webbrowser.open(maps_url)
            else:
                print("  [!] Failed to retrieve geolocation.")
        else:
            print(f"  [!] HTTP Error {r.status_code}")
    except Exception as e:
        explain_error(e)


def extract_exif(image_path):
    print(f"\n[+] Extracting EXIF and camera metadata from: {image_path}")
    try:
        image = Image.open(image_path)
        exifdata = image._getexif()
        if not exifdata:
            print("  [!] No EXIF data found.")
            return

        gps_data = {}
        for tag_id, value in exifdata.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for key in value.keys():
                    gps_tag = GPSTAGS.get(key, key)
                    gps_data[gps_tag] = value[key]
            else:
                print(f"  {tag:25}: {value}")

        if gps_data:
            print("\n[+] GPS Metadata:")
            for key, val in gps_data.items():
                print(f"  {key:25}: {val}")
    except Exception as e:
        explain_error(e)


def reverse_image_search(image_path):
    print(f"\n[+] Opening browser for reverse image search: {image_path}")
    search_url = f"https://www.google.com/searchbyimage?image_url={image_path}"
    webbrowser.open(search_url)


def find_webcam(query):
    print(f"\n[+] Searching public webcams near: {query}")
    try:
        if validate_ip(query):
            url = f"http://www.insecam.org/en/byip/{query}/"
        else:
            url = f"http://www.insecam.org/en/bycountry/{query[:2].upper()}/"
        print(f"  🌐 Opening browser: {url}")
        webbrowser.open(url)
    except Exception as e:
        explain_error(e)


def collect_osint(target_name):
    print(f"[+] Collecting OSINT for: {target_name}")
    # Add OSINT collection logic here (can use APIs, searches, etc.)
    pass


def main():
    banner()
    help_menu()
    while True:
        try:
            cmd = input(Fore.GREEN + "\nTRACEFLOW > " + Style.RESET_ALL).strip()
            if cmd.startswith("exif "):
                _, img = cmd.split(" ", 1)
                extract_exif(img)
            elif cmd.startswith("geoip "):
                _, ip = cmd.split(" ", 1)
                geo_ip_lookup(ip)
            elif cmd.startswith("reverseimg "):
                _, img = cmd.split(" ", 1)
                reverse_image_search(img)
            elif cmd.startswith("webcam "):
                _, target = cmd.split(" ", 1)
                find_webcam(target)
            elif cmd.startswith("datacollect -F "):
                _, name = cmd.split(" ", 1)
                collect_osint(name)
            elif cmd == "help":
                help_menu()
            elif cmd == "exit":
                print("[+] Exiting TraceFlow. Goodbye.")
                break
            else:
                print("[!] Unknown command. Type 'help' for available commands.")
        except Exception as e:
            explain_error(e)


if __name__ == "__main__":
    main()