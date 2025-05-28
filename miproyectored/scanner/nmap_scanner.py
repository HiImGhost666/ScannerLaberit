import subprocess
import xml.etree.ElementTree as ET
import platform
import os
import time
import json
from typing import List, Optional

from ..model.device import Device
from ..util.data_normalizer import DataNormalizer
from ..risk.risk_analyzer import RiskAnalyzer

class NmapScanner:
    def __init__(self, nmap_path=None):
        self.data_normalizer = DataNormalizer()
        self.risk_analyzer = RiskAnalyzer() # Mantener la instancia si se usa en otros métodos no estáticos

        if nmap_path:
            self.nmap_path = nmap_path
            if not self._is_nmap_available(self.nmap_path):
                 print(f"[ERROR] Nmap no parece estar disponible en la ruta especificada: {nmap_path}")
                 self.nmap_path = None # Reset path if not available
        else:
            self.nmap_path = self._find_nmap_path()

        if not self.nmap_path:
            print("[ERROR] Nmap no encontrado en el PATH del sistema ni en ubicaciones comunes. "
                  "Por favor, instala Nmap y asegúrate de que esté en el PATH, "
                  "o proporciona la ruta explícitamente al constructor de NmapScanner.")
            # Considera lanzar una excepción o manejar el error de otra forma

    def _find_nmap_path(self):
        os_name = platform.system()
        command = "nmap"

        if os_name == "Windows":
            # Try with "nmap" (if in PATH)
            if self._is_nmap_available(command): return command
            # Check common paths on Windows
            common_path_program_files = "C:\\Program Files\\Nmap\\nmap.exe"
            if os.path.exists(common_path_program_files) and self._is_nmap_available(common_path_program_files): return common_path_program_files
            common_path_program_files_x86 = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
            if os.path.exists(common_path_program_files_x86) and self._is_nmap_available(common_path_program_files_x86): return common_path_program_files_x86
        else: # Linux, macOS
            if self._is_nmap_available(command): return command
            # You could check /usr/bin/nmap, /usr/local/bin/nmap, etc.
            common_path_usr_bin = "/usr/bin/nmap"
            if os.path.exists(common_path_usr_bin) and self._is_nmap_available(common_path_usr_bin): return common_path_usr_bin
            common_path_usr_local_bin = "/usr/local/bin/nmap"
            if os.path.exists(common_path_usr_local_bin) and self._is_nmap_available(common_path_usr_local_bin): return common_path_usr_local_bin

        return None

    def _is_nmap_available(self, command_or_path):
        try:
            # Use subprocess.run for better control and error handling
            result = subprocess.run([command_or_path, "-V"], capture_output=True, text=True, check=False)
            # Check if the command ran successfully (exit code 0) and produced some output
            return result.returncode == 0 and (result.stdout or result.stderr)
        except FileNotFoundError:
            # This exception is raised if the command_or_path is not found
            return False
        except Exception as e:
            # Catch other potential errors during execution
            # print(f"Error verifying Nmap at '{command_or_path}': {e}")
            return False

    def quick_scan(self, target: str) -> List[str]:
        """Realiza un escaneo rápido para encontrar hosts activos."""
        try:
            # -sn: Ping Scan - disable port scan
            # -n: No DNS resolution
            # --max-parallelism: Máximo número de escaneos paralelos
            command = [
                self.nmap_path,
                "-sn",  # Solo ping scan
                "-n",   # No DNS resolution
                "--max-parallelism", "256",  # Máximo paralelismo
                "-T4",  # Timing template (higher is faster)
                target
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Extraer IPs de la salida usando expresiones regulares
            import re
            ip_pattern = re.compile(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)')
            active_ips = ip_pattern.findall(result.stdout)
            
            return active_ips
            
        except Exception as e:
            print(f"Error en quick_scan: {e}")
            return []

    def detailed_scan(self, ip: str) -> Optional[Device]:
        """Realiza un escaneo detallado de un host específico."""
        try:
            # Escaneo más detallado para un solo host
            command = [
                self.nmap_path,
                "-sS",     # SYN scan
                "-sV",     # Version detection
                "-O",      # OS detection
                "-p-",     # Todos los puertos
                "--version-intensity", "5",  # Detección de versión más agresiva
                "-A",      # Habilitar detección de OS y versiones
                "--max-os-tries", "1",  # Limitar intentos de OS
                "-T4",     # Aggressive timing
                "--host-timeout", "60s",  # Timeout por host aumentado
                "-oX", "-",  # Output XML to stdout
                ip
            ]
            
            print(f"Escaneando {ip} con comando: {' '.join(command)}")  # Debug
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Error en el escaneo de {ip}: {result.stderr}")  # Debug
                return None
                
            # Parsear XML y crear Device
            try:
                root = ET.fromstring(result.stdout)
            except ET.ParseError as e:
                print(f"Error parseando XML para {ip}: {e}")  # Debug
                print(f"XML recibido: {result.stdout[:200]}...")  # Debug
                return None
                
            # Buscar el host en el XML
            host = root.find('.//host')
            if host is not None and host.find(".//status[@state='up']") is not None:
                return self._parse_host(host)
            else:
                print(f"No se encontró información del host para {ip}")  # Debug
                return None
            
        except Exception as e:
            print(f"Error en detailed_scan para {ip}: {e}")
            return None

    def scan(self, target, on_device_found=None):
        """Realiza un escaneo de red mostrando progreso en tiempo real."""
        if not self.nmap_path:
            print("Error: No se encontró nmap en el sistema.")
            return []

        # Configurar comando Nmap para escaneo rápido inicial
        fast_scan_command = [
            self.nmap_path,
            "-sn",               # No port scan, just host discovery
            "-PR",              # ARP scan
            "-PE",              # ICMP Echo
            "-PS21,22,23,25,80,443,3389",  # TCP SYN to common ports
            "-PA80,443",        # TCP ACK to common ports
            "-n",               # No DNS resolution
            "-T4",              # Aggressive timing
            "--min-parallelism=10",  # Parallel host scanning
            "--max-retries=2",  # Limit retries for faster results
            "-oX", "-"          # XML output
        ]

        try:
            print("=" * 50)
            print("[INFO] Iniciando descubrimiento de hosts...")
            
            # Fase 1: Descubrimiento rápido de hosts
            process = subprocess.Popen(
                fast_scan_command + [target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            devices = []
            current_xml = ""
            active_ips = set()

            while True:
                output = process.stdout.read(1)
                if output == '' and process.poll() is not None:
                    break
                if output:
                    current_xml += output
                    if "</host>" in current_xml:
                        try:
                            host_end = current_xml.find("</host>") + 7
                            host_xml = current_xml[:host_end]
                            root = ET.fromstring(host_xml)
                            
                            ip = root.find(".//address[@addrtype='ipv4']")
                            if ip is not None:
                                active_ips.add(ip.get('addr'))
                                
                        except Exception as e:
                            print(f"[ERROR] Error en fase 1: {str(e)}")
                        finally:
                            current_xml = current_xml[host_end:]

            print(f"[INFO] Encontrados {len(active_ips)} hosts activos")

            # Fase 2: Escaneo detallado de hosts activos
            detailed_scan_command = [
                self.nmap_path,
                "-sS",                # TCP SYN scan (requiere privilegios)
                "-sV",               # Version detection
                "-O",                # OS Detection (requiere privilegios)
                "-n",                # No DNS resolution
                "-Pn",               # Skip host discovery
                "-p-",               # All ports
                "--version-intensity=9", # Maximum version detection
                "--version-light",   # Lighter version detection for better compatibility
                "--osscan-limit",    # Limit OS detection to promising targets
                "--max-os-tries=3",  # More OS detection attempts
                "-T4",               # Aggressive timing
                "--min-rate=1000",   # Minimum packet rate
                "--max-retries=3",   # More retries for better accuracy
                "--host-timeout=120s", # Longer timeout for thorough scan
                # Scripts seguros y útiles
                "--script=default,banner,http-title,ssl-cert,ssh-auth-methods,smb-os-discovery,smb-system-info",
                "-oX", "-"           # XML output
            ]

            # Intentar primero con privilegios
            for ip in active_ips:
                try:
                    print(f"\n[INFO] Escaneando detalladamente {ip}...")
                    detailed_process = subprocess.Popen(
                        detailed_scan_command + [ip],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    current_xml = ""
                    device_found = False

                    while True:
                        output = detailed_process.stdout.read(1)
                        if output == '' and detailed_process.poll() is not None:
                            break
                        if output:
                            current_xml += output
                            if "</host>" in current_xml:
                                try:
                                    host_end = current_xml.find("</host>") + 7
                                    host_xml = current_xml[:host_end]
                                    root = ET.fromstring(host_xml)
                                    device = self._parse_host(root)
                                    
                                    if device:
                                        device_found = True
                                        devices.append(device)
                                        if on_device_found:
                                            on_device_found(device)
                                except Exception as e:
                                    print(f"[ERROR] Error procesando {ip}: {str(e)}")
                                finally:
                                    current_xml = current_xml[host_end:]

                    detailed_process.wait()

                    # Si el escaneo privilegiado falló, intentar sin privilegios
                    if not device_found:
                        print(f"[INFO] Reintentando escaneo de {ip} sin privilegios...")
                        unprivileged_scan = [
                            self.nmap_path,
                            "-sT",               # TCP Connect scan (no requiere privilegios)
                            "-sV",               # Version detection
                            "-n",                # No DNS resolution
                            "-Pn",               # Skip host discovery
                            "-p-",               # All ports
                            "--version-light",   # Lighter version detection
                            "-T4",              # Aggressive timing
                            "--min-rate=1000",   # Minimum packet rate
                            "--max-retries=2",   # Fewer retries for speed
                            "--host-timeout=60s", # Shorter timeout
                            "--script=banner,http-title,ssl-cert", # Scripts básicos
                            "-oX", "-"          # XML output
                        ]

                        detailed_process = subprocess.Popen(
                            unprivileged_scan + [ip],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )

                        current_xml = ""
                        while True:
                            output = detailed_process.stdout.read(1)
                            if output == '' and detailed_process.poll() is not None:
                                break
                            if output:
                                current_xml += output
                                if "</host>" in current_xml:
                                    try:
                                        host_end = current_xml.find("</host>") + 7
                                        host_xml = current_xml[:host_end]
                                        root = ET.fromstring(host_xml)
                                        device = self._parse_host(root)
                                        
                                        if device and not device_found:
                                            devices.append(device)
                                            if on_device_found:
                                                on_device_found(device)
                                    except Exception as e:
                                        print(f"[ERROR] Error procesando {ip} sin privilegios: {str(e)}")
                                    finally:
                                        current_xml = current_xml[host_end:]

                        detailed_process.wait()

                except Exception as e:
                    print(f"[ERROR] Error en escaneo detallado de {ip}: {str(e)}")

            if not devices:
                print("\n[WARNING] No se encontraron dispositivos en la red")
            else:
                print(f"\n[SUCCESS] Escaneo completado. Se encontraron {len(devices)} dispositivos")
                
            return devices
            
        except Exception as e:
            print(f"[ERROR] Error durante el escaneo: {str(e)}")
            return []

    def _parse_host(self, host):
        """Parsea un host desde su XML."""
        try:
            # Obtener dirección IP
            address = host.find(".//address[@addrtype='ipv4']")
            if address is None:
                return None
            
            ip_address = address.get('addr')
            print(f"[INFO] Parseando host {ip_address}")
            
            # Crear dispositivo
            device = Device(ip_address)
            device.last_scan_timestamp = int(time.time())
            device.last_scan_success = True
            
            # Obtener hostname
            hostnames = host.findall(".//hostname")
            if hostnames:
                device.hostname = hostnames[0].get('name')
            
            # Obtener MAC y vendor
            mac = host.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr')
                device.vendor = mac.get('vendor', '')
                print(f"[DEBUG] MAC encontrado: {device.mac_address}, Vendor: {device.vendor}")
            
            # Obtener información del OS
            os_info = {}
            os_matches = host.findall(".//osmatch")
            if os_matches:
                best_match = os_matches[0]
                os_info['name'] = best_match.get('name', '')
                os_info['accuracy'] = best_match.get('accuracy', '')
                
                os_classes = best_match.findall(".//osclass")
                if os_classes:
                    best_class = os_classes[0]
                    device.os_type = best_class.get('type', '')
                    device.os_vendor = best_class.get('vendor', '')
                    device.os_family = best_class.get('osfamily', '')
                    device.os_gen = best_class.get('osgen', '')
            
            device.os_info = os_info
            
            # Parsear puertos y servicios
            ports = host.findall(".//port")
            tcp_ports = []
            udp_ports = []
            
            for port in ports:
                port_info = {}
                port_info['number'] = int(port.get('portid'))
                port_info['protocol'] = port.get('protocol')
                
                state = port.find('state')
                if state is not None:
                    port_info['state'] = state.get('state')
                    if state.get('state') != 'open':
                        continue
                
                service = port.find('service')
                if service is not None:
                    port_info['name'] = service.get('name', '')
                    port_info['product'] = service.get('product', '')
                    port_info['version'] = service.get('version', '')
                    port_info['extrainfo'] = service.get('extrainfo', '')
                    
                    # Obtener scripts NSE
                    scripts = port.findall('script')
                    if scripts:
                        script_output = {}
                        for script in scripts:
                            script_output[script.get('id')] = script.get('output')
                        port_info['scripts'] = script_output
                
                if port_info['protocol'] == 'tcp':
                    tcp_ports.append(port_info)
                else:
                    udp_ports.append(port_info)
            
            device.tcp_ports = tcp_ports
            device.udp_ports = udp_ports
            device.open_ports = json.dumps({
                'tcp': [p['number'] for p in tcp_ports],
                'udp': [p['number'] for p in udp_ports]
            })
            
            # Calcular nivel de riesgo basado en puertos abiertos
            risk_score = 0
            high_risk_ports = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
            medium_risk_ports = {80, 443, 8080, 8443}  # HTTP/HTTPS
            
            for port in tcp_ports:
                port_num = port['number']
                if port_num in high_risk_ports:
                    risk_score += 2
                elif port_num in medium_risk_ports:
                    risk_score += 1
                    
            if risk_score > 4:
                device.risk_level = "Alto"
            elif risk_score > 2:
                device.risk_level = "Medio"
            else:
                device.risk_level = "Bajo"
            
            return device
            
        except Exception as e:
            print(f"[ERROR] Error parseando host: {str(e)}")
            return None

    def _parse_single_host(self, host_xml):
        """Parsea un único host desde su XML."""
        try:
            root = ET.fromstring(host_xml)
            
            # Verificar si el host está activo
            status = root.find(".//status")
            if status is None or status.get('state') != 'up':
                return None
                
            # Obtener dirección IP
            ip = root.find(".//address[@addrtype='ipv4']")
            if ip is None:
                return None
                
            ip_address = ip.get('addr')
            if not ip_address:
                return None
                
            # Obtener hostname si existe
            hostname_elem = root.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else ip_address
            
            # Crear dispositivo
            device = Device(ip_address=ip_address, hostname=hostname)
            
            # MAC Address y Vendor
            mac = root.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr')
                device.vendor = mac.get('vendor')
                
            # OS Detection
            os_info = root.find(".//osmatch")
            if os_info is not None:
                device.os_info = self.data_normalizer.normalize_os_info(os_info)
                
            # Ports and Services
            for port in root.findall(".//port[@state='open']"):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                
                service = port.find('service')
                if service is not None:
                    service_info = {
                        'port': port_id,
                        'protocol': protocol,
                        'name': service.get('name', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extra_info': service.get('extrainfo', '')
                    }
                    device.services[port_id] = service_info
                    
            # Determinar tipo de dispositivo basado en puertos y OS
            device.determine_device_type()
            
            return device

        except ET.ParseError as e:
            print(f"[ERROR] Error parseando XML del host: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Error procesando host: {e}")
            return None

    def _create_device_from_host(self, host):
        """Crea un objeto Device a partir de un elemento host XML."""
        # Obtener dirección IP
        ip = host.find(".//address[@addrtype='ipv4']")
        if ip is None:
            return None
            
        ip_address = ip.get('addr')
        
        # Obtener hostname si existe
        hostname_elem = host.find(".//hostname")
        hostname = hostname_elem.get('name') if hostname_elem is not None else ip_address
        
        # Crear dispositivo
        device = Device(ip_address=ip_address, hostname=hostname)
        
        # MAC Address y Vendor
        mac = host.find(".//address[@addrtype='mac']")
        if mac is not None:
            device.mac_address = mac.get('addr')
            device.vendor = mac.get('vendor')
            
        # OS Detection
        os_info = host.find(".//osmatch")
        if os_info is not None:
            device.os_info = self.data_normalizer.normalize_os_info(os_info)
            
        # Ports and Services
        for port in host.findall(".//port[@state='open']"):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            
            service = port.find('service')
            if service is not None:
                service_info = {
                    'port': port_id,
                    'protocol': protocol,
                    'name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extra_info': service.get('extrainfo', '')
                }
                device.services[port_id] = service_info
                
        # Determinar tipo de dispositivo basado en puertos y OS
        device.determine_device_type()
        
        return device

# Example usage (outside the class definition):
# if __name__ == "__main__":
#     # To use the default path finding:
#     # scanner = NmapScanner()
#
#     # To specify the path explicitly:
#     nmap_path_windows = "C:\\Program Files\\Nmap\\nmap.exe"
#     scanner = NmapScanner(nmap_path_windows)
#
#     if scanner.nmap_path:
#         # Replace with a target IP or range in your network
#         target_ip = "192.168.1.1"
#         scanned_devices = scanner.scan(target_ip)
#
#         if scanned_devices:
#             print(f"Scan complete. Found {len(scanned_devices)} devices.")
#             for dev in scanned_devices:
#                 print(f"Device: {dev.ip_address}")
#                 if dev.hostname: print(f"  Hostname: {dev.hostname}")
#                 if dev.mac_address: print(f"  MAC: {dev.mac_address}")
#                 if dev.vendor: print(f"  Vendor: {dev.vendor}")
#                 if dev.os_info: print(f"  OS Info: {dev.os_info}")
#                 if dev.services:
#                     print("  Open Ports and Services:")
#                     for port, service in dev.services.items():
#                         print(f"    Port {port}/{service['protocol']} - {service['name']} {service['product']} {service['version']}")
#         else:
#             print("No devices found or scan failed.")
#     else:
#         print("Nmap Scanner could not be initialized.")
