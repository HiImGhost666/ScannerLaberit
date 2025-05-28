import subprocess
import xml.etree.ElementTree as ET
import platform
import os
import time
import json
import re
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

        # Fase 1: Descubrimiento rápido de hosts con ARP
        arp_scan_command = [
            self.nmap_path,
            "-sn",               # No port scan
            "-PR",              # ARP scan
            "-T4",              # Aggressive timing
            "--min-parallelism=10",
            "--max-retries=3",
            "-oX", "-"          # XML output
        ]

        try:
            print("=" * 50)
            print("[INFO] Fase 1: Descubrimiento ARP de hosts...")
            
            process = subprocess.Popen(
                arp_scan_command + [target],
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

            # Fase 2: Escaneo detallado en paralelo
            max_parallel = 5  # Número máximo de escaneos paralelos
            active_processes = {}
            completed_ips = set()

            # Configuración base para el escaneo detallado
            detailed_scan_base = [
                self.nmap_path,
                "-sS",                # TCP SYN scan
                "-sV",               # Version detection
                "-O",                # OS Detection
                "-A",                # Enable OS detection, version detection, script scanning
                "-n",                # No DNS resolution
                "-Pn",               # Treat all hosts as online
                "-p-",               # All ports
                "--version-all",     # Try every version detection probe
                "--osscan-guess",    # Guess OS more aggressively
                "--max-os-tries=5",  # More OS detection attempts
                "-T4",               # Aggressive timing
                "--min-rate=300",    # Minimum packet rate
                "--max-retries=3",   # More retries
                "--host-timeout=300s", # 5 minutes timeout per host
                # Scripts específicos para obtener más información
                "--script=default,banner,http-title,ssl-cert,ssh-auth-methods,smb-os-discovery,smb-system-info,dns-service-discovery,nbstat,snmp-info,http-headers",
                "-oX", "-"           # XML output
            ]

            print("\n[INFO] Fase 2: Iniciando escaneos detallados en paralelo...")

            while len(completed_ips) < len(active_ips):
                # Iniciar nuevos escaneos si hay espacio
                for ip in active_ips:
                    if ip not in completed_ips and ip not in active_processes and len(active_processes) < max_parallel:
                        print(f"\n[INFO] Iniciando escaneo detallado de {ip}...")
                        process = subprocess.Popen(
                            detailed_scan_base + [ip],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        active_processes[ip] = {
                            'process': process,
                            'xml': "",
                            'start_time': time.time()
                        }

                # Verificar procesos activos
                for ip in list(active_processes.keys()):
                    process_info = active_processes[ip]
                    process = process_info['process']
                    
                    # Leer salida disponible
                    while True:
                        output = process.stdout.read1(1024).decode('utf-8', errors='ignore')
                        if not output:
                            break
                        process_info['xml'] += output

                    # Procesar XML completo si el host está terminado
                    if process.poll() is not None:
                        try:
                            if "</host>" in process_info['xml']:
                                xml_data = process_info['xml']
                                root = ET.fromstring(xml_data[xml_data.find("<host>"):xml_data.find("</host>")+7])
                                device = self._parse_host(root)
                                
                                if device:
                                    devices.append(device)
                                    if on_device_found:
                                        on_device_found(device)
                                    print(f"[SUCCESS] Escaneo de {ip} completado")
                                else:
                                    print(f"[WARNING] No se pudo obtener información de {ip}")
                        except Exception as e:
                            print(f"[ERROR] Error procesando {ip}: {str(e)}")
                        
                        completed_ips.add(ip)
                        del active_processes[ip]
                    
                    # Verificar timeout
                    elif time.time() - process_info['start_time'] > 300:  # 5 minutos timeout
                        print(f"[WARNING] Timeout en escaneo de {ip}")
                        process.terminate()
                        completed_ips.add(ip)
                        del active_processes[ip]

                time.sleep(0.1)  # Pequeña pausa para no saturar CPU

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
            
            # Obtener hostname (intentar varios métodos)
            hostnames = host.findall(".//hostname")
            if hostnames:
                # Priorizar nombres DNS sobre nombres NetBIOS
                dns_names = [h.get('name') for h in hostnames if h.get('type') == 'PTR']
                if dns_names:
                    device.hostname = dns_names[0]
                else:
                    device.hostname = hostnames[0].get('name')
                print(f"[DEBUG] Hostname: {device.hostname}")
            
            # Obtener MAC y vendor
            mac = host.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr').upper()
                device.vendor = mac.get('vendor', '')
                print(f"[DEBUG] MAC: {device.mac_address}, Vendor: {device.vendor}")
            else:
                # Intentar obtener MAC de scripts NBT o SMB
                for script in host.findall(".//script"):
                    if script.get('id') in ['nbstat', 'smb-os-discovery']:
                        output = script.get('output', '')
                        mac_match = re.search(r'MAC: ([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', output)
                        if mac_match:
                            device.mac_address = mac_match.group(1)
                            print(f"[DEBUG] MAC encontrada en script: {device.mac_address}")
            
            # Obtener información del OS
            os_info = {}
            
            # Método 1: OS Match
            os_matches = host.findall(".//osmatch")
            if os_matches:
                best_match = max(os_matches, key=lambda x: float(x.get('accuracy', 0)))
                os_info['name'] = best_match.get('name', '')
                os_info['accuracy'] = best_match.get('accuracy', '')
                
                os_classes = best_match.findall(".//osclass")
                if os_classes:
                    best_class = os_classes[0]
                    device.os_type = best_class.get('type', '')
                    device.os_vendor = best_class.get('vendor', '')
                    device.os_family = best_class.get('osfamily', '')
                    device.os_gen = best_class.get('osgen', '')
            
            # Método 2: Scripts SMB
            if not os_info.get('name'):
                for script in host.findall(".//script"):
                    if script.get('id') == 'smb-os-discovery':
                        output = script.get('output', '')
                        os_info['name'] = re.search(r'OS: (.*?)(?:\n|$)', output)
                        if os_info['name']:
                            os_info['name'] = os_info['name'].group(1)
                            os_info['source'] = 'SMB'
            
            # Método 3: Service Detection
            if not os_info.get('name'):
                for port in host.findall(".//port"):
                    service = port.find('.//service')
                    if service is not None:
                        os_info['name'] = service.get('ostype', '')
                        if os_info['name']:
                            os_info['source'] = 'Service'
                            break
            
            device.os_info = os_info
            if os_info.get('name'):
                print(f"[DEBUG] OS detectado: {os_info['name']} ({os_info.get('accuracy', 'N/A')}%)")
            
            # Parsear puertos y servicios
            tcp_ports = []
            udp_ports = []
            
            for port in host.findall(".//port"):
                port_info = {
                    'number': int(port.get('portid')),
                    'protocol': port.get('protocol'),
                    'state': 'closed'
                }
                
                # Estado del puerto
                state = port.find('state')
                if state is not None:
                    port_info['state'] = state.get('state')
                    if port_info['state'] != 'open':
                        continue
                
                # Información del servicio
                service = port.find('service')
                if service is not None:
                    port_info['name'] = service.get('name', '')
                    port_info['product'] = service.get('product', '')
                    port_info['version'] = service.get('version', '')
                    port_info['extrainfo'] = service.get('extrainfo', '')
                    
                    # Información adicional de scripts
                    scripts = {}
                    for script in port.findall('script'):
                        script_id = script.get('id')
                        if script_id in ['banner', 'http-title', 'ssl-cert']:
                            scripts[script_id] = script.get('output', '').strip()
                    if scripts:
                        port_info['scripts'] = scripts
                
                if port_info['protocol'] == 'tcp':
                    tcp_ports.append(port_info)
                else:
                    udp_ports.append(port_info)
            
            device.tcp_ports = tcp_ports
            device.udp_ports = udp_ports
            
            # Guardar puertos abiertos en formato JSON
            device.open_ports = json.dumps({
                'tcp': [{'number': p['number'], 
                        'service': p.get('name', ''),
                        'product': p.get('product', ''),
                        'version': p.get('version', '')} for p in tcp_ports],
                'udp': [{'number': p['number'], 
                        'service': p.get('name', ''),
                        'product': p.get('product', ''),
                        'version': p.get('version', '')} for p in udp_ports]
            })
            
            # Calcular nivel de riesgo basado en puertos y servicios
            risk_score = 0
            high_risk_ports = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
            medium_risk_ports = {80, 443, 8080, 8443}  # HTTP/HTTPS
            
            for port in tcp_ports:
                port_num = port['number']
                if port_num in high_risk_ports:
                    risk_score += 2
                elif port_num in medium_risk_ports:
                    risk_score += 1
                
                # Verificar servicios vulnerables
                service = port.get('name', '').lower()
                if any(s in service for s in ['telnet', 'ftp', 'rpc']):
                    risk_score += 2
            
            if risk_score > 4:
                device.risk_level = "Alto"
            elif risk_score > 2:
                device.risk_level = "Medio"
            else:
                device.risk_level = "Bajo"
            
            print(f"[DEBUG] Puertos TCP abiertos: {[p['number'] for p in tcp_ports]}")
            print(f"[DEBUG] Puertos UDP abiertos: {[p['number'] for p in udp_ports]}")
            print(f"[DEBUG] Nivel de riesgo: {device.risk_level}")
            
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
        for port in host.findall(".//port"):
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
