import subprocess
import xml.etree.ElementTree as ET
import platform
import os
import time

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

    def scan(self, target, on_device_found=None):
        """Realiza un escaneo de red mostrando progreso en tiempo real."""
        if not self.nmap_path:
            print("[ERROR] Ruta de Nmap no configurada o Nmap no disponible.")
            return []

        # Configurar comando Nmap para descubrimiento rápido de hosts
        discovery_command = [
            self.nmap_path,
            "-sn",                 # No port scan, host discovery only
            "-n",                  # No DNS resolution
            "-PS22,80,443",       # TCP SYN discovery on common ports
            "-PA80,443",          # TCP ACK discovery on common ports
            "-PE",                # ICMP echo request
            "--max-retries=1",     # Solo un reintento para descubrimiento
            "-T4",                # Aggressive timing
            "--min-rate=300",     # Tasa más alta para escaneo rápido
            "--host-timeout=3s",   # Timeout corto para hosts que no responden
            "-oX", "-"            # XML output
        ]

        try:
            print(f"\n[INFO] Iniciando escaneo en {target}")
            print("-" * 50)
            
            # Fase 1: Descubrimiento rápido de hosts
            print("[INFO] Fase 1: Descubrimiento de hosts...")
            process = subprocess.Popen(
                discovery_command + [target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            xml_output = []
            devices = []
            current_xml = ""
            
            # Leer la salida línea por línea
            for line in process.stdout:
                xml_output.append(line)
                current_xml += line
                
                if "</host>" in line and "<host>" in current_xml:
                    try:
                        host_xml = current_xml[current_xml.find("<host>"):current_xml.find("</host>") + 7]
                        device = self._parse_single_host(host_xml)
                        if device:
                            print(f"\n[INFO] Host encontrado: {device.ip_address}")
                            
                            # Configurar escaneo detallado para este host
                            port_scan_command = [
                                self.nmap_path,
                                "-sS",         # SYN Scan
                                "-sV",         # Version detection
                                "-O",          # OS Detection
                                "-p-",         # Scan all ports
                                "-T4",         # Aggressive timing
                                "-Pn",         # Skip host discovery
                                "--version-intensity=5",  # Intensidad media de detección de versiones
                                "-oX", "-",     # XML output
                                device.ip_address
                            ]
                            
                            print(f"[INFO] Iniciando escaneo detallado de {device.ip_address}")
                            
                            try:
                                # Ejecutar escaneo de puertos sin timeout
                                port_scan = subprocess.run(
                                    port_scan_command,
                                    capture_output=True,
                                    text=True
                                )
                                
                                if port_scan.returncode == 0:
                                    updated_device = self._parse_single_host(port_scan.stdout)
                                    if updated_device:
                                        updated_device.ip_address = device.ip_address
                                        updated_device.last_scan_success = True
                                        updated_device.last_scan_timestamp = int(time.time())
                                        # Asignar valores por defecto para risk_score
                                        updated_device.risk_score = 0.0
                                        updated_device.risk_level = "Bajo"
                                        devices.append(updated_device)
                                        if on_device_found:
                                            on_device_found(updated_device)
                                        print(f"[SUCCESS] Escaneo completado para {device.ip_address}")
                                    else:
                                        print(f"[WARNING] No se pudo procesar la información de {device.ip_address}")
                                        device.risk_score = 0.0
                                        device.risk_level = "Desconocido"
                                        devices.append(device)
                                        if on_device_found:
                                            on_device_found(device)
                                else:
                                    print(f"[ERROR] Falló el escaneo detallado de {device.ip_address}")
                                    device.last_scan_error = "Error en escaneo de puertos"
                                    device.risk_score = 0.0
                                    device.risk_level = "Desconocido"
                                    devices.append(device)
                                    if on_device_found:
                                        on_device_found(device)
                                        
                            except Exception as e:
                                print(f"[ERROR] Error escaneando {device.ip_address}: {str(e)}")
                                device.last_scan_error = str(e)
                                device.risk_score = 0.0
                                device.risk_level = "Error"
                                devices.append(device)
                                if on_device_found:
                                    on_device_found(device)
                                    
                    except Exception as e:
                        print(f"[ERROR] Error procesando host XML: {str(e)}")
                    finally:
                        current_xml = current_xml[current_xml.find("</host>") + 7:]
            
            # Esperar a que termine el proceso inicial
            process.wait()
            
            if not devices:
                print("\n[WARNING] No se encontraron dispositivos en la red")
            else:
                print(f"\n[INFO] Escaneo completado. Se encontraron {len(devices)} dispositivos")
                
            return devices
            
        except Exception as e:
            print(f"[ERROR] Error durante el escaneo: {str(e)}")
            return []

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
            os_match = root.find(".//osmatch")
            if os_match is not None:
                os_info = {
                    'name': os_match.get('name', ''),
                    'accuracy': os_match.get('accuracy', ''),
                    'osclass': []
                }
                
                for osclass in os_match.findall('.//osclass'):
                    os_class_info = {
                        'type': osclass.get('type', ''),
                        'vendor': osclass.get('vendor', ''),
                        'osfamily': osclass.get('osfamily', ''),
                        'osgen': osclass.get('osgen', '')
                    }
                    os_info['osclass'].append(os_class_info)
                    
                device.os_info = self.data_normalizer.normalize_os_info(os_info)
                
            # Ports and Services
            for port in root.findall(".//port"):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
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
                        
                        # Actualizar flags de servicios específicos
                        service_name = service.get('name', '').lower()
                        if service_name in ['microsoft-ds', 'netbios-ssn'] or port_id in ['445', '139']:
                            device.has_wmi_port = True
                        elif service_name == 'ssh' and port_id == '22':
                            device.has_ssh_port = True
                        elif service_name == 'snmp' or port_id == '161':
                            device.has_snmp_port = True
                
            # Determinar tipo de dispositivo
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
