from typing import Dict, Optional, Any
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from miproyectored.util.mac_manufacturer_manager import MacManufacturerManager
from miproyectored.auth.network_credentials import NetworkCredentials
from miproyectored.scanner.wmi_client import WmiClient
from miproyectored.scanner.ssh_client import SshClient
from miproyectored.scanner.snmp_client import SNMPClient  # Nueva importación

class Device:
    def __init__(self, ip_address: str, hostname: Optional[str] = None):
        self.id: Optional[int] = None  # Para la base de datos
        self.ip_address: str = ip_address
        self.hostname: str = hostname if hostname else ip_address
        
        self.type: str = "unknown"  # Ej: "windows", "linux", "network_device", "unknown"
        self.mac_address: Optional[str] = None # MAC address principal
        self.vendor: Optional[str] = None # Fabricante basado en MAC
        
        # Risk assessment attributes
        self.risk_score: Optional[float] = None
        self.risk_level: str = "Desconocido"  # Bajo, Medio, Alto, Crítico, Desconocido

        # Estado del escaneo
        self.last_scan_success: bool = False
        self.last_scan_error: Optional[str] = None
        self.last_scan_timestamp: Optional[int] = None
        
        # Diccionarios para almacenar información detallada del escaneo
        self.os_info: Dict[str, Any] = {}
        self.hardware_info: Dict[str, Any] = {}
        self.network_info: Dict[str, Any] = {} # Podría incluir múltiples interfaces
        self.services: Dict[int, str] = {} # Puertos abiertos y servicios
        self.open_ports: list[int] = []

        # Información específica de protocolos de escaneo profundo
        self.wmi_specific_info: Dict[str, Any] = {} # Datos crudos o adicionales de WMI
        self.ssh_specific_info: Dict[str, Any] = {} # Datos crudos o adicionales de SSH
        self.snmp_info: Dict[str, Any] = {} # Para dispositivos de red o SNMP general
        
        self.last_scan: Optional[str] = None # Timestamp del último escaneo exitoso (ISO 8601)
        self.status: str = "pending_scan"  # pending_scan, scanned, error_scan, scanned_with_errors
        self.scan_error: Optional[str] = None # Mensaje de error del último intento de escaneo
        
        # Nuevos campos para determinar compatibilidad con protocolos
        self.has_wmi_port: bool = False
        self.has_ssh_port: bool = False
        self.has_snmp_port: bool = False
        self.has_wmi_potential: bool = False

        # Inicializar MacManufacturerManager
        self.mac_manufacturer_manager = MacManufacturerManager()

    def _update_scan_metadata(self, success: bool, error_message: Optional[str] = None):
        """Actualiza los metadatos comunes del escaneo."""
        self.last_scan = datetime.now(timezone.utc).isoformat()
        if success:
            if self.scan_error and error_message: # Si ya había un error y se añade otro
                 self.scan_error += f"; {error_message}"
                 self.status = "scanned_with_errors"
            elif error_message: # Nuevo error parcial
                self.scan_error = error_message
                self.status = "scanned_with_errors"
            elif not self.scan_error: # Éxito completo sin errores previos o actuales
                self.status = "scanned"
            # Si self.scan_error ya existía pero no hay nuevo error_message, se mantiene scanned_with_errors
        else:
            self.status = "error_scan"
            self.scan_error = error_message if error_message else "Error desconocido durante el escaneo."

    def update_from_wmi(self, wmi_data: Dict[str, str]) -> None:
        """Actualiza el dispositivo con datos de WMI."""
        self.os_info.clear()
        self.hardware_info.clear()
        self.network_info.clear() # Limpiar información de red general
        self.wmi_specific_info = dict(wmi_data) # Guardar todos los datos crudos de WMI
        
        current_scan_error = None

        if "error" in wmi_data:
            current_scan_error = wmi_data["error"]
            # No retornar inmediatamente, intentar procesar datos parciales si los hay

        # Procesar y categorizar datos de wmi_data
        # Nota: WmiClient devuelve un Dict[str, str] plano.
        # La categorización se basa en las claves que WmiClient.collect_system_info() genera.

        # OS Info
        if wmi_data.get("os_caption"): self.os_info["caption"] = wmi_data["os_caption"]
        if wmi_data.get("os_version"): self.os_info["version"] = wmi_data["os_version"]
        if wmi_data.get("os_architecture"): self.os_info["architecture"] = wmi_data["os_architecture"]
        if wmi_data.get("system_directory"): self.os_info["system_directory"] = wmi_data["system_directory"]
        
        # Hardware Info - CPU
        if wmi_data.get("cpu_name"): self.hardware_info["cpu_name"] = wmi_data["cpu_name"]
        if wmi_data.get("cpu_manufacturer"): self.hardware_info["cpu_manufacturer"] = wmi_data["cpu_manufacturer"]
        if wmi_data.get("cpu_max_clock_speed_mhz"): self.hardware_info["cpu_max_clock_speed_mhz"] = wmi_data["cpu_max_clock_speed_mhz"]
        if wmi_data.get("cpu_cores"): self.hardware_info["cpu_cores"] = wmi_data["cpu_cores"]
        if wmi_data.get("cpu_logical_processors"): self.hardware_info["cpu_logical_processors"] = wmi_data["cpu_logical_processors"]
        
        # Hardware Info - Memory
        if wmi_data.get("total_visible_memory_kb"): self.hardware_info["total_memory_kb"] = wmi_data["total_visible_memory_kb"]
        if wmi_data.get("free_physical_memory_kb"): self.hardware_info["free_memory_kb"] = wmi_data["free_physical_memory_kb"]

        # Hardware Info - Disks (agrupados)
        disks = []
        i = 0
        while True:
            disk_id_key = f"disk_{i}_device_id"
            if disk_id_key in wmi_data:
                disk_info = {
                    "device_id": wmi_data.get(disk_id_key),
                    "total_gb": wmi_data.get(f"disk_{i}_total_gb"),
                    "free_gb": wmi_data.get(f"disk_{i}_free_gb"),
                    "filesystem": wmi_data.get(f"disk_{i}_filesystem"),
                    "volume_name": wmi_data.get(f"disk_{i}_volume_name", "N/A")
                }
                disks.append(disk_info)
                i += 1
            else:
                break
        if disks: self.hardware_info["disks"] = disks
        
        # Network Info (para adaptadores con IP)
        # WmiClient actualmente devuelve info del primer adaptador con IP como network_adapter_0_*
        # Aquí lo almacenamos de forma más genérica en self.network_info
        # Si WmiClient cambia para devolver una lista de adaptadores, esta lógica necesitaría ajuste.
        main_interface = {}
        if wmi_data.get("network_adapter_0_description"): main_interface["description"] = wmi_data.get("network_adapter_0_description")
        
        ip_addresses = []
        idx = 0
        while f"network_adapter_0_ip_address_{idx}" in wmi_data:
            ip_addresses.append(wmi_data[f"network_adapter_0_ip_address_{idx}"])
            idx += 1
        if ip_addresses: main_interface["ip_addresses"] = ip_addresses
        
        if wmi_data.get("network_adapter_0_mac_address"):
            main_interface["mac_address"] = wmi_data["network_adapter_0_mac_address"]
            if not self.mac_address: self.mac_address = main_interface["mac_address"] # Tomar la primera MAC como principal

        gateways = []
        idx = 0
        while f"network_adapter_0_default_gateway_{idx}" in wmi_data:
            gateways.append(wmi_data[f"network_adapter_0_default_gateway_{idx}"])
            idx += 1
        if gateways: main_interface["default_gateways"] = gateways

        dns_servers = []
        idx = 0
        while f"network_adapter_0_dns_server_{idx}" in wmi_data:
            dns_servers.append(wmi_data[f"network_adapter_0_dns_server_{idx}"])
            idx += 1
        if dns_servers: main_interface["dns_servers"] = dns_servers
        
        if main_interface:
            self.network_info["interfaces"] = [main_interface] # Asumimos una interfaz principal por ahora

        # Determinar tipo y estado
        self.type = "windows"
        if not self.os_info and not self.hardware_info and not self.network_info and not current_scan_error:
            current_scan_error = (current_scan_error + "; " if current_scan_error else "") + \
                                 "Datos WMI recibidos, pero no se pudo categorizar información relevante."
        
        self._update_scan_metadata(success=not bool(current_scan_error), error_message=current_scan_error)


    def update_from_ssh(self, ssh_data: Dict[str, Any]) -> None:
        """Actualiza el dispositivo con datos de SSH.
        ssh_data puede tener valores directos y algunas claves con cadenas JSON (si SshClient las provee).
        """
        self.os_info.clear()
        self.hardware_info.clear()
        self.network_info.clear() # Limpiar información de red general
        self.ssh_specific_info = dict(ssh_data) # Guardar todos los datos crudos de SSH

        current_scan_error = None

        if "error" in ssh_data and isinstance(ssh_data["error"], str):
            current_scan_error = ssh_data["error"]

        # Actualizar hostname si SSH lo provee y es diferente
        if "hostname" in ssh_data and isinstance(ssh_data["hostname"], str) and ssh_data["hostname"]:
            self.hostname = ssh_data["hostname"]

        # OS Info (directamente de SshClient)
        if ssh_data.get("os_kernel"): self.os_info["kernel"] = ssh_data["os_kernel"]
        if ssh_data.get("distro_info"): self.os_info["distribution"] = ssh_data["distro_info"]
        if ssh_data.get("uptime"): self.os_info["uptime"] = ssh_data["uptime"]
        
        # Hardware Info (directamente de SshClient o parseado)
        if ssh_data.get("cpu_info"): # SshClient actualmente no provee 'cpu_info' de forma estructurada
            self.hardware_info["cpu_info_string"] = ssh_data["cpu_info"] # Almacenar como string si se provee
        
        if ssh_data.get("memory_usage"): # Ej: "1.2G/7.8G"
            self.hardware_info["memory_usage_string"] = ssh_data["memory_usage"]
            # Aquí se podría añadir lógica para parsear "memory_usage_string" a total/free si es necesario
            # Por ejemplo:
            # parts = ssh_data["memory_usage"].split('/')
            # if len(parts) == 2:
            #     self.hardware_info["memory_used_human"] = parts[0]
            #     self.hardware_info["memory_total_human"] = parts[1]

        if ssh_data.get("disk_usage"): # Ej: salida de 'df -h /'
            self.hardware_info["disk_usage_root_string"] = ssh_data["disk_usage"]
            # Similar a memory, se podría parsear si es necesario

        # Procesamiento de datos JSON (si SshClient los proveyera en el futuro)
        # Actualmente SshClient no devuelve estas claves JSON.
        # Esta sección es especulativa o para futuras mejoras de SshClient.
        json_keys_map = {
            "disk_info_json": self.hardware_info, 
            "network_interfaces_json": self.network_info 
        }
        for json_key, target_dict in json_keys_map.items():
            if json_key in ssh_data and isinstance(ssh_data[json_key], str):
                try:
                    parsed_data = json.loads(ssh_data[json_key])
                    # Si es una lista (ej. múltiples discos/interfaces) o un dict (info general)
                    # Esto es un ejemplo, la estructura real de 'parsed_data' dependería de SshClient
                    if isinstance(parsed_data, (list, dict)):
                         # Para datos de disco, podrían ser una lista de montajes
                         # Para datos de red, una lista de interfaces
                        target_dict[json_key.replace("_json", "")] = parsed_data
                    else: # Dato parseado no es lista ni diccionario
                        target_dict[json_key.replace("_json", "")] = str(parsed_data)

                except json.JSONDecodeError as e:
                    err_msg = f"Error al decodificar JSON para '{json_key}': {e}"
                    current_scan_error = (current_scan_error + "; " if current_scan_error else "") + err_msg
                    target_dict[json_key.replace("_json", "_error")] = err_msg
        
        # Tipo de dispositivo (generalmente linux o similar para SSH)
        self.type = "linux" # O "unix-like", podría refinarse con distro_info
        if "macos" in self.os_info.get("kernel", "").lower() or \
           "darwin" in self.os_info.get("kernel", "").lower():
            self.type = "macos"

        if not self.os_info and not self.hardware_info and not self.network_info and not current_scan_error:
             current_scan_error = (current_scan_error + "; " if current_scan_error else "") + \
                                 "Datos SSH recibidos, pero no se pudo categorizar información relevante."

        self._update_scan_metadata(success=not bool(current_scan_error), error_message=current_scan_error)

    def determine_device_type(self):
        """Determina el tipo de dispositivo basado en puertos abiertos y OS."""
        if not self.type or self.type == "unknown":
            # Primero intentar determinar por OS
            if self.os_info:
                os_name = str(self.os_info.get('name', '')).lower()
                if 'windows' in os_name:
                    self.type = 'Windows'
                elif any(x in os_name for x in ['linux', 'ubuntu', 'debian', 'centos', 'redhat']):
                    self.type = 'Linux'
                elif 'cisco' in os_name:
                    self.type = 'Network Device'
                elif 'fortigate' in os_name or 'fortios' in os_name:
                    self.type = 'Firewall'
            
            # Luego por puertos y servicios característicos
            if not self.type or self.type == "unknown":
                services = set()
                for port_info in self.services.values():
                    service_name = port_info.get('name', '').lower()
                    services.add(service_name)
                    
                    # Detectar switches/routers
                    if service_name in ['snmp', 'telnet'] or port_info.get('port') in ['161', '23']:
                        self.type = 'Network Device'
                        break
                    # Detectar firewalls
                    elif service_name in ['https'] and port_info.get('port') in ['443', '8443']:
                        product = port_info.get('product', '').lower()
                        if 'fortinet' in product or 'fortigate' in product:
                            self.type = 'Firewall'
                            break
                    # Detectar Windows
                    elif service_name in ['microsoft-ds', 'netbios-ssn'] or port_info.get('port') in ['445', '139']:
                        self.type = 'Windows'
                        break
                    # Detectar Linux
                    elif service_name in ['ssh'] and port_info.get('port') == '22':
                        self.type = 'Linux'
                        break
                        
            # Si aún no se ha determinado, usar heurísticas adicionales
            if not self.type or self.type == "unknown":
                if self.vendor:
                    vendor_lower = self.vendor.lower()
                    if any(x in vendor_lower for x in ['cisco', 'juniper', 'hp', 'aruba']):
                        self.type = 'Network Device'
                    elif 'fortinet' in vendor_lower:
                        self.type = 'Firewall'
                
        # Marcar si el dispositivo podría necesitar WMI
        self.has_wmi_potential = self.type == 'Windows'

    def perform_detailed_scan(self, credentials: NetworkCredentials) -> bool:
        """Realiza un escaneo detallado del dispositivo basado en su tipo detectado.
        Retorna True si al menos un escaneo tuvo éxito."""
        success = False
        
        # Determinar el tipo de dispositivo y realizar el escaneo apropiado
        os_lower = self.get_os().lower() if self.get_os() else ""
        
        # Verificar si es un dispositivo Windows
        if "windows" in os_lower or self.has_wmi_port:
            if credentials and credentials.username and credentials.password:
                wmi_client = WmiClient(
                    host=self.ip_address,
                    username=credentials.username,
                    password=credentials.password,
                    domain=credentials.domain
                )
                if wmi_client.connection:
                    wmi_data = wmi_client.collect_system_info()
                    self.update_from_wmi(wmi_data)
                    success = True
        
        # Verificar si es un dispositivo Linux/Unix
        if "linux" in os_lower or "unix" in os_lower or self.has_ssh_port:
            if credentials and (credentials.username and (credentials.password or credentials.ssh_key_path)):
                ssh_client = SshClient(
                    host=self.ip_address,
                    username=credentials.username,
                    password=credentials.password,
                    key_filename=credentials.ssh_key_path
                )
                if ssh_client.client:
                    ssh_data = ssh_client.collect_system_info()
                    self.update_from_ssh(ssh_data)
                    success = True
        
        # Verificar si el dispositivo soporta SNMP
        if self.has_snmp_port:
            if credentials and credentials.snmp_community:
                snmp_client = SNMPClient(
                    host=self.ip_address,
                    community=credentials.snmp_community
                )
                snmp_data = snmp_client.collect_system_info()
                self.update_from_snmp(snmp_data)
                success = True
        
        return success

    def update_from_snmp(self, snmp_data: Dict[str, Any]) -> None:
        """Actualiza el dispositivo con datos de SNMP."""
        # Esta es una estructura básica, snmp_data puede ser complejo.
        self.snmp_info.clear()
        self.snmp_info.update(snmp_data)
        
        current_scan_error = None
        if "error" in snmp_data:
            current_scan_error = snmp_data["error"]
        
        # Extraer información común de SNMP
        if "sysDescr" in snmp_data: self.os_info["description_snmp"] = snmp_data["sysDescr"]
        if "sysName" in snmp_data and not self.hostname: self.hostname = snmp_data["sysName"]
        if "sysUpTime" in snmp_data: self.os_info["uptime_snmp"] = snmp_data["sysUpTime"]
        if "sysLocation" in snmp_data: self.os_info["location"] = snmp_data["sysLocation"]
        
        # Información de hardware
        if "memTotalReal" in snmp_data: self.hardware_info["total_memory_kb"] = snmp_data["memTotalReal"]
        if "cpuLoad" in snmp_data: self.hardware_info["cpu_load"] = snmp_data["cpuLoad"]
        
        # Procesos en ejecución
        if "runningProcesses" in snmp_data: 
            self.snmp_info["processes"] = snmp_data["runningProcesses"]
        
        if not self.type or self.type == "unknown":
            self.type = "network_device" # Asumir dispositivo de red si se escanea por SNMP y no hay otro tipo

        self._update_scan_metadata(success=not bool(current_scan_error), error_message=current_scan_error)


    def update_from_nmap(self, nmap_data: Dict[str, Any]) -> None:
        """Actualiza el dispositivo con datos de Nmap parseados."""
        # Limpiar información que Nmap puede proporcionar para evitar duplicados/conflictos
        # Nmap es a menudo la fuente principal de puertos/servicios y OS inicial
        self.services.clear()
        self.open_ports.clear()
        # No limpiar os_info, hardware_info, network_info completamente
        # Nmap puede añadir información, pero no reemplaza escaneos profundos

        current_scan_error = None
        if "error" in nmap_data:
            current_scan_error = nmap_data["error"]

        # Actualizar campos directos si están presentes en los datos parseados
        if "hostname" in nmap_data and nmap_data["hostname"]:
            self.hostname = nmap_data["hostname"]

        if "mac_address" in nmap_data and nmap_data["mac_address"]:
            self.set_mac(nmap_data["mac_address"])
            if "manufacturer" in nmap_data and nmap_data["manufacturer"]:
                 self.set_manufacturer(nmap_data["manufacturer"])
            # set_mac ya intenta resolver el fabricante si no se proporciona

        if "open_ports" in nmap_data and isinstance(nmap_data["open_ports"], list):
            self.open_ports = nmap_data["open_ports"]

        if "services" in nmap_data and isinstance(nmap_data["services"], dict):
            self.services = nmap_data["services"]

        # Actualizar información del OS (Nmap es una fuente primaria)
        if "os_info" in nmap_data and isinstance(nmap_data["os_info"], dict):
            # Nmap puede dar múltiples coincidencias de OS, tomamos la mejor o la principal
            # Aquí asumimos que nmap_data["os_info"] ya contiene la información relevante parseada
            self.os_info.update(nmap_data["os_info"])
            # Intentar establecer el tipo de dispositivo basado en el OS de Nmap
            os_name_lower = self.os_info.get("name", "").lower()
            if "windows" in os_name_lower:
                self.type = "windows"
            elif "linux" in os_name_lower:
                self.type = "linux"
            elif "macos" in os_name_lower or "darwin" in os_name_lower:
                self.type = "macos"
            elif "network device" in os_name_lower or "router" in os_name_lower or "switch" in os_name_lower:
                 self.type = "network_device"
            # Si el tipo sigue siendo desconocido, podría ser otro tipo o necesitar escaneo profundo
            if self.type == "unknown" and os_name_lower:
                 self.type = "other"

        # Nmap specific info (optional, could store raw XML snippets or parsed details not fitting elsewhere)
        if "nmap_specific_info" in nmap_data and isinstance(nmap_data["nmap_specific_info"], dict):
             # Podríamos tener un campo específico para datos crudos de Nmap si es necesario
             # self.nmap_specific_info = nmap_data["nmap_specific_info"]
             pass # Por ahora, integramos los datos en los campos generales

        # Actualizar metadatos del escaneo
        # Nmap es a menudo el primer escaneo, así que actualizamos el estado general
        self._update_scan_metadata(success=not bool(current_scan_error), error_message=current_scan_error)


    def to_dict(self) -> Dict[str, Any]:
        """Convierte el objeto Device a un diccionario para serialización (ej. JSON, BDD)."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "type": self.type,
            "mac_address": self.mac_address,
            "vendor": self.vendor, # Este se llenaría externamente o con MacManufacturerManager
            "os_info": self.os_info,
            "hardware_info": self.hardware_info,
            "network_info": self.network_info,
            "services": self.services, # Llenado por NmapScanner u otro
            "open_ports": self.open_ports, # Llenado por NmapScanner u otro
            "wmi_specific_info": self.wmi_specific_info,
            "ssh_specific_info": self.ssh_specific_info,
            "snmp_info": self.snmp_info,
            "last_scan": self.last_scan,
            "status": self.status,
            "scan_error": self.scan_error
        }
    def get_open_ports(self) -> Dict[str, Dict[int, Dict]]:
        """
        Returns a dictionary with open ports organized by protocol.
        
        Returns:
            Dict[str, Dict[int, Dict]]: A dictionary where keys are protocols (tcp/udp)
            and values are dictionaries mapping port numbers to their service info.
        """
        # Initialize the result dictionary
        result = {'tcp': {}, 'udp': {}}
        
        # Get all open ports from the services dictionary
        for port, service_info in self.services.items():
            if 'protocol' in service_info and 'port' in service_info:
                protocol = service_info['protocol'].lower()
                port_num = int(service_info['port'])
                
                # Add to the appropriate protocol dictionary
                if protocol in result:
                    result[protocol][port_num] = service_info
        
        return result

    def __repr__(self) -> str:
        return f"<Device ip='{self.ip_address}' hostname='{self.hostname}' type='{self.type}' status='{self.status}'>"

    def get_os(self) -> str:
        """Devuelve el nombre del sistema operativo detectado, si está disponible."""
        if 'name' in self.os_info:
            return self.os_info['name']
        if 'caption' in self.os_info:
            return self.os_info['caption']
        if 'description_snmp' in self.os_info:
            return self.os_info['description_snmp']
        if 'kernel' in self.os_info:
            return self.os_info['kernel']
        if 'distribution' in self.os_info:
            return self.os_info['distribution']
        return ""
