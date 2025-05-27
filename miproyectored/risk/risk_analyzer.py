from typing import Dict, List, Optional
from miproyectored.model.device import Device # Asumiendo que Device está en model

class RiskAnalyzer:
    # --- Definición de Criterios de Riesgo ---
    # Estos valores son ejemplos y deben ajustarse según las políticas de seguridad y el entorno.

    # Puertos comúnmente asociados con servicios vulnerables o de gestión que podrían ser mal utilizados.
    HIGH_RISK_PORTS = {
        21,  # FTP (transferencia de archivos, a menudo inseguro si no es FTPS)
        22,  # SSH (acceso remoto, un objetivo común si las credenciales son débiles o hay vulnerabilidades)
        23,  # Telnet (acceso remoto no cifrado, muy inseguro)
        25,  # SMTP (servidor de correo, puede ser abusado para spam si está mal configurado)
        110, # POP3 (recuperación de correo, a menudo no cifrado)
        135, # MSRPC (Microsoft RPC, objetivo para exploits)
        137, # NetBIOS Name Service
        138, # NetBIOS Datagram Service
        139, # NetBIOS Session Service (SMB sobre NetBIOS)
        445, # Microsoft-DS (SMB directamente sobre TCP, objetivo para WannaCry, etc.)
        1433, # MSSQL Server
        1521, # Oracle DB
        3306, # MySQL DB
        3389, # RDP (Escritorio Remoto, objetivo común)
        5900, # VNC (Control remoto, a menudo sin cifrar o con credenciales débiles)
    }
    # Puntuación asignada si un puerto de alto riesgo está abierto.
    SCORE_HIGH_RISK_PORT = 20

    # Palabras clave en nombres de servicios que pueden indicar un riesgo medio.
    MEDIUM_RISK_SERVICES_KEYWORDS = [
        "telnet", "ftp", "smb", "rpc", "rdp", "vnc", "shell", "login", "exec"
    ]
    # Puntuación asignada si se detecta un servicio con palabra clave de riesgo medio.
    SCORE_MEDIUM_RISK_SERVICE = 15

    # Puntuación para puertos conocidos (<=1024) no listados como de alto riesgo.
    SCORE_KNOWN_PORT = 5
    # Puntuación para puertos registrados/dinámicos (>1024).
    SCORE_OTHER_PORT = 1

    # Sistemas operativos conocidos por ser obsoletos y tener vulnerabilidades no parcheadas.
    OBSOLETE_OS_KEYWORDS = [
        "windows xp", "windows server 2003", "windows vista", "windows server 2008", # No R2
        "linux 2.4", "linux 2.6", # Kernels muy antiguos
        # Añadir más según sea necesario
    ]
    # Puntuación si se detecta un OS obsoleto.
    SCORE_OBSOLETE_OS = 30

    # Puntuación si hay errores al obtener información detallada (SSH/WMI),
    # lo que podría indicar problemas de configuración o evasión.
    SCORE_INFO_COLLECTION_ERROR = 5

    # --- Umbrales de Puntuación para Niveles de Riesgo ---
    THRESHOLD_HIGH_RISK = 60
    THRESHOLD_MEDIUM_RISK = 30
    # THRESHOLD_LOW_RISK es implícitamente > 0 y < THRESHOLD_MEDIUM_RISK

    def __init__(self):
        # Aquí se podrían cargar configuraciones de riesgo desde un archivo (ej. JSON, YAML)
        # para hacer los umbrales y palabras clave más flexibles.
        pass

    def calculate_risk_for_device(self, device: Device) -> str:
        """
        Calcula un nivel de riesgo para un dispositivo basado en varios factores.
        La puntuación de riesgo se acumula y luego se mapea a un nivel (Muy Bajo, Bajo, Medio, Alto).
        """
        if not device:
            return "Desconocido"

        risk_score = 0
        details = [] # Para almacenar los motivos del riesgo (opcional, para informes detallados)

        # 1. Análisis de Puertos Abiertos
        if device.open_ports:
            for port in device.open_ports:
                if port in self.HIGH_RISK_PORTS:
                    risk_score += self.SCORE_HIGH_RISK_PORT
                    details.append(f"Puerto de alto riesgo abierto: {port}")
                elif port <= 1024:
                    risk_score += self.SCORE_KNOWN_PORT
                    details.append(f"Puerto conocido (<1024) abierto: {port}")
                else:
                    risk_score += self.SCORE_OTHER_PORT
                    details.append(f"Puerto (>1024) abierto: {port}")
        
        # 2. Análisis de Servicios Detectados
        if device.services:
            for port, service_name in device.services.items():
                service_name_lower = service_name.lower()
                for keyword in self.MEDIUM_RISK_SERVICES_KEYWORDS:
                    if keyword in service_name_lower:
                        risk_score += self.SCORE_MEDIUM_RISK_SERVICE
                        details.append(f"Servicio potencialmente riesgoso '{service_name}' en puerto {port}")
                        break # Contar solo una vez por servicio, incluso si coincide con múltiples palabras clave

        # 3. Análisis del Sistema Operativo
        os_name = device.get_os().lower()
        if os_name and os_name != "desconocido":
            for keyword in self.OBSOLETE_OS_KEYWORDS:
                if keyword in os_name:
                    risk_score += self.SCORE_OBSOLETE_OS
                    details.append(f"Sistema operativo obsoleto detectado: {device.get_os()}")
                    break
        
        # 4. Errores en la Recolección de Información Detallada (SSH/WMI)
        # Un error podría indicar que el host está protegido, pero también que algo no funciona
        # o que el host está intentando evadir la detección.
        if device.ssh_info and device.ssh_info.get("error"):
            risk_score += self.SCORE_INFO_COLLECTION_ERROR
            details.append(f"Error al obtener info SSH: {device.ssh_info.get('error')}")
        if device.wmi_info and device.wmi_info.get("error"):
            risk_score += self.SCORE_INFO_COLLECTION_ERROR
            details.append(f"Error al obtener info WMI: {device.wmi_info.get('error')}")

        # --- Lógica Adicional Potencial (a implementar) ---
        # - Comprobación de versiones de software específicas (ej. "Apache 2.2.15" -> Vulnerable)
        # - Búsqueda de CVEs conocidos para los servicios y versiones detectadas.
        # - Análisis de configuraciones inseguras (ej. FTP anónimo habilitado).
        # - Integración con bases de datos de vulnerabilidades.

        # Determinar nivel de riesgo basado en el puntaje
        if risk_score >= self.THRESHOLD_HIGH_RISK:
            level = "Alto"
        elif risk_score >= self.THRESHOLD_MEDIUM_RISK:
            level = "Medio"
        elif risk_score > 0:
            level = "Bajo"
        else:
            level = "Muy Bajo" # O "Informacional" si no se encontraron riesgos directos

        # Opcional: Guardar detalles del riesgo en el dispositivo si se añade un campo para ello.
        # if hasattr(device, 'risk_details'):
        #     device.risk_details = details
        
        # print(f"Risk for {device.ip}: Score {risk_score}, Level {level}, Details: {', '.join(details)}")
        return level

    def assign_risk_levels(self, devices: List[Device]):
        """
        Asigna niveles de riesgo a una lista de dispositivos.
        """
        if not devices:
            return

        for device in devices:
            risk_level = self.calculate_risk_for_device(device)
            device.set_risk_level(risk_level)
            # print(f"Dispositivo: {device.get_ip()}, OS: {device.get_os()}, Riesgo Asignado: {risk_level}")


if __name__ == '__main__':
    # Ejemplo de uso
    analyzer = RiskAnalyzer()
    
    # Crear dispositivos de ejemplo
    dev1 = Device("192.168.1.10")
    dev1.set_os("Linux Ubuntu 20.04")
    dev1.set_open_ports([22, 80, 443])
    dev1.set_services({22: "OpenSSH", 80: "Apache httpd", 443: "HTTPS"})

    dev2 = Device("192.168.1.20")
    dev2.set_os("Microsoft Windows XP") # OS obsoleto
    dev2.set_open_ports([135, 139, 445, 3389]) # Puertos de alto riesgo
    dev2.set_services({135: "msrpc", 445: "microsoft-ds (SMB)", 3389: "ms-wbt-server (RDP)"})
    
    dev3 = Device("192.168.1.30")
    dev3.set_os("macOS Big Sur")
    dev3.set_open_ports([8080])
    dev3.set_services({8080: "WebApp"})


    devices_list = [dev1, dev2, dev3]
    analyzer.assign_risk_levels(devices_list)

    for dev in devices_list:
        print(f"IP: {dev.get_ip()}, Riesgo: {dev.get_risk_level()}")
        # if hasattr(dev, 'risk_details'):
        #     print(f"  Detalles: {dev.risk_details}")
