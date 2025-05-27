from typing import Optional

class NetworkCredentials:
    """Clase para almacenar credenciales de red para diferentes protocolos."""
    
    def __init__(self, 
                 username: Optional[str] = None, 
                 password: Optional[str] = None,
                 domain: Optional[str] = None,
                 ssh_key_path: Optional[str] = None,
                 ssh_port: int = 22,
                 snmp_community: str = "public",
                 snmp_version: int = 2):
        """
        Inicializa las credenciales de red.
        
        Args:
            username: Nombre de usuario para SSH/WMI
            password: Contraseña para SSH/WMI
            domain: Dominio para WMI (formato: DOMINIO)
            ssh_key_path: Ruta al archivo de clave privada SSH
            ssh_port: Puerto SSH (por defecto 22)
            snmp_community: Comunidad SNMP (por defecto "public")
            snmp_version: Versión SNMP (por defecto 2)
        """
        self.username = username
        self.password = password
        self.domain = domain
        self.ssh_key_path = ssh_key_path
        self.ssh_port = ssh_port
        self.snmp_community = snmp_community
        self.snmp_version = snmp_version
    
    def has_ssh_credentials(self) -> bool:
        """Verifica si hay credenciales SSH válidas."""
        return bool(self.username and (self.password or self.ssh_key_path))
    
    def has_wmi_credentials(self) -> bool:
        """Verifica si hay credenciales WMI válidas."""
        return bool(self.username and self.password)
    
    def has_snmp_credentials(self) -> bool:
        """Verifica si hay credenciales SNMP válidas."""
        return bool(self.snmp_community)
