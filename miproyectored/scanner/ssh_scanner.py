from typing import Dict, Optional
from miproyectored.model.device import Device
from miproyectored.scanner.ssh_client import SshClient
from miproyectored.auth.network_credentials import NetworkCredentials

class SshScanner:
    def __init__(self):
        self.client = None
        
    def scan_device(self, device: Device, credentials: NetworkCredentials) -> bool:
        if not credentials.has_ssh_credentials():
            return False
            
        try:
            self.client = SshClient(
                host=device.ip_address,
                username=credentials.username,
                password=credentials.password,
                key_filename=credentials.ssh_key_path
            )
            
            if self.client.client:
                ssh_data = self.client.collect_system_info()
                device.update_from_ssh(ssh_data)
                return True
                
        except Exception as e:
            print(f"Error en escaneo SSH para {device.ip_address}: {e}")
            
        return False