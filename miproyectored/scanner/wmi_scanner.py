from typing import Dict, Optional
from miproyectored.model.device import Device
from miproyectored.scanner.wmi_client import WmiClient
from miproyectored.auth.network_credentials import NetworkCredentials

class WmiScanner:
    def __init__(self):
        self.client = None
        
    def scan_device(self, device: Device, credentials: NetworkCredentials) -> bool:
        if not credentials.has_wmi_credentials():
            return False
            
        try:
            self.client = WmiClient(
                host=device.ip_address,
                username=credentials.username,
                password=credentials.password,
                domain=credentials.domain
            )
            
            if self.client.connection:
                wmi_data = self.client.collect_system_info()
                device.update_from_wmi(wmi_data)
                return True
                
        except Exception as e:
            print(f"Error en escaneo WMI para {device.ip_address}: {e}")
            
        return False