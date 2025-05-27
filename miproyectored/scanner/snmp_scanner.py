from typing import Dict
from miproyectored.model.device import Device
from miproyectored.scanner.snmp_client import SNMPClient
from miproyectored.auth.network_credentials import NetworkCredentials

class SnmpScanner:
    def __init__(self):
        self.client = None
        
    def scan_device(self, device: Device, credentials: NetworkCredentials) -> bool:
        if not credentials.has_snmp_credentials():
            return False
            
        try:
            self.client = SNMPClient(
                host=device.ip_address,
                community=credentials.snmp_community
            )
            
            snmp_data = self.client.collect_system_info()
            device.update_from_snmp(snmp_data)
            return True
            
        except Exception as e:
            print(f"Error en escaneo SNMP para {device.ip_address}: {e}")
            
        return False