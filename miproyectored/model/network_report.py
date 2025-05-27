import time
from typing import List, Optional, Any, Dict
from miproyectored.model.device import Device

class NetworkReport:
    def __init__(self):
        self.scan_timestamp: int = int(time.time() * 1000)  # Milisegundos
        self.scanned_network_target: Optional[str] = None
        self.devices: List[Device] = []
        self.scan_engine_info: Optional[str] = None

    def add_device(self, device: Device):
        self.devices.append(device)

    def get_devices(self) -> List[Device]:
        return self.devices

    def get_device_count(self) -> int:
        return len(self.devices)

    def get_scan_timestamp(self) -> int:
        return self.scan_timestamp

    def get_scanned_network_target(self) -> Optional[str]:
        return self.scanned_network_target

    def set_scanned_network_target(self, scanned_network_target: str):
        self.scanned_network_target = scanned_network_target

    def get_scan_engine_info(self) -> Optional[str]:
        return self.scan_engine_info

    def set_scan_engine_info(self, scan_engine_info: str):
        self.scan_engine_info = scan_engine_info

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el NetworkReport a un diccionario para serialización."""
        return {
            "scan_timestamp": self.scan_timestamp,
            "scanned_network_target": self.scanned_network_target,
            "scan_engine_info": self.scan_engine_info,
            "device_count": self.get_device_count(),
            "devices": [device.to_dict() for device in self.devices]
        }
