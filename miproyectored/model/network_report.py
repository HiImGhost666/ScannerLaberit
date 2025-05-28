import time
from typing import List, Optional, Any, Dict
from miproyectored.model.device import Device

class NetworkReport:
    def __init__(self, target: Optional[str] = None, timestamp: Optional[int] = None, engine_info: Optional[str] = None, devices: Optional[List[Device]] = None):
        self.scan_timestamp: int = timestamp or int(time.time())  # Cambiado a scan_timestamp para coincidir con la BD
        self.target: str = target
        self.devices: List[Device] = devices or []
        self.scan_engine_info: Optional[str] = engine_info

    def add_device(self, device: Device):
        self.devices.append(device)

    def get_devices(self) -> List[Device]:
        return self.devices

    def get_device_count(self) -> int:
        return len(self.devices)

    def get_scan_timestamp(self) -> int:  # Cambiado a get_scan_timestamp
        return self.scan_timestamp

    def get_target(self) -> Optional[str]:
        return self.target

    def set_target(self, target: str):
        self.target = target

    def get_scan_engine_info(self) -> Optional[str]:
        return self.scan_engine_info

    def set_scan_engine_info(self, scan_engine_info: str):
        self.scan_engine_info = scan_engine_info

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el NetworkReport a un diccionario para serialización."""
        return {
            "scan_timestamp": self.scan_timestamp,  # Cambiado a scan_timestamp
            "target": self.target,
            "scan_engine_info": self.scan_engine_info,
            "device_count": self.get_device_count(),
            "devices": [device.to_dict() for device in self.devices]
        }
