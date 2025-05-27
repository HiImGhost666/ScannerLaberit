import re
from typing import Dict, Pattern

class MacManufacturerManager:
    MAC_PATTERN: Pattern[str] = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

    def __init__(self):
        self.manufacturer_database: Dict[str, str] = {}
        self._initialize_database()

    def _initialize_database(self):
        # Formato: primeros 6 caracteres de la MAC (OUI)
        self.manufacturer_database["00:00:0C"] = "Cisco Systems"
        self.manufacturer_database["00:1A:11"] = "Google"
        self.manufacturer_database["00:23:AB"] = "Apple Inc."
        self.manufacturer_database["00:1B:63"] = "Apple Inc."
        self.manufacturer_database["00:50:56"] = "VMware, Inc."
        self.manufacturer_database["00:0C:29"] = "VMware, Inc."
        self.manufacturer_database["08:00:27"] = "Oracle VirtualBox"
        self.manufacturer_database["DC:A6:32"] = "Raspberry Pi Foundation"
        self.manufacturer_database["B8:27:EB"] = "Raspberry Pi Foundation"
        self.manufacturer_database["00:25:90"] = "Super Micro Computer, Inc."
        self.manufacturer_database["00:1B:21"] = "Intel Corporate"
        self.manufacturer_database["9C:B6:D0"] = "Intel Corporate"
        self.manufacturer_database["00:16:32"] = "Samsung Electronics Co.,Ltd"
        self.manufacturer_database["00:14:22"] = "Dell Inc."
        self.manufacturer_database["00:0F:20"] = "Hewlett Packard"
        self.manufacturer_database["3C:D9:2B"] = "Hewlett Packard Enterprise"
        self.manufacturer_database["00:1D:D8"] = "Microsoft Corporation"
        self.manufacturer_database["14:CC:20"] = "TP-LINK TECHNOLOGIES CO.,LTD."
        self.manufacturer_database["00:09:5B"] = "NETGEAR"
        self.manufacturer_database["00:0C:6E"] = "ASUSTek COMPUTER INC."
        self.manufacturer_database["00:E0:4C"] = "Realtek Semiconductor Corp."
        self.manufacturer_database["00:10:18"] = "Broadcom"
        # Agrega más según sea necesario

    def get_manufacturer(self, mac_address: str) -> str:
        if not mac_address or not mac_address.strip():
            return "Desconocido"

        mac_address = self._normalize_mac_address(mac_address)

        if not self._is_valid_mac_address(mac_address):
            return "Formato MAC inválido"

        oui = mac_address[:8].upper()
        return self.manufacturer_database.get(oui, "Desconocido")

    def add_manufacturer(self, mac_prefix: str, manufacturer: str):
        if mac_prefix and manufacturer and mac_prefix.strip():
            self.manufacturer_database[mac_prefix.upper()] = manufacturer

    def _normalize_mac_address(self, mac_address: str) -> str:
        normalized = mac_address.strip().upper().replace("-", ":")
        # Asegurar formato XX:XX:XX si viene sin separadores
        if ":" not in normalized and len(normalized) == 12:
            normalized = ":".join(normalized[i:i+2] for i in range(0, 12, 2))
        return normalized

    def _is_valid_mac_address(self, mac_address: str) -> bool:
        return bool(self.MAC_PATTERN.match(mac_address))

    def get_all_manufacturers(self) -> Dict[str, str]:
        return dict(self.manufacturer_database)
