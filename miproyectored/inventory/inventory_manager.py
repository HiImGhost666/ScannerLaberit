import sqlite3
import json
from typing import Any

from typing import List, Dict, Optional
from miproyectored.model.device import Device
from miproyectored.model.network_report import NetworkReport
import os

class InventoryManager:
    DATABASE_PATH = "network_inventory.db"
    
    def __init__(self):
        self.connection = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Crea las tablas necesarias si no existen"""
        try:
            self.connection = sqlite3.connect(self.DATABASE_PATH)
            cursor = self.connection.cursor()
            
            # Tabla ScanReports
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ScanReports (
                    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_target TEXT NOT NULL,
                    scan_timestamp INTEGER NOT NULL,
                    scan_engine_info TEXT
                )
            ''')
            
            # Tabla Devices
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Devices (
                    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    hostname TEXT,
                    mac_address TEXT,
                    vendor TEXT,
                    os_info TEXT,
                    os_type TEXT,
                    os_vendor TEXT,
                    os_family TEXT,
                    os_gen TEXT,
                    risk_level TEXT,
                    last_scan_timestamp INTEGER,
                    last_scan_success BOOLEAN,
                    last_scan_error TEXT,
                    open_ports TEXT,
                    FOREIGN KEY (report_id) REFERENCES ScanReports(report_id) ON DELETE CASCADE,
                    UNIQUE (report_id, ip_address)
                )
            ''')
            
            # Tabla DevicePorts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DevicePorts (
                    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT,
                    service_product TEXT,
                    service_version TEXT,
                    service_extra_info TEXT,
                    state TEXT NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE,
                    UNIQUE (device_id, port_number, protocol)
                )
            ''')
            
            # Nueva tabla para datos WMI
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS WmiData (
                    wmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    os_caption TEXT,
                    os_version TEXT,
                    os_architecture TEXT,
                    cpu_name TEXT,
                    cpu_cores TEXT,
                    total_memory_kb TEXT,
                    free_memory_kb TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')
            
            # Nueva tabla para datos SSH
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SshData (
                    ssh_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    os_kernel TEXT,
                    distribution TEXT,
                    uptime TEXT,
                    memory_usage TEXT,
                    disk_usage TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')
            
            # Nueva tabla para datos SNMP
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SnmpData (
                    snmp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    system_name TEXT,
                    system_description TEXT,
                    system_location TEXT,
                    system_contact TEXT,
                    system_uptime TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')
            
            self.connection.commit()
            
        except sqlite3.Error as e:
            print(f"Error al inicializar la base de datos: {e}")
            raise

    def save_report(self, report: NetworkReport) -> int:
        """Guarda un reporte de red en la base de datos"""
        try:
            cursor = self.connection.cursor()
            
            # Insertar el reporte usando scan_timestamp
            cursor.execute('''
                INSERT INTO ScanReports (scan_target, scan_timestamp, scan_engine_info)
                VALUES (?, ?, ?)
            ''', (report.target, report.scan_timestamp, report.scan_engine_info))
            
            report_id = cursor.lastrowid
            
            # Insertar dispositivos
            for device in report.devices:
                self._save_device(cursor, report_id, device)
            
            self.connection.commit()
            return report_id
            
        except sqlite3.Error as e:
            print(f"Error al guardar reporte: {e}")
            self.connection.rollback()
            raise

    def _save_device(self, cursor, report_id: int, device: Device) -> int:
        """Guarda un dispositivo en la base de datos"""
        cursor.execute('''
            INSERT INTO Devices (
                report_id, ip_address, hostname, mac_address, vendor,
                os_info, os_type, os_vendor, os_family, os_gen, risk_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_id,
            device.ip_address,
            device.hostname,
            device.mac_address,
            device.vendor,
            json.dumps(device.os_info) if hasattr(device, 'os_info') else None,
            device.os_type if hasattr(device, 'os_type') else None,
            device.os_vendor if hasattr(device, 'os_vendor') else None,
            device.os_family if hasattr(device, 'os_family') else None,
            device.os_gen if hasattr(device, 'os_gen') else None,
            device.risk_level if hasattr(device, 'risk_level') else 'Unknown'
        ))
        
        device_id = cursor.lastrowid
        
        # Guardar puertos TCP
        if hasattr(device, 'tcp_ports') and device.tcp_ports:
            for port_number, service_info in device.tcp_ports.items():
                self._save_device_port(cursor, device_id, {
                    'number': port_number,
                    'service': service_info.get('name', ''),
                    'protocol': 'tcp'
                })
        
        # Guardar puertos UDP
        if hasattr(device, 'udp_ports') and device.udp_ports:
            for port_number, service_info in device.udp_ports.items():
                self._save_device_port(cursor, device_id, {
                    'number': port_number,
                    'service': service_info.get('name', ''),
                    'protocol': 'udp'
                })
        
        # Guardar datos WMI si existen
        if hasattr(device, 'wmi_specific_info') and device.wmi_specific_info:
            self._save_wmi_data(cursor, device_id, device.wmi_specific_info)
        
        # Guardar datos SSH si existen
        if hasattr(device, 'ssh_specific_info') and device.ssh_specific_info:
            self._save_ssh_data(cursor, device_id, device.ssh_specific_info)
        
        # Guardar datos SNMP si existen
        if hasattr(device, 'snmp_info') and device.snmp_info:
            self._save_snmp_data(cursor, device_id, device.snmp_info)
            
        return device_id

    def _save_device_port(self, cursor, device_id: int, port: Dict) -> int:
        """Guarda un puerto de dispositivo en la base de datos"""
        cursor.execute('''
            INSERT INTO DevicePorts (
                device_id, port_number, protocol, service_name
            ) VALUES (?, ?, ?, ?)
        ''', (device_id, port['number'], port['protocol'], port['service']))
        
        return cursor.lastrowid

    def get_reports(self) -> List[Dict]:
        """Obtiene todos los reportes de escaneo"""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT * FROM ScanReports ORDER BY scan_timestamp DESC')
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error al obtener reportes: {e}")
            return []

    def close(self):
        """Cierra la conexión a la base de datos."""
        if self.connection:
            self.connection.close()
            self.connection = None
            
    def add_or_update_device(self, device: Device) -> bool:
        """
        Agrega o actualiza un dispositivo en la base de datos.
        
        Args:
            device: El dispositivo a agregar o actualizar
            
        Returns:
            bool: True si la operación fue exitosa, False en caso contrario
        """
        if not self.connection:
            self.connection = sqlite3.connect(self.DATABASE_PATH)
            
        try:
            cursor = self.connection.cursor()
            
            # Verificar si el dispositivo ya existe
            cursor.execute(
                'SELECT device_id FROM Devices WHERE ip_address = ?',
                (device.ip_address,)
            )
            result = cursor.fetchone()
            
            if result:
                # Actualizar dispositivo existente
                device_id = result[0]
                cursor.execute('''
                    UPDATE Devices SET
                        hostname = ?,
                        mac_address = ?,
                        vendor = ?,
                        os_info = ?,
                        os_type = ?,
                        os_vendor = ?,
                        os_family = ?,
                        os_gen = ?,
                        risk_level = ?
                    WHERE device_id = ?
                ''', (
                    device.hostname,
                    device.mac_address,
                    device.vendor,
                    json.dumps(device.os_info) if device.os_info else None,
                    device.os_type if hasattr(device, 'os_type') else None,
                    device.os_vendor if hasattr(device, 'os_vendor') else None,
                    device.os_family if hasattr(device, 'os_family') else None,
                    device.os_gen if hasattr(device, 'os_gen') else None,
                    device.risk_level,
                    device_id
                ))
                
                # Eliminar puertos existentes para este dispositivo
                cursor.execute('DELETE FROM DevicePorts WHERE device_id = ?', (device_id,))
            else:
                # Insertar nuevo dispositivo
                cursor.execute('''
                    INSERT INTO Devices (
                        ip_address, hostname, mac_address, vendor,
                        os_info, os_type, os_vendor, os_family, os_gen, risk_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device.ip_address,
                    device.hostname,
                    device.mac_address,
                    device.vendor,
                    json.dumps(device.os_info) if device.os_info else None,
                    device.os_type if hasattr(device, 'os_type') else None,
                    device.os_vendor if hasattr(device, 'os_vendor') else None,
                    device.os_family if hasattr(device, 'os_family') else None,
                    device.os_gen if hasattr(device, 'os_gen') else None,
                    device.risk_level
                ))
                device_id = cursor.lastrowid
            
            # Guardar puertos del dispositivo
            if hasattr(device, 'get_open_ports'):
                open_ports = device.get_open_ports()
                for protocol, ports in open_ports.items():
                    for port_num, port_info in ports.items():
                        cursor.execute('''
                            INSERT INTO DevicePorts (
                                device_id, port_number, protocol, service_name
                            ) VALUES (?, ?, ?, ?)
                        ''', (
                            device_id,
                            port_num,
                            protocol,
                            port_info.get('name', '')
                        ))
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"Error al guardar/actualizar dispositivo: {e}")
            if self.connection:
                self.connection.rollback()
            return False

class ScanReport:
    def __init__(self, report_id: int, target: str, timestamp: int, engine_info: str):
        self.report_id = report_id
        self.target = target
        self.timestamp = timestamp
        self.engine_info = engine_info

class DevicePort:
    def __init__(self, port_id: int, device_id: int, port_number: int, service_name: str, protocol: str):
        self.port_id = port_id
        self.device_id = device_id
        self.port_number = port_number
        self.service_name = service_name
        self.protocol = protocol


def _save_wmi_data(self, cursor, device_id: int, wmi_data: Dict[str, Any]) -> int:
    """Guarda datos WMI en la base de datos"""
    cursor.execute('''
        INSERT INTO WmiData (
            device_id, os_caption, os_version, os_architecture,
            cpu_name, cpu_cores, total_memory_kb, free_memory_kb
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        device_id,
        wmi_data.get("os_caption"),
        wmi_data.get("os_version"),
        wmi_data.get("os_architecture"),
        wmi_data.get("cpu_name"),
        wmi_data.get("cpu_cores"),
        wmi_data.get("total_visible_memory_kb"),
        wmi_data.get("free_physical_memory_kb")
    ))
    return cursor.lastrowid

def _save_ssh_data(self, cursor, device_id: int, ssh_data: Dict[str, Any]) -> int:
    """Guarda datos SSH en la base de datos"""
    cursor.execute('''
        INSERT INTO SshData (
            device_id, os_kernel, distribution, uptime,
            memory_usage, disk_usage
        ) VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        device_id,
        ssh_data.get("os_kernel"),
        ssh_data.get("distribution"),
        ssh_data.get("uptime"),
        ssh_data.get("memory_usage"),
        ssh_data.get("disk_usage")
    ))
    return cursor.lastrowid

def _save_snmp_data(self, cursor, device_id: int, snmp_data: Dict[str, Any]) -> int:
    """Guarda datos SNMP en la base de datos"""
    cursor.execute('''
        INSERT INTO SnmpData (
            device_id, system_name, system_description,
            system_location, system_contact, system_uptime
        ) VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        device_id,
        snmp_data.get("system_name"),
        snmp_data.get("system_description"),
        snmp_data.get("system_location"),
        snmp_data.get("system_contact"),
        snmp_data.get("system_uptime")
    ))
    return cursor.lastrowid
