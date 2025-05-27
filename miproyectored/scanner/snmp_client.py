from typing import Dict, Optional, Any
import logging
import time

try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("Módulo pysnmp no disponible. La funcionalidad SNMP estará deshabilitada.")

class SNMPClient:
    """Cliente para recolectar información mediante SNMP."""
    
    def __init__(self, host: str, community: str = "public", port: int = 161, timeout: int = 5):
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        self.connection_error = None
        
        if not SNMP_AVAILABLE:
            self.connection_error = "Módulo pysnmp no disponible."
            print(self.connection_error)
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Recolecta información del sistema mediante SNMP."""
        if not SNMP_AVAILABLE:
            return {"error": "Módulo pysnmp no disponible."}
        
        result = {}
        
        try:
            # Información básica del sistema
            system_info = self._get_system_info()
            result.update(system_info)
            
            # Información de memoria
            memory_info = self._get_memory_info()
            result.update(memory_info)
            
            # Carga del CPU
            cpu_info = self._get_cpu_info()
            result.update(cpu_info)
            
            # Procesos en ejecución
            process_info = self._get_process_info()
            result.update(process_info)
            
        except Exception as e:
            error_msg = f"Error al recolectar información SNMP: {str(e)}"
            print(error_msg)
            result["error"] = error_msg
        
        return result
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Obtiene información básica del sistema."""
        result = {}
        
        # OIDs estándar para información del sistema
        oids = {
            "sysDescr": "1.3.6.1.2.1.1.1.0",      # Descripción del sistema
            "sysObjectID": "1.3.6.1.2.1.1.2.0",   # ID del objeto
            "sysUpTime": "1.3.6.1.2.1.1.3.0",     # Tiempo de actividad
            "sysContact": "1.3.6.1.2.1.1.4.0",    # Contacto
            "sysName": "1.3.6.1.2.1.1.5.0",       # Nombre del sistema
            "sysLocation": "1.3.6.1.2.1.1.6.0",   # Ubicación
            "sysServices": "1.3.6.1.2.1.1.7.0"    # Servicios
        }
        
        for name, oid in oids.items():
            value = self._get_snmp_value(oid)
            if value is not None:
                result[name] = value
        
        return result
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Obtiene información de memoria."""
        result = {}
        
        # OIDs para información de memoria (UCD-SNMP-MIB)
        oids = {
            "memTotalReal": "1.3.6.1.4.1.2021.4.5.0",  # Memoria física total
            "memAvailReal": "1.3.6.1.4.1.2021.4.6.0",  # Memoria física disponible
            "memTotalSwap": "1.3.6.1.4.1.2021.4.3.0",  # Swap total
            "memAvailSwap": "1.3.6.1.4.1.2021.4.4.0"   # Swap disponible
        }
        
        for name, oid in oids.items():
            value = self._get_snmp_value(oid)
            if value is not None:
                result[name] = value
        
        return result
    
    def _get_cpu_info(self) -> Dict[str, Any]:
        """Obtiene información de CPU."""
        result = {}
        
        # OIDs para información de CPU (UCD-SNMP-MIB)
        oids = {
            "cpuUser": "1.3.6.1.4.1.2021.11.9.0",    # Porcentaje de CPU en modo usuario
            "cpuSystem": "1.3.6.1.4.1.2021.11.10.0", # Porcentaje de CPU en modo sistema
            "cpuIdle": "1.3.6.1.4.1.2021.11.11.0"    # Porcentaje de CPU inactivo
        }
        
        for name, oid in oids.items():
            value = self._get_snmp_value(oid)
            if value is not None:
                result[name] = value
        
        # Calcular carga total de CPU
        if "cpuIdle" in result:
            try:
                result["cpuLoad"] = 100 - int(result["cpuIdle"])
            except (ValueError, TypeError):
                pass
        
        return result
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Obtiene información de procesos en ejecución."""
        result = {}
        
        # OID para número de procesos (HOST-RESOURCES-MIB)
        num_processes_oid = "1.3.6.1.2.1.25.1.6.0"
        num_processes = self._get_snmp_value(num_processes_oid)
        
        if num_processes is not None:
            result["numProcesses"] = num_processes
        
        # Obtener lista de procesos (más complejo, requiere recorrer una tabla)
        # Esto es una simplificación, en un entorno real se recorrería la tabla hrSWRunTable
        processes = []
        result["runningProcesses"] = processes
        
        return result
    
    def _get_snmp_value(self, oid: str) -> Optional[Any]:
        """Obtiene un valor SNMP para un OID específico."""
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(SnmpEngine(),
                       CommunityData(self.community),
                       UdpTransportTarget((self.host, self.port), timeout=self.timeout),
                       ContextData(),
                       ObjectType(ObjectIdentity(oid)))
            )
            
            if error_indication:
                print(f"Error SNMP: {error_indication}")
                return None
            elif error_status:
                print(f"Error SNMP: {error_status.prettyPrint()} en {error_index and var_binds[int(error_index) - 1][0] or '?'}")
                return None
            else:
                for var_bind in var_binds:
                    return var_bind[1].prettyPrint()
        except Exception as e:
            print(f"Error al obtener valor SNMP para OID {oid}: {e}")
            return None