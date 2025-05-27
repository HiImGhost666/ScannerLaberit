import datetime

class DataNormalizer:
    """
    Clase para normalizar y formatear datos, similar a DataNormalizer.java.
    """
    DEFAULT_UNKNOWN = "Desconocido"  # Mover la constante aquí como atributo de clase

    def __init__(self):
        # En Python, el formateo de fechas se maneja de forma diferente,
        # no se suele precompilar un formateador como SimpleDateFormat
        # a menos que haya requisitos de rendimiento muy específicos.
        pass

    def normalize_string(self, input_str: str) -> str:
        """
        Normaliza un string: lo convierte a minúsculas y maneja nulos/vacíos.
        """
        if not input_str or not input_str.strip():
            return self.DEFAULT_UNKNOWN
        return input_str.strip().lower()

    def normalize_mac_address(self, mac: str) -> str:
        """
        Normaliza una dirección MAC: la convierte a mayúsculas y maneja nulos/vacíos.
        """
        if not mac or not mac.strip():
            return self.DEFAULT_UNKNOWN
        return mac.strip().upper()

    def format_timestamp(self, timestamp_ms: int) -> str:
        """
        Formatea un timestamp (long en milisegundos) a un string de fecha legible.
        """
        if timestamp_ms <= 0:
            return self.DEFAULT_UNKNOWN
        try:
            # Convertir milisegundos a segundos
            dt_object = datetime.datetime.fromtimestamp(timestamp_ms / 1000)
            # Formato similar a "yyyy-MM-dd HH:mm:ss z"
            # Python no tiene un equivalente directo para 'z' (nombre de zona horaria)
            # de forma simple con strftime. Se puede usar pytz para zonas horarias más complejas.
            # Aquí usamos un formato común.
            return dt_object.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return self.DEFAULT_UNKNOWN
            
    def normalize_os_info(self, os_info: dict) -> dict:
        """
        Normaliza la información del sistema operativo obtenida del escaneo Nmap.
        
        Args:
            os_info: Diccionario con la información del sistema operativo
            
        Returns:
            dict: Diccionario con la información normalizada
        """
        if not os_info:
            return {
                'name': self.DEFAULT_UNKNOWN,
                'type': self.DEFAULT_UNKNOWN,
                'vendor': self.DEFAULT_UNKNOWN,
                'osfamily': self.DEFAULT_UNKNOWN,
                'osgen': self.DEFAULT_UNKNOWN,
                'accuracy': '0',
                'cpe': ''
            }
            
        normalized = {}
        
        # Normalizar campos básicos
        normalized['name'] = os_info.get('name', self.DEFAULT_UNKNOWN)
        normalized['type'] = os_info.get('type', self.DEFAULT_UNKNOWN)
        normalized['vendor'] = os_info.get('vendor', self.DEFAULT_UNKNOWN)
        normalized['osfamily'] = os_info.get('osfamily', self.DEFAULT_UNKNOWN)
        normalized['osgen'] = os_info.get('osgen', self.DEFAULT_UNKNOWN)
        normalized['cpe'] = os_info.get('cpe', '')
        
        # Normalizar precisión
        accuracy = str(os_info.get('accuracy', '0'))
        try:
            # Asegurarse de que la precisión sea un número entre 0 y 100
            accuracy_int = int(accuracy)
            accuracy_int = max(0, min(100, accuracy_int))  # Asegurar que esté entre 0 y 100
            normalized['accuracy'] = str(accuracy_int)
        except (ValueError, TypeError):
            normalized['accuracy'] = '0'
            
        # Intentar inferir la familia del SO si no está presente
        if normalized['osfamily'] == self.DEFAULT_UNKNOWN and normalized['name'] != self.DEFAULT_UNKNOWN:
            name_lower = normalized['name'].lower()
            if 'windows' in name_lower:
                normalized['osfamily'] = 'Windows'
            elif 'linux' in name_lower:
                normalized['osfamily'] = 'Linux'
            elif 'mac os' in name_lower or 'darwin' in name_lower:
                normalized['osfamily'] = 'Mac OS X'
            elif 'freebsd' in name_lower or 'openbsd' in name_lower or 'netbsd' in name_lower:
                normalized['osfamily'] = 'BSD'
                
        return normalized

if __name__ == '__main__':
    # Ejemplo de uso
    normalizer = DataNormalizer()
    print(f"String normalizado: {normalizer.normalize_string('  Test String  ')}")
    print(f"MAC normalizada: {normalizer.normalize_mac_address('00-1A-2B-3C-4D-5E')}")
    print(f"Timestamp formateado: {normalizer.format_timestamp(datetime.datetime.now().timestamp() * 1000)}")
    print(f"Timestamp inválido: {normalizer.format_timestamp(0)}")
