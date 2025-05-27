import ipaddress
import socket
from typing import List, Optional

def detect_local_networks() -> List[str]:
    """
    Detecta las redes locales (formato CIDR, ej. "192.168.1.0/24") a las que la máquina está conectada.
    Intenta excluir interfaces de loopback.
    NOTA: Esta función es una simplificación y puede no funcionar en todos los sistemas operativos
    o configuraciones de red de la misma manera que la versión Java con NetworkInterface.
    Se basa en obtener la IP del host y asumir una máscara /24 común para redes domésticas/pequeñas.
    Para una detección más robusta, se podrían necesitar librerías como `netifaces`.
    """
    networks: List[str] = []
    try:
        hostname = socket.gethostname()
        # Obtener todas las IPs asociadas con el hostname
        # Esto puede devolver múltiples IPs si hay varias interfaces
        addr_info = socket.getaddrinfo(hostname, None)
        
        for item in addr_info:
            family, _, _, _, sockaddr = item
            if family == socket.AF_INET: # Solo IPv4
                ip_address_str = sockaddr[0]
                try:
                    # Crear un objeto de interfaz de red para obtener la dirección de red
                    # Asumimos una máscara /24 por simplicidad, esto es una gran suposición.
                    # Para una detección precisa de la máscara, se necesitarían métodos más avanzados.
                    ip_interface = ipaddress.ip_interface(f"{ip_address_str}/24") 
                    network_cidr = str(ip_interface.network)
                    if network_cidr not in networks and not ip_interface.is_loopback:
                        networks.append(network_cidr)
                        print(f"Interfaz (supuesta): {ip_address_str} -> Red detectada: {network_cidr}")
                except ValueError:
                    # Podría fallar si la IP es, por ejemplo, de loopback y no se maneja bien con /24
                    print(f"No se pudo determinar la red para la IP: {ip_address_str}")
                    pass
        
        # Fallback si no se detectaron redes (ej. solo se obtuvo 127.0.0.1)
        if not networks:
            try:
                # Intento alternativo conectándose a un host externo (no establece conexión real)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80)) # DNS de Google
                local_ip = s.getsockname()[0]
                s.close()
                if local_ip and not ipaddress.ip_address(local_ip).is_loopback:
                    ip_interface = ipaddress.ip_interface(f"{local_ip}/24")
                    network_cidr = str(ip_interface.network)
                    if network_cidr not in networks:
                        networks.append(network_cidr)
                        print(f"Interfaz (fallback): {local_ip} -> Red detectada: {network_cidr}")
            except Exception as e:
                print(f"Error en fallback de detección de red: {e}")

    except socket.gaierror as e:
        print(f"Error al obtener información de la dirección del host: {e}")
    except Exception as e:
        print(f"Error general al detectar redes locales: {e}")
        
    return list(set(networks)) # Eliminar duplicados

def calculate_network_address(ip: str, prefix_length: int) -> Optional[str]:
    """
    Calcula la dirección de red base a partir de una dirección IP y la longitud de su prefijo.
    """
    try:
        # ipaddress.ip_network espera la IP en formato CIDR o IP/máscara
        # Usamos strict=False para permitir IPs de host
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return str(network.network_address)
    except ValueError as e:
        print(f"Error al calcular la dirección de red para '{ip}/{prefix_length}': {e}")
        return None

def get_hostname(ip_address: str) -> str:
    """
    Intenta resolver el nombre de host para una dirección IP dada.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror: # Host no encontrado
        return ip_address
    except socket.gaierror: # Error de resolución de nombre
        return ip_address
    except Exception: # Otros errores
        return ip_address

if __name__ == '__main__':
    print("Redes locales detectadas:")
    local_nets = detect_local_networks()
    if local_nets:
        for net in local_nets:
            print(net)
    else:
        print("No se pudieron detectar redes locales automáticamente.")
        print("Considera especificar el objetivo manualmente, ej. '192.168.1.0/24'.")

    print("\nEjemplo de cálculo de dirección de red:")
    print(f"Para 192.168.1.100/24 -> {calculate_network_address('192.168.1.100', 24)}")
    print(f"Para 10.0.5.30/16 -> {calculate_network_address('10.0.5.30', 16)}")

    print("\nEjemplo de resolución de hostname:")
    print(f"Hostname para 8.8.8.8: {get_hostname('8.8.8.8')}")
    # La siguiente línea es para pruebas locales, puedes descomentarla si la necesitas para depurar
    # o eliminarla si ya no es necesaria.
    # print(f"Hostname para una IP local (puede variar): {get_hostname('192.168.1.1')}") # Descomentar para probar