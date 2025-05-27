from typing import Dict, Optional
import paramiko

class SshClient:
    def __init__(self, host: str, port: int = 22, username: Optional[str] = None, password: Optional[str] = None, key_filename: Optional[str] = None, timeout: int = 10):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.client = None
        self.connection_error = None

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Aceptar automáticamente la clave del host (considerar implicaciones de seguridad)
            
            print(f"Intentando conectar a {self.host}:{self.port} vía SSH con usuario {self.username}...")
            if self.key_filename:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_filename,
                    timeout=self.timeout,
                    look_for_keys=False, # No buscar claves en ubicaciones por defecto si se especifica una
                    allow_agent=False # No usar agente SSH si se especifica una clave
                )
            elif self.password:
                 self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False
                )
            else:
                # Intento de conexión sin contraseña (podría funcionar si hay claves SSH configuradas en el agente o ~/.ssh/config)
                # O si el servidor permite login sin password (no recomendado)
                 self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    timeout=self.timeout,
                    allow_agent=True, # Permitir uso del agente SSH
                    look_for_keys=True # Buscar claves en ubicaciones por defecto
                )
            print(f"Conexión SSH a {self.host} exitosa.")
        except paramiko.AuthenticationException:
            self.connection_error = "Error de autenticación SSH."
            print(f"{self.connection_error} para {self.host} con usuario {self.username}")
        except paramiko.SSHException as e:
            self.connection_error = f"Error de SSH: {e}"
            print(f"{self.connection_error} para {self.host}")
        except socket.timeout:
            self.connection_error = "Timeout durante la conexión SSH."
            print(f"{self.connection_error} para {self.host}")
        except Exception as e:
            self.connection_error = f"Error inesperado en conexión SSH: {e}"
            print(f"{self.connection_error} para {self.host}")
        
        if self.connection_error and self.client:
            self.client.close()
            self.client = None


    def _execute_command(self, command: str) -> Optional[str]:
        if not self.client or self.connection_error:
            return None
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode('utf-8', errors='replace').strip()
            error = stderr.read().decode('utf-8', errors='replace').strip()
            if error and "stdin: is not a tty" not in error.lower(): # Ignorar error común de tty
                # print(f"Error ejecutando comando SSH '{command}' en {self.host}: {error}")
                # Podríamos devolver el error o parte de él si es relevante
                return f"Error: {error}" if not output else output + f"\nError: {error}"
            return output
        except paramiko.SSHException as e:
            print(f"Error SSH ejecutando comando '{command}' en {self.host}: {e}")
            return f"Error SSH: {e}"
        except socket.timeout:
            print(f"Timeout ejecutando comando SSH '{command}' en {self.host}")
            return "Error: Timeout ejecutando comando"
        except Exception as e:
            print(f"Error inesperado ejecutando comando SSH '{command}' en {self.host}: {e}")
            return f"Error inesperado: {e}"

    def collect_system_info(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if self.connection_error:
            info["error"] = self.connection_error
            return info
        if not self.client:
            info["error"] = "Cliente SSH no conectado."
            return info

        # Comandos comunes para recolectar información en sistemas tipo Unix (Linux/macOS)
        commands = {
            "os_kernel": "uname -a",
            "hostname": "hostname",
            "uptime": "uptime -p",
            "disk_usage": "df -h /", # Uso del disco para la raíz, simplificado
            "memory_usage": "free -h | grep Mem | awk '{print $3\"/\"$2}'", # Memoria usada/total
            # "cpu_info": "cat /proc/cpuinfo | grep 'model name' | uniq | sed 's/model name\\s*: //'", # Más complejo de parsear
            "distro_info": "cat /etc/*-release | grep PRETTY_NAME || lsb_release -ds || cat /etc/issue.net || echo Desconocido"
        }

        for key, cmd in commands.items():
            output = self._execute_command(cmd)
            if output:
                info[key] = output
            else:
                info[key] = "No se pudo obtener"
        
        if not any(val != "No se pudo obtener" for val in info.values()): # Si todo falló
             info["error"] = "No se pudo recolectar información del sistema vía SSH."
        else:
            info["status"] = "Información SSH recolectada parcialmente." if "No se pudo obtener" in info.values() else "Información SSH recolectada exitosamente."
            
        return info

    def close(self):
        if self.client:
            self.client.close()
            print(f"Conexión SSH a {self.host} cerrada.")

if __name__ == '__main__':
    print("Ejemplo de SshClient (requiere un host SSH accesible para probar):")
    # Reemplaza con tus datos para probar
    # test_host = "tu_host_ssh" 
    # test_user = "tu_usuario"
    # test_pass = "tu_password" # O usa test_keyfile
    # test_keyfile = "/ruta/a/tu/clave_privada.pem"

    # if 'test_host' in locals():
    #     ssh_client = SshClient(test_host, username=test_user, password=test_pass) # o key_filename=test_keyfile
    #     if not ssh_client.connection_error:
    #         sys_info = ssh_client.collect_system_info()
    #         for key, value in sys_info.items():
    #             print(f"{key}: {value}")
    #         ssh_client.close()
    #     else:
    #         print(f"No se pudo conectar o recolectar información de {test_host}")
    # else:
    #     print("Descomenta y configura las variables de prueba en __main__ para probar SshClient.")
    print("Asegúrate de tener Paramiko instalado: pip install paramiko")