#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de interfaz gráfica para la herramienta de escaneo de red (adaptado para miproyectored)

Este módulo implementa la interfaz gráfica de usuario utilizando ttkbootstrap
para mostrar y controlar el escaneo de red.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import threading
import time
import os
import sys
import logging
import socket
import sqlite3
from typing import Dict, List, Optional, Tuple, Any

# Importar módulos del proyecto miproyectored
from miproyectored.scanner.nmap_scanner import NmapScanner
from miproyectored.model.device import Device
from miproyectored.model.network_report import NetworkReport
from miproyectored.auth.network_credentials import NetworkCredentials
from miproyectored.risk.risk_analyzer import RiskAnalyzer
from miproyectored.export import csv_exporter, json_exporter, html_exporter
# Importar nuevos módulos para escaneo detallado
from miproyectored.scanner.wmi_scanner import WmiScanner
from miproyectored.scanner.ssh_scanner import SshScanner
from miproyectored.scanner.snmp_scanner import SnmpScanner
from miproyectored.inventory.inventory_manager import InventoryManager

# Configuración del sistema de logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    log_file_path = os.path.join(os.path.dirname(__file__), 'network_scanner_gui.log')
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

class NetworkScannerGUI(ttk.Window):
    """
    Clase principal para la interfaz gráfica de la herramienta de escaneo de red.
    """
    def __init__(self):
        """Inicializa la interfaz gráfica."""
        try:
            super().__init__(themename="litera") # Elige un tema de ttkbootstrap
            self.title("Herramienta de Escaneo de Red - MiProyectoRed")
            self.geometry("1300x750") # Aumentado el tamaño para más detalles
            self.minsize(1000, 600)
            
            self.nmap_scanner = NmapScanner() # Usar NmapScanner del proyecto
            self.risk_analyzer = RiskAnalyzer() # Usar RiskAnalyzer del proyecto
            
            # Inicializar escáneres específicos
            self.wmi_scanner = WmiScanner()
            self.ssh_scanner = SshScanner()
            self.snmp_scanner = SnmpScanner()
            
            # Inicializar base de datos
            self.db = InventoryManager()
            
            # Variables para almacenar los resultados del escaneo
            self.scan_results: List[Device] = []
            self.filtered_results: List[Device] = []
            self.selected_device_ip: Optional[str] = None
            
            # Contadores para tipos de dispositivos
            self.windows_devices_count = 0
            self.linux_devices_count = 0
            self.snmp_devices_count = 0
            
            # Variables para las credenciales
            self.ssh_username = ttk.StringVar()
            self.ssh_password = ttk.StringVar()
            self.ssh_key_file = ttk.StringVar()
            self.snmp_community = ttk.StringVar(value="public") # Valor por defecto para SNMP
            self.wmi_username = ttk.StringVar()
            self.wmi_password = ttk.StringVar()
            self.wmi_domain = ttk.StringVar() # Añadido para WMI
            
            # Variable para habilitar/deshabilitar escaneo WMI
            self.wmi_scan_enabled = ttk.BooleanVar(value=False)
            
            # Variable para habilitar/deshabilitar escaneo automático
            self.auto_scan_enabled = ttk.BooleanVar(value=True)
            
            self.network_range = ttk.StringVar(value=self._get_local_network_range())
            
            self.search_filter = ttk.StringVar()
            self.search_filter.trace_add("write", self._apply_filter)
            
            self.scan_status = ttk.StringVar(value="Listo para escanear.")
            
            self._create_widgets()
            
            self.protocol("WM_DELETE_WINDOW", self._on_closing)
            
            logger.info("Interfaz gráfica inicializada correctamente")
        except Exception as e:
            logger.error(f"Error al inicializar la interfaz gráfica: {e}", exc_info=True)
            messagebox.showerror("Error de Inicialización", f"Error al inicializar la aplicación: {e}")
            self.destroy()

    def _get_local_network_range(self) -> str:
        """Intenta detectar el rango de red local (ej. 192.168.1.0/24)."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            if local_ip.startswith("127."): # IP de Loopback, no útil para escanear la LAN
                # Intenta obtener una IP no loopback conectándose a un host externo (dummy)
                # Esto ayuda a identificar la interfaz de red principal usada para salir.
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1) # Timeout corto para no bloquear mucho
                try:
                    s.connect(('10.254.254.254', 1)) # IP dummy, no necesita ser alcanzable
                    local_ip = s.getsockname()[0]
                except Exception:
                    logger.warning("No se pudo determinar la IP no-loopback mediante conexión dummy. Usando IP de hostname si es válida.")
                    # Re-evaluar la IP del hostname, podría ser una IP de LAN si hay múltiples interfaces
                    local_ip = socket.gethostbyname(hostname) # Obtener de nuevo por si acaso
                    if local_ip.startswith("127."): # Si sigue siendo loopback
                        logger.warning("La IP del hostname sigue siendo loopback. Usando rango por defecto.")
                        return "192.168.1.0/24" # Fallback a un rango común
                finally:
                    s.close()
            
            if local_ip and not local_ip.startswith("127."):
                ip_parts = local_ip.split('.')
                if len(ip_parts) == 4: # Asegurar que es una IPv4 válida
                    network_base = ".".join(ip_parts[:3])
                    detected_range = f"{network_base}.0/24"
                    logger.info(f"Rango de red local detectado: {detected_range}")
                    return detected_range
                else:
                    logger.warning(f"Formato de IP local inesperado: {local_ip}. Usando rango por defecto.")
            else:
                logger.warning(f"No se pudo determinar una IP local adecuada (IP actual: {local_ip}). Usando rango por defecto.")

        except socket.gaierror:
            logger.error("Error al obtener hostname o IP (gaierror). La red podría estar desconectada o mal configurada. Usando rango por defecto.", exc_info=False)
        except Exception as e:
            logger.error(f"Error inesperado al detectar la red local: {e}. Usando rango por defecto.", exc_info=True)
        
        return "192.168.1.0/24" # Rango por defecto como fallback

    def _create_widgets(self):
        """Crea los widgets de la interfaz gráfica."""
        main_pane = ttk.PanedWindow(self, orient=HORIZONTAL)
        main_pane.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Panel Izquierdo: Controles y Configuración
        left_frame_container = ttk.Frame(main_pane, padding=10)
        main_pane.add(left_frame_container, weight=1)

        # Sección de Escaneo
        scan_frame = ttk.Labelframe(left_frame_container, text="Configuración de Escaneo", padding=10)
        scan_frame.pack(fill=X, pady=5)

        ttk.Label(scan_frame, text="Rango de Red (ej: 192.168.1.0/24):").pack(fill=X, pady=(0,2))
        ttk.Entry(scan_frame, textvariable=self.network_range).pack(fill=X, pady=(0,5))
        
        # Opción para escaneo automático
        auto_scan_check = ttk.Checkbutton(
            scan_frame, 
            text="Escaneo automático detallado (SSH, SNMP)", 
            variable=self.auto_scan_enabled,
            bootstyle="round-toggle"
        )
        auto_scan_check.pack(fill=X, pady=2)
        
        # Opción para escaneo WMI
        wmi_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Incluir escaneo WMI (Windows)",
            variable=self.wmi_scan_enabled,
            bootstyle="round-toggle"
        )
        wmi_scan_check.pack(fill=X, pady=2)
        
        self.scan_button = ttk.Button(scan_frame, text="Iniciar Escaneo", command=self._start_nmap_scan, style=SUCCESS)
        self.scan_button.pack(fill=X, pady=5)

        self.scan_progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.scan_progress.pack(fill=X, pady=5)
        
        ttk.Label(scan_frame, textvariable=self.scan_status).pack(fill=X, pady=2)

        # Sección de Credenciales para escaneo detallado
        creds_frame = ttk.Labelframe(left_frame_container, text="Credenciales para Escaneo Detallado", padding=10)
        creds_frame.pack(fill=X, pady=10)

        # SSH
        ssh_label = ttk.Label(creds_frame, text="SSH (Linux/Unix):")
        ssh_label.pack(anchor=W)
        ssh_form = ttk.Frame(creds_frame)
        ssh_form.pack(fill=X, padx=10)
        ttk.Label(ssh_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="Contraseña:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="Ruta Clave:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        key_frame = ttk.Frame(ssh_form)
        key_frame.grid(row=2, column=1, sticky=EW)
        ttk.Entry(key_frame, textvariable=self.ssh_key_file, width=10).pack(side=LEFT, expand=True, fill=X)
        ttk.Button(key_frame, text="...", command=self._browse_ssh_key, width=3).pack(side=LEFT)
        
        # WMI
        wmi_label = ttk.Label(creds_frame, text="WMI (Windows):")
        wmi_label.pack(anchor=W, pady=(5,0))
        wmi_form = ttk.Frame(creds_frame)
        wmi_form.pack(fill=X, padx=10)
        ttk.Label(wmi_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="Contraseña:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="Dominio:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_domain, width=15).grid(row=2, column=1, sticky=EW, padx=2, pady=2)
        
        # SNMP
        snmp_label = ttk.Label(creds_frame, text="SNMP:")
        snmp_label.pack(anchor=W, pady=(5,0))
        snmp_form = ttk.Frame(creds_frame)
        snmp_form.pack(fill=X, padx=10)
        ttk.Label(snmp_form, text="Comunidad:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(snmp_form, textvariable=self.snmp_community, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)

        ssh_form.columnconfigure(1, weight=1)
        wmi_form.columnconfigure(1, weight=1)
        snmp_form.columnconfigure(1, weight=1)

        # Sección de Exportación
        export_frame = ttk.Labelframe(left_frame_container, text="Exportar Resultados", padding=10)
        export_frame.pack(fill=X, pady=10)
        self.export_button = ttk.Button(export_frame, text="Exportar Datos", command=self._export_data, state=DISABLED)
        self.export_button.pack(fill=X)
        
        # Panel Derecho: Resultados y Detalles
        right_frame_container = ttk.Frame(main_pane, padding=0) # No padding for container, let PanedWindow handle it
        main_pane.add(right_frame_container, weight=3)

        results_pane = ttk.PanedWindow(right_frame_container, orient=VERTICAL)
        results_pane.pack(fill=BOTH, expand=True)

        # Frame para la tabla de resultados y búsqueda
        results_table_frame = ttk.Frame(results_pane, padding=(10,10,10,0)) # Padding solo arriba y a los lados
        results_pane.add(results_table_frame, weight=2)

        search_frame = ttk.Frame(results_table_frame)
        search_frame.pack(fill=X, pady=(0,5))
        ttk.Label(search_frame, text="Buscar:").pack(side=LEFT, padx=(0,5))
        ttk.Entry(search_frame, textvariable=self.search_filter).pack(side=LEFT, fill=X, expand=True)

        cols = ("IP", "Hostname", "MAC", "Fabricante", "OS", "Riesgo")
        self.results_tree = ttk.Treeview(results_table_frame, columns=cols, show='headings', bootstyle=PRIMARY)
        for col in cols:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100, anchor=W) # Ajustar anchos según necesidad
        self.results_tree.column("Hostname", width=150)
        self.results_tree.column("Fabricante", width=150)
        self.results_tree.column("OS", width=180)

        # Scrollbars para Treeview
        tree_ysb = ttk.Scrollbar(results_table_frame, orient=VERTICAL, command=self.results_tree.yview)
        tree_xsb = ttk.Scrollbar(results_table_frame, orient=HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscroll=tree_ysb.set, xscroll=tree_xsb.set)
        
        tree_ysb.pack(side=RIGHT, fill=Y)
        tree_xsb.pack(side=BOTTOM, fill=X)
        self.results_tree.pack(fill=BOTH, expand=True)
        
        self.results_tree.bind("<<TreeviewSelect>>", self._on_device_select)

        # Frame para detalles del dispositivo
        details_frame = ttk.Labelframe(results_pane, text="Detalles del Dispositivo Seleccionado", padding=10)
        results_pane.add(details_frame, weight=1)

        self.details_notebook = ttk.Notebook(details_frame)
        self.details_notebook.pack(fill=BOTH, expand=True)

        self.general_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ports_services_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ssh_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.wmi_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.snmp_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0) # Nueva pestaña SNMP
        
        self.details_notebook.add(self.general_details_text, text="General")
        self.details_notebook.add(self.ports_services_text, text="Puertos/Servicios")
        self.details_notebook.add(self.wmi_details_text, text="Info WMI")
        self.details_notebook.add(self.ssh_details_text, text="Info SSH")
        self.details_notebook.add(self.snmp_details_text, text="Info SNMP") # Añadir pestaña SNMP

    def _browse_ssh_key(self):
        """Abre un diálogo para seleccionar un archivo de clave SSH."""
        filepath = filedialog.askopenfilename(title="Seleccionar archivo de clave SSH")
        if filepath:
            self.ssh_key_file.set(filepath)

    def _update_scan_ui(self, scanning: bool, status_message: Optional[str] = None):
        """Actualiza la UI durante el escaneo."""
        if scanning:
            self.scan_button.config(state=DISABLED)
            self.export_button.config(state=DISABLED)
            self.scan_progress.start()
            if status_message:
                self.scan_status.set(status_message)
        else:
            self.scan_button.config(state=NORMAL)
            self.scan_progress.stop()
            if status_message:
                self.scan_status.set(status_message)
            else:
                self.scan_status.set(f"{len(self.scan_results)} dispositivos encontrados. Listo.")
            
            if self.scan_results:
                self.export_button.config(state=NORMAL)

    def _start_nmap_scan(self):
        """Inicia el escaneo Nmap en un hilo separado."""
        target = self.network_range.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un rango de red válido.")
            return
        
        self.scan_results.clear() # Limpiar resultados anteriores
        self._populate_results_tree() # Limpiar tabla
        self._clear_details_view() # Limpiar vistas de detalle
        
        self._update_scan_ui(True, "Escaneando red (Nmap)...")
        
        scan_thread = threading.Thread(target=self._perform_nmap_scan_thread, args=(target,), daemon=True)
        scan_thread.start()

    def _perform_nmap_scan_thread(self, target: str):
        """Lógica de escaneo Nmap que se ejecuta en el hilo."""
        try:
            def on_device_found(device: Device):
                """Callback cuando se encuentra un dispositivo"""
                self.scan_results.append(device)
                self.after(0, self._populate_results_tree)  # Actualizar GUI
                
            # Realizar el escaneo Nmap
            self.scan_results = []
            devices = self.nmap_scanner.scan(target, on_device_found)
            
            if not devices:
                self.after(0, lambda: messagebox.showwarning(
                    "Escaneo Completado",
                    "No se encontraron dispositivos en la red especificada.",
                    parent=self
                ))
                self.after(0, lambda: self._update_scan_ui(False, "No se encontraron dispositivos."))
                return
            
            # Contar tipos de dispositivos
            self._count_device_types()
            logger.info(f"Escaneo Nmap completado. Encontrados {len(devices)} dispositivos.")
            
            # Si el escaneo automático está habilitado, iniciar escaneos detallados
            if self.auto_scan_enabled.get():
                self._start_automatic_detailed_scans()
            else:
                self.after(0, lambda: self._update_scan_ui(False, "Escaneo Nmap completado."))
            
        except Exception as e:
            logger.error(f"Error durante el escaneo Nmap: {e}", exc_info=True)
            self.after(0, lambda: messagebox.showerror(
                "Error de Escaneo",
                f"Ocurrió un error durante el escaneo: {e}",
                parent=self
            ))
            self.after(0, lambda: self._update_scan_ui(False, "Error durante el escaneo."))

    def _count_device_types(self):
        """Cuenta los dispositivos por tipo y marca si tienen puertos relevantes."""
        self.windows_devices_count = 0
        self.linux_devices_count = 0
        self.snmp_devices_count = 0
        
        for device in self.scan_results:
            os_lower = device.get_os().lower() if device.get_os() else ""
            device.has_wmi_potential = False # Usar un nombre más descriptivo
            device.has_ssh_potential = False
            device.has_snmp_potential = False

            if "windows" in os_lower:
                self.windows_devices_count += 1
                device.has_wmi_potential = True 
            
            if any(x in os_lower for x in ["linux", "unix", "ubuntu", "debian", "centos", "fedora", "mac", "os x"]):
                self.linux_devices_count += 1
                device.has_ssh_potential = True
            
            # Nmap puede detectar el servicio SNMP en otros puertos, pero 161/udp es el estándar
            if 161 in device.get_open_ports().get('udp', {}):
                self.snmp_devices_count += 1
                device.has_snmp_potential = True
            elif any('snmp' in service_info.get('name','').lower() for port_info in device.get_open_ports().values() for service_info in port_info.values()):
                 self.snmp_devices_count += 1
                 device.has_snmp_potential = True


    def _request_credentials_dialog(self, title, prompts):
        """Muestra un diálogo genérico para solicitar credenciales."""
        # Esta es una implementación simple. Podrías usar un Toplevel personalizado para mejor UI.
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("350x200")

        entries = {}
        for i, (label_text, var, is_password) in enumerate(prompts):
            ttk.Label(dialog, text=label_text).grid(row=i, column=0, padx=5, pady=5, sticky=W)
            entry = ttk.Entry(dialog, textvariable=var, show="*" if is_password else None, width=30)
            entry.grid(row=i, column=1, padx=5, pady=5, sticky=EW)
            entries[label_text] = entry
        
        dialog.columnconfigure(1, weight=1)

        def on_ok():
            # Las StringVars se actualizan automáticamente
            dialog.destroy()

        ok_button = ttk.Button(dialog, text="Aceptar", command=on_ok)
        ok_button.grid(row=len(prompts), column=0, columnspan=2, pady=10)
        
        # Centrar el diálogo
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        self.wait_window(dialog) # Esperar a que el diálogo se cierre

    def _request_windows_credentials(self):
        """Solicita credenciales WMI si no están ya configuradas."""
        if not (self.wmi_username.get() and self.wmi_password.get()):
            messagebox.showinfo("Credenciales WMI Requeridas", 
                                "Se detectaron dispositivos Windows. Por favor, ingrese las credenciales de WMI para un escaneo detallado.",
                                parent=self)
            prompts = [
                ("Usuario WMI:", self.wmi_username, False),
                ("Contraseña WMI:", self.wmi_password, True),
                ("Dominio WMI (opcional):", self.wmi_domain, False)
            ]
            self._request_credentials_dialog("Credenciales WMI", prompts)
            return bool(self.wmi_username.get() and self.wmi_password.get())
        return True

    def _request_linux_credentials(self):
        """Solicita credenciales SSH si no están ya configuradas."""
        if not (self.ssh_username.get() and (self.ssh_password.get() or self.ssh_key_file.get())):
            messagebox.showinfo("Credenciales SSH Requeridas",
                                "Se detectaron dispositivos Linux/Unix. Por favor, ingrese las credenciales SSH para un escaneo detallado.",
                                parent=self)
            prompts = [
                ("Usuario SSH:", self.ssh_username, False),
                ("Contraseña SSH:", self.ssh_password, True),
                # ("Ruta Clave SSH (opcional):", self.ssh_key_file, False) # El browse es mejor
            ]
            # Para la clave SSH, el usuario ya tiene un botón de browse.
            # Podríamos añadir un campo de texto aquí también o solo confiar en el de la UI principal.
            self._request_credentials_dialog("Credenciales SSH", prompts)
            return bool(self.ssh_username.get() and (self.ssh_password.get() or self.ssh_key_file.get()))
        return True
        
    def _start_automatic_detailed_scans(self):
        """Prepara e inicia los escaneos detallados automáticos en un nuevo hilo."""
        if not self.scan_results:
            self._update_scan_ui(False, "No hay dispositivos para escaneo detallado.")
            return

        proceed_wmi = False
        proceed_ssh = True

        # Solo pedir credenciales WMI si está habilitado y hay dispositivos Windows
        if self.wmi_scan_enabled.get() and self.windows_devices_count > 0:
            proceed_wmi = self._request_windows_credentials()
    
        if self.linux_devices_count > 0:
            proceed_ssh = self._request_linux_credentials()
    
        if not (proceed_wmi or proceed_ssh):
            messagebox.showwarning(
                "Advertencia",
                "No se proporcionaron credenciales para el escaneo detallado.",
                parent=self)
            # Aún así, podríamos proceder con SNMP o con los que sí tengan creds.
            # O simplemente guardar Nmap y terminar. Por ahora, procedemos con lo que tengamos.

        self._update_scan_ui(True, "Iniciando escaneos detallados...")
        
        detailed_scan_thread = threading.Thread(target=self._perform_automatic_detailed_scans_thread, daemon=True)
        detailed_scan_thread.start()

    def _perform_automatic_detailed_scans_thread(self):
        """Lógica de escaneos detallados (WMI, SSH, SNMP) que se ejecuta en un hilo."""
        try:
            wmi_creds = None
            if self.wmi_username.get() and self.wmi_password.get():
                wmi_creds = NetworkCredentials(
                    username=self.wmi_username.get(),
                    password=self.wmi_password.get(),
                    domain=self.wmi_domain.get() or None
                )

            ssh_creds = None
            if self.ssh_username.get() and (self.ssh_password.get() or self.ssh_key_file.get()):
                ssh_creds = NetworkCredentials(
                    username=self.ssh_username.get(),
                    password=self.ssh_password.get() or None,
                    ssh_key_path=self.ssh_key_file.get() or None
                )

            snmp_creds = NetworkCredentials(snmp_community=self.snmp_community.get())

            total_devices = len(self.scan_results)
            for i, device in enumerate(self.scan_results):
                current_status = f"Escaneando detalles: {device.ip_address} ({i+1}/{total_devices})"
                self.after(0, lambda status=current_status: self.scan_status.set(status))

                # WMI Scan
                if device.has_wmi_potential and wmi_creds and self.wmi_scan_enabled.get():
                    try:
                        logger.info(f"Iniciando escaneo WMI para {device.ip_address}")
                        wmi_data = self.wmi_scanner.scan_device(device, wmi_creds)
                        if wmi_data:
                            device.wmi_details = wmi_data # Asumiendo que Device tiene este atributo
                            logger.info(f"WMI data obtenida para {device.ip_address}")
                        else:
                            logger.warning(f"No se obtuvo data WMI para {device.ip_address}")
                    except Exception as e:
                        logger.error(f"Error en escaneo WMI para {device.ip_address}: {e}", exc_info=True)

                # SSH Scan
                if device.has_ssh_potential and ssh_creds:
                    try:
                        logger.info(f"Iniciando escaneo SSH para {device.ip_address}")
                        ssh_data = self.ssh_scanner.scan_device(device, ssh_creds)
                        if ssh_data:
                            device.ssh_details = ssh_data # Asumiendo que Device tiene este atributo
                            logger.info(f"SSH data obtenida para {device.ip_address}")
                        else:
                            logger.warning(f"No se obtuvo data SSH para {device.ip_address}")
                    except Exception as e:
                        logger.error(f"Error en escaneo SSH para {device.ip_address}: {e}", exc_info=True)

                # SNMP Scan
                if device.has_snmp_potential and snmp_creds: # snmp_creds siempre existe con comunidad
                    try:
                        logger.info(f"Iniciando escaneo SNMP para {device.ip_address}")
                        snmp_data = self.snmp_scanner.scan_device(device, snmp_creds) # Pasar creds con comunidad
                        if snmp_data:
                            device.snmp_details = snmp_data # Asumiendo que Device tiene este atributo
                            logger.info(f"SNMP data obtenida para {device.ip_address}")
                        else:
                            logger.warning(f"No se obtuvo data SNMP para {device.ip_address}")
                    except Exception as e:
                        logger.error(f"Error en escaneo SNMP para {device.ip_address}: {e}", exc_info=True)

                # Actualizar vista de detalles si este dispositivo está seleccionado
                if device.ip_address == self.selected_device_ip:
                    self.after(0, lambda d=device: self._update_device_details_view(d))

            self.after(0, self._save_scan_to_db) # Guardar todo después de los escaneos detallados
            self.after(0, lambda: self._update_scan_ui(False, "Todos los escaneos completados."))

        except Exception as e:
            logger.error(f"Error durante los escaneos detallados automáticos: {e}", exc_info=True)
            self.after(0, lambda: messagebox.showerror("Error en Escaneo Detallado", f"Ocurrió un error: {e}"))
            self.after(0, lambda: self._update_scan_ui(False, "Error en escaneos detallados."))


    def _populate_results_tree(self):
        """Actualiza el árbol de resultados con los dispositivos encontrados."""
        # Limpiar árbol existente
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        if not self.scan_results:
            return
            
        # Agrupar dispositivos por tipo
        devices_by_type = {}
        for device in self.scan_results:
            device_type = device.type or "Unknown"
            if device_type not in devices_by_type:
                devices_by_type[device_type] = []
            devices_by_type[device_type].append(device)
            
        # Insertar dispositivos agrupados
        for device_type, devices in devices_by_type.items():
            # Crear nodo padre para el tipo
            type_node = self.results_tree.insert("", "end", text=device_type, values=("", "", "", ""))
            
            # Insertar dispositivos de este tipo
            for device in devices:
                # Determinar estado del dispositivo
                status = "✓" if device.last_scan_success else "✗" if device.last_scan_error else ""
                
                # Formatear puertos como string
                ports = ", ".join(sorted(device.services.keys(), key=lambda x: int(x)))
                
                # Insertar dispositivo
                device_node = self.results_tree.insert(
                    type_node, 
                    "end",
                    text=device.ip_address,
                    values=(
                        device.hostname or "N/A",
                        device.vendor or "N/A",
                        ports or "N/A",
                        status
                    )
                )
                
                # Añadir detalles como sub-nodos
                if device.os_info:
                    os_info = device.os_info.get('name', 'Unknown OS')
                    self.results_tree.insert(device_node, "end", text="OS", values=(os_info, "", "", ""))
                    
                # Mostrar servicios detectados
                if device.services:
                    services_node = self.results_tree.insert(device_node, "end", text="Services", values=("", "", "", ""))
                    for port, service in device.services.items():
                        service_info = f"{service['name']} {service['product']} {service['version']}".strip()
                        self.results_tree.insert(
                            services_node, 
                            "end", 
                            text=f"Port {port}", 
                            values=(service_info, "", "", "")
                        )
                        
        # Expandir todos los nodos de tipo
        for item in self.results_tree.get_children():
            self.results_tree.item(item, open=True)


    def _apply_filter(self, *args):
        """Filtra los resultados del Treeview según el texto de búsqueda."""
        search_term = self.search_filter.get().lower()
        if not search_term:
            self.filtered_results = self.scan_results[:]
        else:
            self.filtered_results = [
                dev for dev in self.scan_results 
                if search_term in str(dev.ip_address).lower() or \
                   search_term in str(dev.hostname).lower() or \
                   search_term in str(dev.mac_address).lower() or \
                   search_term in str(dev.vendor).lower() or \
                   search_term in str(dev.get_os()).lower()
            ]
        self._populate_results_tree()

    def _on_device_select(self, event=None):
        """Maneja la selección de un dispositivo en el Treeview."""
        selected_item = self.results_tree.focus()
        if not selected_item:
            self.selected_device_ip = None
            self._clear_details_view()
            return

        item_values = self.results_tree.item(selected_item, "values")
        if item_values:
            self.selected_device_ip = item_values[0]
            device = next((dev for dev in self.scan_results if dev.ip_address == self.selected_device_ip), None)
            if device:
                self._update_device_details_view(device)
            else:
                self._clear_details_view()
        else:
            self.selected_device_ip = None
            self._clear_details_view()

    def _clear_details_view(self):
        """Limpia todas las pestañas de detalles."""
        text_widgets = [
            self.general_details_text, self.ports_services_text,
            self.wmi_details_text, self.ssh_details_text, self.snmp_details_text
        ]
        for text_widget in text_widgets:
            text_widget.config(state=NORMAL)
            text_widget.delete(1.0, END)
            text_widget.config(state=DISABLED)

    def _update_text_widget(self, widget, content):
        """Actualiza un widget ScrolledText con el contenido dado."""
        widget.config(state=NORMAL)
        widget.delete(1.0, END)
        if isinstance(content, (dict, list)):
            import json
            widget.insert(END, json.dumps(content, indent=2, ensure_ascii=False))
        elif content:
            widget.insert(END, str(content))
        else:
            widget.insert(END, "No hay datos disponibles.")
        widget.config(state=DISABLED)

    def _update_device_details_view(self, device: Device):
        """Actualiza las pestañas de detalles con la información del dispositivo."""
        if not device:
            self._clear_details_view()
            return

        # General
        general_info = f"IP: {device.ip_address}\n"
        general_info += f"Hostname: {device.hostname or 'N/A'}\n"
        general_info += f"MAC: {device.mac_address or 'N/A'}\n"
        general_info += f"Fabricante: {device.vendor or 'N/A'}\n"
        general_info += f"Sistema Operativo (Nmap): {device.get_os() or 'N/A'}\n"
        general_info += f"Estado: {device.status or 'N/A'}\n"
        if device.risk_score is not None:
            general_info += f"Puntuación de Riesgo: {device.risk_score:.1f} ({device.risk_level})\n"
        else:
            general_info += f"Puntuación de Riesgo: No disponible\n"
        if device.vulnerabilities:
            general_info += "\nVulnerabilidades (Nmap):\n"
            for vul in device.vulnerabilities: # Asumiendo que vulnerabilidades es una lista de strings o dicts
                general_info += f"  - {vul}\n"
        self._update_text_widget(self.general_details_text, general_info)

        # Puertos y Servicios
        ports_info = "Puertos Abiertos (TCP):\n"
        if device.get_open_ports().get('tcp'):
            for port, service_info in device.get_open_ports()['tcp'].items():
                ports_info += f"  - Puerto {port}: {service_info.get('name', 'N/A')} ({service_info.get('product', '')} {service_info.get('version', '')})\n"
        else:
            ports_info += "  No se detectaron puertos TCP abiertos.\n"
        
        ports_info += "\nPuertos Abiertos (UDP):\n"
        if device.get_open_ports().get('udp'):
            for port, service_info in device.get_open_ports()['udp'].items():
                 ports_info += f"  - Puerto {port}: {service_info.get('name', 'N/A')} ({service_info.get('product', '')} {service_info.get('version', '')})\n"
        else:
            ports_info += "  No se detectaron puertos UDP abiertos.\n"
        self._update_text_widget(self.ports_services_text, ports_info)

        # Pestaña Info SSH
        ssh_info_str = "Información SSH:\n"
        if device.ssh_info and device.ssh_info.get("Estado") != "Desconocido" and not device.ssh_info.get("error"):
            for key, value in device.ssh_info.items():
                ssh_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.ssh_info and device.ssh_info.get("error"):
             ssh_info_str += f"  Error: {device.ssh_info['error']}\n"
        else:
            ssh_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.ssh_details_text, ssh_info_str)

        # Pestaña Info WMI
        wmi_info_str = "Información WMI:\n"
        if device.wmi_info and device.wmi_info.get("Estado") != "Desconocido" and not device.wmi_info.get("error"):
            for key, value in device.wmi_info.items():
                wmi_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.wmi_info and device.wmi_info.get("error"):
            wmi_info_str += f"  Error: {device.wmi_info['error']}\n"
        else:
            wmi_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.wmi_details_text, wmi_info_str)


    def _save_scan_to_db(self):
        """Guarda los resultados del escaneo en la base de datos."""
        if not self.scan_results:
            return
            
        try:
            logger.info(f"Guardando {len(self.scan_results)} dispositivos en la base de datos.")
            
            # Crear un nuevo reporte
            report = NetworkReport(
                target=self.network_range.get(),
                timestamp=int(time.time()),
                engine_info="Nmap Scanner"
            )
            
            # Guardar el reporte primero
            report_id = self.db.save_report(report)
            
            if report_id <= 0:
                raise Exception("Error al guardar el reporte")
            
            # Ahora guardar cada dispositivo asociado al reporte
            for device in self.scan_results:
                device.report_id = report_id  # Asociar el dispositivo al reporte
                self.db.add_or_update_device(device)
                
            logger.info("Resultados del escaneo guardados en la base de datos.")
            
        except Exception as e:
            logger.error(f"Error inesperado al guardar en la base de datos: {e}")
            messagebox.showerror("Error", f"Error al guardar en la base de datos: {e}")


    def _export_data(self):
        """Exporta los datos del escaneo a un formato seleccionado por el usuario."""
        if not self.scan_results:
            messagebox.showwarning("Sin Datos", "No hay datos para exportar.", parent=self)
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("HTML files", "*.html"), ("All files", "*.*")],
            title="Guardar Reporte Como"
        )
        if not file_path:
            return

        report = NetworkReport(devices=self.scan_results)
        file_ext = os.path.splitext(file_path)[1].lower()

        try:
            if file_ext == ".csv":
                csv_exporter.export_to_csv(report, file_path)
            elif file_ext == ".json":
                json_exporter.export_to_json(report, file_path)
            elif file_ext == ".html":
                html_exporter.export_to_html(report, file_path)
            else:
                messagebox.showerror("Error de Formato", f"Formato de archivo no soportado: {file_ext}", parent=self)
                return
            
            messagebox.showinfo("Exportación Exitosa", f"Datos exportados correctamente a:\n{file_path}", parent=self)
            logger.info(f"Datos exportados a {file_path}")
        except Exception as e:
            messagebox.showerror("Error de Exportación", f"No se pudo exportar el archivo: {e}", parent=self)
            logger.error(f"Error al exportar datos a {file_path}: {e}", exc_info=True)

    def _on_closing(self):
        """Maneja el evento de cierre de la ventana."""
        if messagebox.askokcancel("Salir", "¿Está seguro de que desea salir?", parent=self):
            logger.info("Cerrando la aplicación.")
            if self.db:
                self.db.close() # Cerrar conexión a la base de datos
            self.destroy()

if __name__ == '__main__':
    # Asegurarse que el directorio del proyecto está en sys.path para importaciones relativas
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Reimportar módulos con el path actualizado (si es necesario para pruebas directas del GUI)
    from miproyectored.scanner.nmap_scanner import NmapScanner
    from miproyectored.model.device import Device
    from miproyectored.model.network_report import NetworkReport
    from miproyectored.auth.network_credentials import NetworkCredentials
    from miproyectored.risk.risk_analyzer import RiskAnalyzer
    from miproyectored.export import csv_exporter, json_exporter, html_exporter
    from miproyectored.scanner.wmi_scanner import WmiScanner
    from miproyectored.scanner.ssh_scanner import SshScanner
    from miproyectored.scanner.snmp_scanner import SnmpScanner
    from miproyectored.inventory.inventory_manager import InventoryManager
    
    app = NetworkScannerGUI()
    app.mainloop()