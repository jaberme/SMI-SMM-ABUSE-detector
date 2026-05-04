import logging
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple
 
from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    renderers,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import (
    handles,
    modules,
    pslist,
)
 
vollog = logging.getLogger(__name__)
 
 
# ─────────────────────────────────────────────────────────────────────
#   Drivers vulnerables tipo BYOVD
#
#   Subconjunto revisado de loldrivers.io priorizando los que ofrecen
#   primitivas de:
#     - escritura/lectura en memoria física
#     - read/write de MSRs arbitrarios
#     - I/O a puertos arbitrarios (incluyendo 0xB2)
#     - mapeo a PhysicalMemory
#
#   Cada entrada incluye nombre de fichero, alias de Device, y
#   capability tags. Los hash exactos se omiten porque:
#     (a) cambian entre versiones del driver
#     (b) los plugins de Vol que comparan hash son lentos en dumps grandes
#     (c) el nombre del fichero es señal suficiente para un primer triaje
# ─────────────────────────────────────────────────────────────────────
KNOWN_VULNERABLE_DRIVERS: List[Dict[str, Any]] = [
    {
        "names": ["rwdrv.sys", "rweverything.sys"],
        "device": "Nal",
        "vendor": "RWEverything",
        "capabilities": ["physmem", "msr", "io_ports", "smi_trigger"],
        "notes": "Driver legítimo, abusado para casi todo: lectura/escritura "
                 "PCI, MSRs, PhysicalMemory y disparo de SMI vía 0xB2.",
    },
    {
        "names": ["gdrv.sys", "gdrv2.sys"],
        "device": "GIO",
        "vendor": "Gigabyte",
        "capabilities": ["physmem", "msr"],
        "notes": "CVE-2018-19320. Usado por RobbinHood, Slingshot y otros.",
    },
    {
        "names": ["asio.sys", "asio2.sys", "asio3.sys"],
        "device": "Asusgio",
        "vendor": "ASUS",
        "capabilities": ["physmem", "msr", "io_ports"],
        "notes": "AsIO/AsusIO. CVE-2018-18537. Familia muy reutilizada.",
    },
    {
        "names": ["mtcbsv64.sys", "atillk64.sys"],
        "device": "ATILLKIO",
        "vendor": "AMD/ATI",
        "capabilities": ["physmem", "msr"],
        "notes": "AMD ATI Diagnostic Hardware Driver — vector clásico BYOVD.",
    },
    {
        "names": ["pcdsrvc.pkms", "pcdsrvc_x64.pkms"],
        "device": "PCDSRVC",
        "vendor": "Dell",
        "capabilities": ["physmem"],
        "notes": "CVE-2021-21551 (Dell DBUtil) — explotado por Lazarus.",
    },
    {
        "names": ["dbutil_2_3.sys", "dbutildrv2.sys"],
        "device": "DBUtil_2_3",
        "vendor": "Dell",
        "capabilities": ["physmem", "msr"],
        "notes": "CVE-2021-21551 — utilizado por múltiples APTs.",
    },
    {
        "names": ["ene.sys", "enelow.sys", "eneio64.sys"],
        "device": "EneIo",
        "vendor": "ENE Technology",
        "capabilities": ["physmem", "io_ports"],
        "notes": "Usado en familias de ransomware (Blackbyte) para "
                 "deshabilitar EDR.",
    },
    {
        "names": ["winring0.sys", "winring0x64.sys"],
        "device": "WinRing0",
        "vendor": "OpenLibSys",
        "capabilities": ["physmem", "msr", "io_ports", "smi_trigger"],
        "notes": "Driver muy conocido para sensores de hardware. Reutilizado "
                 "ampliamente en herramientas de explotación firmware.",
    },
    {
        "names": ["mhyprot2.sys", "mhyprot3.sys"],
        "device": "Mhyprot2",
        "vendor": "miHoYo (Genshin Impact)",
        "capabilities": ["kernel_arbitrary"],
        "notes": "Anticheat firmado. Usado por ransomware para terminar EDR "
                 "desde kernel.",
    },
    {
        "names": ["procexp.sys", "procexp152.sys"],
        "device": "PROCEXP",
        "vendor": "Sysinternals",
        "capabilities": ["kernel_handle"],
        "notes": "Usado en cadenas BYOVD (no vulnerable per se, pero útil "
                 "como pivote).",
    },
    {
        "names": ["speedfan.sys"],
        "device": "speedfan",
        "vendor": "Almico",
        "capabilities": ["physmem", "msr", "io_ports"],
        "notes": "Driver de monitorización abusado para R/W MSRs.",
    },
    {
        "names": ["cpuz.sys", "cpuz141.sys", "cpuz149.sys"],
        "device": "cpuz",
        "vendor": "CPUID",
        "capabilities": ["msr", "io_ports"],
        "notes": "Driver legítimo. Reutilizado en cadenas de exploit firmware.",
    },
    {
        "names": ["aswarpot.sys"],
        "device": "aswArPot",
        "vendor": "Avast",
        "capabilities": ["kernel_terminate"],
        "notes": "CVE-2022-26522/26523 — usado por ransomware AvosLocker, "
                 "Cuba, LockBit.",
    },
    {
        "names": ["truesight.sys"],
        "device": "RTCore64",
        "vendor": "Adlice",
        "capabilities": ["kernel_terminate", "msr"],
        "notes": "Usado por Terminator/Spyboy para deshabilitar EDR.",
    },
    {
        "names": ["rtcore64.sys"],
        "device": "RTCore64",
        "vendor": "MSI Afterburner",
        "capabilities": ["physmem", "msr", "io_ports"],
        "notes": "CVE-2019-16098. Explotado en múltiples campañas APT.",
    },
]
 
 
# ─────────────────────────────────────────────────────────────────────
#   Patrones característicos de frameworks de explotación SMM/firmware
#
#   Cada patrón incluye:
#     name:        identificador corto
#     pattern:     regex bytes
#     severity:    HIGH | MEDIUM | LOW
#     description: qué indica realmente
# ─────────────────────────────────────────────────────────────────────
SMM_INDICATORS: List[Dict[str, Any]] = [
    # --- Chipsec (framework legítimo de auditoría firmware, pero también
    #     herramienta favorita de quien evalúa de manera ofensiva el SMM) ---
    {
        "name": "chipsec_module_path",
        "pattern": rb"chipsec[\\/]modules[\\/]common[\\/]",
        "severity": "MEDIUM",
        "description": "Ruta a módulos de Chipsec en línea de comandos o memoria.",
    },
    {
        "name": "chipsec_smm_module",
        "pattern": rb"chipsec_main\.py.{0,40}(smm|smrr|bios_wp|spi_lock)",
        "severity": "HIGH",
        "description": "Invocación a módulos Chipsec específicos de SMM/firmware.",
    },
    {
        "name": "chipsec_helper",
        "pattern": rb"chipsec_hlpr\.sys|chipsec_helper",
        "severity": "MEDIUM",
        "description": "Driver helper de Chipsec cargado en kernel.",
    },
    # --- Nombres de proyectos públicos de abuso de firmware ---
    {
        "name": "smm_backdoor_strings",
        "pattern": rb"SmmBackdoor|SMM_BACKDOOR|smm_backdoor",
        "severity": "HIGH",
        "description": "Cadena característica del PoC SmmBackdoor.",
    },
    {
        "name": "thinkpwn",
        "pattern": rb"ThinkPwn|thinkpwn",
        "severity": "HIGH",
        "description": "Cadena del exploit ThinkPwn (Lenovo SMM).",
    },
    {
        "name": "lojax_artifact",
        "pattern": rb"ReWriter_binary\.exe|SecDxe\.efi",
        "severity": "HIGH",
        "description": "Artefactos del rootkit UEFI LoJax (Sednit/Fancy Bear).",
    },
    {
        "name": "blacklotus_strings",
        "pattern": rb"BlackLotus|baton_drop\.efi|grubx64\.efi.{0,20}rootkit",
        "severity": "HIGH",
        "description": "Strings asociados a BlackLotus (UEFI bootkit).",
    },
    # --- Símbolos UEFI/SMM frecuentes en payloads de exploit ---
    {
        "name": "efi_smm_protocols",
        "pattern": rb"EFI_SMM_(?:BASE2?|SW_DISPATCH2?|CPU_PROTOCOL|"
                   rb"SX_DISPATCH2|VARIABLE_PROTOCOL)",
        "severity": "MEDIUM",
        "description": "Nombres de protocolos SMM EFI. Pueden aparecer "
                       "legítimamente en componentes de firmware o ser parte "
                       "de un payload.",
    },
    {
        "name": "efi_runtime_services",
        "pattern": rb"gRT->SetVariable|EFI_VARIABLE_NON_VOLATILE.{0,40}"
                   rb"EFI_VARIABLE_BOOTSERVICE_ACCESS",
        "severity": "LOW",
        "description": "Patrones de manipulación de variables UEFI desde el SO.",
    },
    # --- Manipulación directa del puerto 0xB2 (APM_CNT - software SMI) ---
    {
        "name": "apm_cnt_port",
        "pattern": rb"\bAPM_CNT\b|\bAPMC\b|0x0?[bB]2.{0,8}(out|outb|__outbyte|"
                   rb"WRITE_PORT_UCHAR)",
        "severity": "HIGH",
        "description": "Referencias al puerto APM_CNT (0xB2) usado para "
                       "disparar Software SMI.",
    },
    {
        "name": "smi_handler_strings",
        "pattern": rb"SmiHandler|SMI_HANDLER|RegisterSmiHandler",
        "severity": "MEDIUM",
        "description": "Símbolos de manejo de SMI que no deberían aparecer "
                       "fuera de componentes firmware/diagnóstico.",
    },
    # --- DSE bypass / kernel patch herramientas ---
    {
        "name": "kdmapper_strings",
        "pattern": rb"kdmapper|drvmap\.exe|capcom\.sys",
        "severity": "HIGH",
        "description": "Herramientas de mapeo manual de drivers sin firma "
                       "vía drivers vulnerables (Capcom, kdmapper).",
    },
    {
        "name": "physical_memory_open",
        "pattern": rb"\\\\?\\Device\\PhysicalMemory|\\Device\\PhysicalMemory",
        "severity": "HIGH",
        "description": "Apertura de \\Device\\PhysicalMemory desde user-land.",
    },
    # --- Funciones de Windows de bajo nivel normalmente abusadas ---
    {
        "name": "ntmaps_section",
        "pattern": rb"NtMapViewOfSection.{0,80}PhysicalMemory",
        "severity": "MEDIUM",
        "description": "Mapeo de la sección PhysicalMemory desde código.",
    },
    # --- Frameworks comerciales de pentest firmware ---
    {
        "name": "scrt_crystal",
        "pattern": rb"CRYSTALSDK|CrystalSmm|smm_pwn",
        "severity": "HIGH",
        "description": "Strings de frameworks comerciales SMM exploitation.",
    },
]
 
 
# ─────────────────────────────────────────────────────────────────────
#   Rutas sospechosas para drivers cargados
#
#   Drivers legítimos firmados rara vez se cargan desde rutas de usuario.
#   Cuando un actor descarga su BYOVD lo deja típicamente en una de estas.
# ─────────────────────────────────────────────────────────────────────
SUSPICIOUS_DRIVER_PATHS: List[bytes] = [
    rb"\\Users\\",
    rb"\\AppData\\",
    rb"\\ProgramData\\",
    rb"\\Temp\\",
    rb"\\Tmp\\",
    rb"\\Public\\",
    rb"\\Downloads\\",
    rb"\\Recycle",
]
 
 
class SmiSmmAbuse(interfaces.plugins.PluginInterface):
    """Detecta artefactos de explotación SMI/SMM y BYOVD en dumps Windows."""
 
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
 
    # Tamaño máximo de lectura por chunk (8 MiB)
    _CHUNK_SIZE = 8 * 1024 * 1024
    # VADs > 512 MiB se descartan (mapeos enormes que generan ruido)
    _MAX_VAD_SIZE = 512 * 1024 * 1024
    _CHUNK_OVERLAP = 1024
    _CONTEXT_BEFORE = 32
    _CONTEXT_AFTER = 96
 
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(1, 0, 0)
            ),
            requirements.ChoiceRequirement(
                name="severity",
                description="Filtrar por severidad mínima",
                choices=["all", "low", "medium", "high"],
                default="all",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="skip-strings",
                description="Saltar el escaneo de cadenas en VAD (más rápido)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="skip-handles",
                description="Saltar el análisis de handles abiertos",
                default=False,
                optional=True,
            ),
            requirements.ListRequirement(
                name="proc",
                element_type=str,
                description="Filtrar escaneo de strings a estos procesos",
                optional=True,
            ),
        ]
 
    # ─────────────────────────────────────────────────────────────────
    #   Helpers
    # ─────────────────────────────────────────────────────────────────
    @staticmethod
    def _printable(buf: bytes) -> str:
        return "".join(chr(b) if 32 <= b < 127 else "." for b in buf)
 
    def _severity_passes(self, sev: str) -> bool:
        threshold = (self.config.get("severity") or "all").lower()
        order = {"low": 1, "medium": 2, "high": 3}
        if threshold == "all":
            return True
        return order.get(sev.lower(), 0) >= order.get(threshold, 0)
 
    def _build_driver_lookup(self) -> Dict[bytes, Dict[str, Any]]:
        """Mapa rápido de nombre-driver-en-bytes-lower → metadatos."""
        lookup: Dict[bytes, Dict[str, Any]] = {}
        for entry in KNOWN_VULNERABLE_DRIVERS:
            for name in entry["names"]:
                lookup[name.lower().encode()] = entry
        return lookup
 
    def _build_indicator_regexes(self) -> List[Tuple[Dict[str, Any], "re.Pattern[bytes]"]]:
        compiled: List[Tuple[Dict[str, Any], "re.Pattern[bytes]"]] = []
        for ind in SMM_INDICATORS:
            try:
                rx = re.compile(ind["pattern"], re.IGNORECASE)
                compiled.append((ind, rx))
            except re.error as exc:
                vollog.warning(f"Regex inválida en {ind['name']}: {exc}")
        return compiled
 
    # ─────────────────────────────────────────────────────────────────
    #   1. Drivers vulnerables cargados
    # ─────────────────────────────────────────────────────────────────
    def _scan_loaded_drivers(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config["kernel"]]
        driver_lookup = self._build_driver_lookup()
 
        try:
            mod_iter = modules.Modules.list_modules(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            )
        except Exception as exc:
            vollog.warning(f"No se pudo enumerar módulos: {exc}")
            return
 
        for mod in mod_iter:
            try:
                full_name = utility.array_to_string(
                    mod.FullDllName.get_string()
                ) if hasattr(mod, "FullDllName") else ""
                base_name = utility.array_to_string(
                    mod.BaseDllName.get_string()
                ) if hasattr(mod, "BaseDllName") else ""
            except exceptions.InvalidAddressException:
                continue
 
            base_lc = base_name.lower().encode(errors="ignore")
            full_lc_bytes = full_name.lower().encode(errors="ignore")
 
            # 1.a — Match contra catálogo de vulnerables conocidos
            if base_lc in driver_lookup:
                entry = driver_lookup[base_lc]
                if self._severity_passes("HIGH"):
                    yield (
                        0,
                        (
                            "DRIVER_VULNERABLE",
                            "HIGH",
                            base_name,
                            full_name,
                            f"vendor={entry['vendor']}, caps={','.join(entry['capabilities'])}",
                            entry["notes"],
                        ),
                    )
 
            # 1.b — Driver cargado desde ruta sospechosa (cualquier driver,
            #       sea conocido o no)
            for sus_path in SUSPICIOUS_DRIVER_PATHS:
                if sus_path.lower() in full_lc_bytes:
                    if self._severity_passes("MEDIUM"):
                        yield (
                            0,
                            (
                                "DRIVER_SUSPICIOUS_PATH",
                                "MEDIUM",
                                base_name,
                                full_name,
                                f"path_pattern={sus_path.decode()}",
                                "Driver kernel cargado desde ruta de usuario; "
                                "típico de campañas BYOVD que dropean drivers "
                                "firmados en Temp/AppData/ProgramData.",
                            ),
                        )
                    break
 
    # ─────────────────────────────────────────────────────────────────
    #   2. Procesos con handles a interfaces sensibles
    # ─────────────────────────────────────────────────────────────────
    def _scan_handles(self) -> Iterator[Tuple]:
        if self.config.get("skip-handles", False):
            return
 
        kernel = self.context.modules[self.config["kernel"]]
        driver_lookup = self._build_driver_lookup()
 
        # Construir set de device-names sospechosos (case-insensitive)
        suspicious_devices: Dict[str, Dict[str, Any]] = {}
        for entry in KNOWN_VULNERABLE_DRIVERS:
            dev = entry.get("device", "").lower()
            if dev:
                suspicious_devices[dev] = entry
 
        try:
            proc_iter = pslist.PsList.list_processes(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            )
        except Exception as exc:
            vollog.warning(f"No se pudo enumerar procesos para handles: {exc}")
            return
 
        try:
            handles_plugin = handles.Handles(
                context=self.context,
                config_path=self.config_path + ".handles_internal",
            )
        except Exception as exc:
            vollog.debug(f"No se pudo instanciar Handles plugin: {exc}")
            handles_plugin = None
 
        for proc in proc_iter:
            try:
                pid = int(proc.UniqueProcessId)
                pname = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue
 
            try:
                proc_handles = list(handles_plugin.handles(
                    proc.ObjectTable
                )) if handles_plugin else []
            except Exception:
                proc_handles = []
 
            for h in proc_handles:
                try:
                    obj_type = h.get_object_type(
                        kernel.get_type("_OBJECT_HEADER"),
                        kernel.symbol_table_name,
                    ) if hasattr(h, "get_object_type") else None
                    if obj_type not in ("File", "Device", None):
                        continue
                    body = h.Body
                    name = ""
                    # Para Device/File intentamos extraer el nombre
                    try:
                        if hasattr(body, "FileName"):
                            name = utility.array_to_string(
                                body.FileName.get_string()
                            )
                        elif hasattr(body, "ObjectName"):
                            name = utility.array_to_string(
                                body.ObjectName.get_string()
                            )
                    except Exception:
                        pass
                    if not name:
                        continue
 
                    name_lc = name.lower()
 
                    # 2.a — \Device\PhysicalMemory abierto
                    if "physicalmemory" in name_lc:
                        if self._severity_passes("HIGH"):
                            yield (
                                0,
                                (
                                    "HANDLE_PHYSICALMEMORY",
                                    "HIGH",
                                    f"{pname} (PID {pid})",
                                    name,
                                    "handle_open",
                                    "Proceso user-land con handle a "
                                    "\\Device\\PhysicalMemory: vector clásico "
                                    "para R/W físico desde user-mode.",
                                ),
                            )
                        continue
 
                    # 2.b — Handle a Device de driver vulnerable conocido
                    for dev, entry in suspicious_devices.items():
                        if dev and dev in name_lc:
                            if self._severity_passes("HIGH"):
                                yield (
                                    0,
                                    (
                                        "HANDLE_VULN_DRIVER",
                                        "HIGH",
                                        f"{pname} (PID {pid})",
                                        name,
                                        f"vendor={entry['vendor']}",
                                        f"Handle a driver vulnerable "
                                        f"({entry['vendor']}). Caps: "
                                        f"{','.join(entry['capabilities'])}.",
                                    ),
                                )
                            break
                except (exceptions.InvalidAddressException, AttributeError):
                    continue
 
    # ─────────────────────────────────────────────────────────────────
    #   3. Cadenas indicadoras en VADs de procesos
    # ─────────────────────────────────────────────────────────────────
    def _scan_strings(self) -> Iterator[Tuple]:
        if self.config.get("skip-strings", False):
            return
 
        kernel = self.context.modules[self.config["kernel"]]
        indicator_regexes = self._build_indicator_regexes()
        proc_filter = self.config.get("proc")
        proc_filter_lc = [p.lower() for p in proc_filter] if proc_filter else None
 
        try:
            proc_iter = pslist.PsList.list_processes(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            )
        except Exception as exc:
            vollog.warning(f"No se pudo enumerar procesos: {exc}")
            return
 
        # Deduplicación de hits por (pattern, candidate_text) por proceso para
        # no inundar la salida con la misma cadena repetida muchas veces
        # dentro de un mismo VAD.
        for proc in proc_iter:
            try:
                pname = utility.array_to_string(proc.ImageFileName)
                pid = int(proc.UniqueProcessId)
            except exceptions.InvalidAddressException:
                continue
 
            if proc_filter_lc is not None:
                if not any(p in pname.lower() for p in proc_filter_lc):
                    continue
 
            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue
            proc_layer = self.context.layers[proc_layer_name]
 
            seen_per_proc: Set[Tuple[str, str]] = set()
 
            try:
                vad_root = proc.get_vad_root()
            except exceptions.InvalidAddressException:
                continue
 
            try:
                vads = list(vad_root.traverse())
            except exceptions.InvalidAddressException:
                continue
 
            for vad in vads:
                try:
                    vstart = vad.get_start()
                    vend = vad.get_end()
                except exceptions.InvalidAddressException:
                    continue
 
                size = vend - vstart + 1
                if size <= 0 or size > self._MAX_VAD_SIZE:
                    continue
 
                offset = vstart
                prev_tail = b""
                prev_tail_addr = offset
 
                while offset <= vend:
                    read_size = min(self._CHUNK_SIZE, vend - offset + 1)
                    try:
                        chunk = proc_layer.read(offset, read_size, pad=True)
                    except exceptions.InvalidAddressException:
                        offset += read_size
                        prev_tail = b""
                        prev_tail_addr = offset
                        continue
 
                    if prev_tail:
                        buf = prev_tail + chunk
                        base_addr = prev_tail_addr
                    else:
                        buf = chunk
                        base_addr = offset
 
                    for ind, rx in indicator_regexes:
                        if not self._severity_passes(ind["severity"]):
                            continue
                        for m in rx.finditer(buf):
                            match_text = m.group(0).decode(
                                "utf-8", errors="replace"
                            )[:80]
                            dedup_key = (ind["name"], match_text)
                            if dedup_key in seen_per_proc:
                                continue
                            seen_per_proc.add(dedup_key)
 
                            ctx_start = max(0, m.start() - self._CONTEXT_BEFORE)
                            ctx_end = min(len(buf), m.end() + self._CONTEXT_AFTER)
                            context = self._printable(buf[ctx_start:ctx_end])
 
                            yield (
                                0,
                                (
                                    f"STRING_{ind['name'].upper()}",
                                    ind["severity"],
                                    f"{pname} (PID {pid})",
                                    f"0x{base_addr + m.start():x}",
                                    match_text,
                                    f"{ind['description']} | ctx: {context[:120]}",
                                ),
                            )
 
                    if read_size > self._CHUNK_OVERLAP:
                        prev_tail = chunk[-self._CHUNK_OVERLAP:]
                        prev_tail_addr = offset + read_size - self._CHUNK_OVERLAP
                    else:
                        prev_tail = b""
                        prev_tail_addr = offset + read_size
 
                    offset += read_size
 
    # ─────────────────────────────────────────────────────────────────
    #   Generador principal
    # ─────────────────────────────────────────────────────────────────
    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        vollog.info("Fase 1/3: análisis de drivers cargados...")
        yield from self._scan_loaded_drivers()
 
        vollog.info("Fase 2/3: análisis de handles abiertos...")
        yield from self._scan_handles()
 
        vollog.info("Fase 3/3: escaneo de cadenas indicadoras en memoria...")
        yield from self._scan_strings()
 
    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Indicator", str),
                ("Severity", str),
                ("Subject", str),
                ("Detail", str),
                ("Evidence", str),
                ("Notes", str),
            ],
            self._generator(),
        )
