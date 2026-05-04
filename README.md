# SMI-SMM-ABUSE-detector
Plugin Volatility 3 para detectar artefactos en memoria que sugieran intentos de explotación de firmware vía SMI/SMM desde el sistema operativo (perfiles Windows 10/11 x64).

o que detecta
--------------
1. **Drivers vulnerables conocidos cargados** (BYOVD - Bring Your Own
   Vulnerable Driver). Comparación con una lista interna basada en
   loldrivers.io: RWEverything, gdrv, AsIO, pcdsrvc, ene.sys, etc.
   Estos drivers están firmados pero exponen primitivas de R/W físico
   que permiten escribir en MSRs, mapear PhysicalMemory y disparar SMIs.
 
2. **Procesos con handles a interfaces sensibles**:
     - \Device\PhysicalMemory  (acceso directo a RAM física)
     - Device names de drivers vulnerables conocidos
     - \Device\Nal (RWEverything)
 
3. **Cadenas características de frameworks de explotación SMM** en la
   memoria de procesos: referencias a Chipsec, SmmBackdoor, símbolos
   EFI_SMM_*, nombres de protocolos UEFI usados en exploits.
 
4. **Indicadores de I/O al puerto 0xB2** (APM_CNT, el método clásico de
   trigger software-SMI) y wrappers conocidos en código.
 
5. **Drivers cargados desde rutas sospechosas** (Temp, AppData,
   ProgramData) que es típico cuando se dropean drivers vulnerables
   firmados durante una intrusión.
 
Lo que NO hace
--------------
- No accede a SMRAM (es por diseño inaccesible al SO desde un dump).
- No verifica el estado de bloqueo SMRR/D_LCK por hardware (no recuperable
  fiablemente desde un dump de software).
- No detecta rootkits SMM activos (que son invisibles al SO).
 
El plugin produce HIPÓTESIS de compromiso. Cada hit requiere triaje
manual y correlación con timeline, eventos de Windows, y captura
forense del disco.
 
Instalación y uso
-----------------
    cp smi_smm_abuse.py <vol3>/volatility3/framework/plugins/windows/
    vol -f memory.raw windows.smi_smm_abuse
    vol -f memory.raw windows.smi_smm_abuse --severity high
    vol -r csv -f memory.raw windows.smi_smm_abuse > findings.csv
"""
