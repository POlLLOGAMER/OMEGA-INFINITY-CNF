#!/usr/bin/env python3
"""
============================================================================
 Parser de solución SAT para colisión de SHA-3/256
 
 Lee la salida de un solver SAT y extrae los dos mensajes que colisionan.
 
 Uso:
     python3 parse_solution.py sha3_var.map solution.txt
     
 La salida del solver debe estar en formato estándar DIMACS:
   - Línea "s SATISFIABLE" o "s UNSATISFIABLE"
   - Líneas "v <literal>" con las asignaciones de variables
============================================================================
"""

import sys
import hashlib


def parse_map(map_path):
    """Lee el archivo de mapeo de variables."""
    config = {}
    with open(map_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split('=', 1)
                config[key] = int(val)
    return config


def parse_sat_solution(sol_path):
    """
    Parsea la salida del solver SAT.
    Retorna: (is_sat, assignments)
      - is_sat: True si SATISFIABLE, False si UNSATISFIABLE
      - assignments: dict {var_id: bool} con las asignaciones
    """
    is_sat = None
    assignments = {}
    
    with open(sol_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('c'):
                continue
            
            if line.startswith('s '):
                status = line.split()[1]
                if status == 'SATISFIABLE':
                    is_sat = True
                elif status == 'UNSATISFIABLE':
                    is_sat = False
                continue
            
            if line.startswith('v '):
                # Línea de valores: "v 1 -2 3 -4 0"
                literals = line.split()[1:]
                for lit in literals:
                    if lit == '0':
                        continue
                    var_id = abs(int(lit))
                    value = int(lit) > 0
                    assignments[var_id] = value
    
    return is_sat, assignments


def extract_message(assignments, start_var, end_var):
    """
    Extrae un mensaje de las asignaciones del solver.
    Retorna: (bits_list, bytes_obj, hex_str)
    """
    bits = []
    for var_id in range(start_var, end_var + 1):
        bit = assignments.get(var_id, False)
        bits.append(1 if bit else 0)
    
    # Convertir bits a bytes (little-endian bit order dentro de cada byte)
    msg_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            byte_bits.extend([0] * (8 - len(byte_bits)))
        # Little-endian: bit 0 es el LSB
        byte_val = 0
        for j, b in enumerate(byte_bits):
            byte_val |= (b << j)
        msg_bytes.append(byte_val)
    
    hex_str = msg_bytes.hex()
    return bits, bytes(msg_bytes), hex_str


def verify_sha3_256(msg_bytes):
    """
    Verifica el hash SHA-3/256 de un mensaje usando hashlib.
    Retorna el hash como hex string.
    """
    h = hashlib.sha3_256(msg_bytes).hexdigest()
    return h


def main():
    if len(sys.argv) != 3:
        print(f"Uso: {sys.argv[0]} <archivo.map> <solucion.txt>")
        print()
        print("Ejemplo:")
        print(f"  {sys.argv[0]} sha3_var.map solution.txt")
        sys.exit(1)
    
    map_path = sys.argv[1]
    sol_path = sys.argv[2]
    
    # Parsear archivos
    print("[*] Leyendo mapa de variables...")
    config = parse_map(map_path)
    msg_bits = config['MSG_BITS']
    msg1_start = config['msg1_start']
    msg1_end = config['msg1_end']
    msg2_start = config['msg2_start']
    msg2_end = config['msg2_end']
    total_vars = config['total_vars']
    total_clauses = config['total_clauses']
    
    print(f"    Mensajes de {msg_bits} bits ({msg_bits//8} bytes)")
    print(f"    Variables totales: {total_vars}")
    print(f"    Cláusulas totales: {total_clauses}")
    print()
    
    print("[*] Parseando solución del solver SAT...")
    is_sat, assignments = parse_sat_solution(sol_path)
    
    if is_sat is None:
        print("[!] Error: no se encontró línea de estado en la solución")
        print("    Esperando 's SATISFIABLE' o 's UNSATISFIABLE'")
        sys.exit(1)
    
    if not is_sat:
        print("[✗] El problema es UNSATISFIABLE")
        print("    No existe colisión para mensajes de este tamaño")
        sys.exit(0)
    
    print(f"[✓] Solución SATISFIABLE encontrada")
    print(f"    Variables asignadas: {len(assignments)}")
    print()
    
    # Extraer mensajes
    print("[*] Extrayendo mensajes de la solución...")
    bits1, bytes1, hex1 = extract_message(assignments, msg1_start, msg1_end)
    bits2, bytes2, hex2 = extract_message(assignments, msg2_start, msg2_end)
    
    print()
    print("=" * 70)
    print("  MENSAJES QUE COLISIONAN EN SHA-3/256")
    print("=" * 70)
    print()
    
    print("Mensaje 1:")
    print(f"  Hex:    {hex1}")
    print(f"  Bytes:  {bytes1.hex()}")
    print(f"  Bits:   {''.join(str(b) for b in bits1)}")
    print()
    
    print("Mensaje 2:")
    print(f"  Hex:    {hex2}")
    print(f"  Bytes:  {bytes2.hex()}")
    print(f"  Bits:   {''.join(str(b) for b in bits2)}")
    print()
    
    # Verificar que son diferentes
    if bytes1 == bytes2:
        print("[!] ADVERTENCIA: Los mensajes son idénticos")
        print("    Esto no es una colisión válida")
    else:
        print("[✓] Los mensajes son diferentes")
    print()
    
    # Verificar hashes
    print("[*] Verificando hashes SHA-3/256...")
    hash1 = verify_sha3_256(bytes1)
    hash2 = verify_sha3_256(bytes2)
    
    print(f"  Hash(msg1): {hash1}")
    print(f"  Hash(msg2): {hash2}")
    print()
    
    if hash1 == hash2:
        print("[✓✓✓] ¡COLISIÓN VERIFICADA!")
        print(f"      Ambos mensajes producen el mismo hash SHA-3/256:")
        print(f"      {hash1}")
        print()
        print("=" * 70)
        print("  ¡FELICITACIONES! Has encontrado una colisión de SHA-3/256")
        print("  Esto es un resultado criptográfico significativo.")
        print("=" * 70)
    else:
        print("[✗] ERROR: Los hashes NO coinciden")
        print("    La solución del solver es incorrecta")
        print("    Esto puede indicar un bug en la codificación CNF")
        sys.exit(1)


if __name__ == "__main__":
    main()
