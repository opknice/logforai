import re
import os

# =========================
# 📦 LOAD PACKET DB
# =========================
def load_packet_db(file_path):
    recv_db = {}
    send_db = {}
    current = None

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if line == "[Recv]":
                current = recv_db
                continue
            elif line == "[Send]":
                current = send_db
                continue

            if not line or current is None:
                continue

            parts = line.split(" ", 1)
            if len(parts) == 2:
                opcode_hex, name = parts
                try:
                    opcode = int(opcode_hex, 16)
                    current[opcode] = name.strip()
                except:
                    pass

    return recv_db, send_db


# =========================
# CORE
# =========================
def parse_byte_array(s):
    hex_values = re.findall(r'0x([0-9A-Fa-f]{2})', s)
    return bytes(int(h, 16) for h in hex_values)


def get_opcode(data):
    if len(data) < 2:
        return None
    return data[0] | (data[1] << 8)


def extract_strings(data):
    result = []
    current = b''

    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) >= 4:
                result.append(current.decode())
            current = b''

    if len(current) >= 4:
        result.append(current.decode())

    return result


# =========================
# PROCESS LOG
# =========================
def process_log(input_file, output_file, recv_db, send_db):
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    output = []
    pattern = re.compile(r'ByteArray:\s*\{([^}]*)\}')

    for i, line in enumerate(lines):
        output.append(line.rstrip())

        m = pattern.search(line)
        if m:
            byte_str = m.group(1)

            try:
                data = parse_byte_array(byte_str)
                opcode = get_opcode(data)

                # 🔥 detect direction
                direction = ""
                if "[C->S]" in lines[i-1]:
                    direction = "send"
                elif "[S->C]" in lines[i-1]:
                    direction = "recv"

                # 🔥 lookup
                name = "UNKNOWN"
                if direction == "send":
                    name = send_db.get(opcode, "UNKNOWN")
                elif direction == "recv":
                    name = recv_db.get(opcode, "UNKNOWN")

                # 🔥 string extract
                strings = extract_strings(data)

                output.append(f"         OPCODE : 0x{opcode:04X} ({name})")

                if strings:
                    output.append(f"         STRING : {' | '.join(strings)}")
                else:
                    output.append(f"         STRING : -")

            except Exception as e:
                output.append(f"         ERROR : {e}")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output))


# =========================
# RUN
# =========================
if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))

    input_file = os.path.join(base, "analysis.log")
    output_file = os.path.join(base, "analysis_outstring.log")
    packet_file = os.path.join(base, "packetdescriptions.txt")

    recv_db, send_db = load_packet_db(packet_file)

    process_log(input_file, output_file, recv_db, send_db)

    print("✅ DONE (PRO MODE)")