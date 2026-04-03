#!/usr/bin/env python3
import re
import sys


_NAMES = ['T0', 'T1', 'T2', 'T3', 'T4', 
          'T5', 'T6', 'T7',
          'alpha_mul', 'alphainv_mul']

def parse_tables(c_file: str) -> dict:
    with open(c_file, encoding='utf-8', errors='replace') as f:
        content = f.read()
    vals = [int(x, 16)
            for x in re.findall(r'0x([0-9a-fA-F]{16})[Uu][Ll][Ll]', content)]
    if len(vals) != 10 * 256:
        raise ValueError(f"Expected 2560 values, found {len(vals)}. "
                         f"Check that the C file contains all 10 tables.")
    return {name: vals[i * 256:(i + 1) * 256]
            for i, name in enumerate(_NAMES)}


def write_py(tables: dict, out: str = 'strumok_tables.py') -> None:
    lines = []
    for name, vals in tables.items():
        lines.append(f'{name} = [')
        for i in range(0, 256, 4):
            row = ', '.join(f'0x{v:016x}' for v in vals[i:i + 4])
            lines.append(f'    {row},')
        lines.append(']')
        lines.append('')
    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"Written {out} ({len(tables)} tables × 256 entries)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    tables = parse_tables(sys.argv[1])
    write_py(tables)
