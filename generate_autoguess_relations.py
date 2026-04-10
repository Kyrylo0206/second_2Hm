import sys


def generate_64bit_relations(nclocks: int) -> str:
    lines = [f"# Strumok-512 {nclocks} clock cycles (64-bit words)"]
    lines.append("connection relations")

    for t in range(nclocks):
        lines.append(f"S_{16+t}, S_{t}, S_{11+t}, S_{13+t}")
        lines.append(f"z_{t}, S_{15+t}, R_{2*t}, R_{2*t+1}, S_{t}")
        lines.append(f"R_{2*t+2}, R_{2*t+1}, S_{13+t}")
        lines.append(f"R_{2*t+3}, R_{2*t}")

    lines.append("known")
    for t in range(nclocks):
        lines.append(f"z_{t}")
    lines.append("end")
    return "\n".join(lines)+"\n"


def generate_64bit_relations_clean(nclocks: int) -> str:
    lines = [f"# Strumok-512 {nclocks} clock cycles (64-bit words)"]
    lines.append("connection relations")

    for t in range(nclocks):
        s_new = 16+t
        s_0 = t
        s_11 = 11+t
        s_13 = 13+t
        s_15 = 15+t
        r_r1 = 2*t
        r_r2 = 2*t+1
        r_r1_next = 2*t+2
        r_r2_next = 2*t+3

        lines.append(f"S_{s_new}, S_{s_0}, S_{s_11}, S_{s_13}")
        lines.append(f"z_{t}, S_{s_15}, R_{r_r1}, R_{r_r2}, S_{s_0}")
        lines.append(f"R_{r_r1_next}, R_{r_r2}, S_{s_13}")
        lines.append(f"R_{r_r2_next}, R_{r_r1}")

    lines.append("known")
    for t in range(nclocks):
        lines.append(f"z_{t}")
    lines.append("end")
    return "\n".join(lines)+"\n"


def generate_32bit_relations(nclocks: int) -> str:
    lines = [f"# Strumok-512 {nclocks} clock cycles (32-bit words)"]
    lines.append("connection relations")

    for t in range(nclocks):
        s_new = 16+t
        s_0 = t
        s_11 = 11+t
        s_13 = 13+t
        s_15 = 15+t
        r1_idx = 2*t
        r2_idx = 2*t+1
        r1_next = 2*t+2
        r2_next = 2*t+3

        lines.append(f"A_{t}_H, A_{t}_L, S_{s_0}_H, S_{s_0}_L")
        lines.append(f"B_{t}_H, B_{t}_L, S_{s_11}_H, S_{s_11}_L")
        lines.append(f"S_{s_new}_H, A_{t}_H, B_{t}_H, S_{s_13}_H")
        lines.append(f"S_{s_new}_L, A_{t}_L, B_{t}_L, S_{s_13}_L")

        lines.append(f"V_{t}_L, S_{s_15}_L, R_{r1_idx}_L, carry_out_{t}")
        lines.append(f"V_{t}_H, S_{s_15}_H, R_{r1_idx}_H, carry_out_{t}")
        lines.append(f"z_{t}_H, V_{t}_H, R_{r2_idx}_H, S_{s_0}_H")
        lines.append(f"z_{t}_L, V_{t}_L, R_{r2_idx}_L, S_{s_0}_L")

        lines.append(f"R_{r1_next}_L, R_{r2_idx}_L, S_{s_13}_L, carry_r1_{t}")
        lines.append(f"R_{r1_next}_H, R_{r2_idx}_H, S_{s_13}_H, carry_r1_{t}")
        lines.append(f"R_{r2_next}_H, R_{r2_next}_L, R_{r1_idx}_H, R_{r1_idx}_L")

    lines.append("known")
    for t in range(nclocks):
        lines.append(f"z_{t}_H")
        lines.append(f"z_{t}_L")
    lines.append("end")
    return "\n".join(lines)+"\n"


def generate_8bit_relations(nclocks: int) -> str:
    lines = [f"# Strumok-512 {nclocks} clock cycles (8-bit words)"]
    lines.append("connection relations")

    def bytes_of(var):
        return [f"{var}_b{i}" for i in range(8)]

    for t in range(nclocks):
        s_new = 16+t
        s_0 = t
        s_11 = 11+t
        s_13 = 13+t
        s_15 = 15+t
        r1_idx = 2*t
        r2_idx = 2*t+1
        r1_next = 2*t+2
        r2_next = 2*t+3

        a_bytes = bytes_of(f"A_{t}")
        b_bytes = bytes_of(f"B_{t}")
        s0_bytes = bytes_of(f"S_{s_0}")
        s11_bytes = bytes_of(f"S_{s_11}")
        s13_bytes = bytes_of(f"S_{s_13}")
        snew_bytes = bytes_of(f"S_{s_new}")

        lines.append(", ".join(a_bytes+s0_bytes))
        lines.append(", ".join(b_bytes+s11_bytes))
        for i in range(8):
            lines.append(f"{snew_bytes[i]}, {a_bytes[i]}, {b_bytes[i]}, {s13_bytes[i]}")

        s15_bytes = bytes_of(f"S_{s_15}")
        r1_bytes = bytes_of(f"R_{r1_idx}")
        r2_bytes = bytes_of(f"R_{r2_idx}")
        v_bytes = bytes_of(f"V_{t}")
        z_bytes = bytes_of(f"z_{t}")

        lines.append(", ".join(v_bytes+s15_bytes+r1_bytes))
        for i in range(8):
            lines.append(f"{z_bytes[i]}, {v_bytes[i]}, {r2_bytes[i]}, {s0_bytes[i]}")

        r1next_bytes = bytes_of(f"R_{r1_next}")
        lines.append(", ".join(r1next_bytes+bytes_of(f"R_{r2_idx}")+s13_bytes))

        r2next_bytes = bytes_of(f"R_{r2_next}")
        lines.append(", ".join(r2next_bytes+r1_bytes))

    lines.append("known")
    for t in range(nclocks):
        for bname in bytes_of(f"z_{t}"):
            lines.append(bname)
    lines.append("end")
    return "\n".join(lines)+"\n"


def count_vars_relations(content: str):
    variables = set()
    relations = 0
    in_relations = False
    in_known = False
    known_vars = set()

    for line in content.strip().split("\n"):
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if line=="connection relations":
            in_relations = True
            continue
        if line=="known":
            in_relations = False
            in_known = True
            continue
        if line=="end":
            break
        if in_relations:
            vars_in_rel = [v.strip() for v in line.split(",")]
            variables.update(vars_in_rel)
            relations += 1
        elif in_known:
            known_vars.add(line.strip())

    return len(variables), relations, len(known_vars)


def main():
    configs = [
        ("64bit", [8,9,10,11,12,13]),
        ("32bit", [11]),
        ("8bit", [11]),
    ]

    for word_size, clocks_list in configs:
        for nclocks in clocks_list:
            if word_size=="64bit":
                content = generate_64bit_relations_clean(nclocks)
                fname = f"strumok512_{nclocks}clk_{word_size}.txt"
            elif word_size=="32bit":
                content = generate_32bit_relations(nclocks)
                fname = f"strumok512_{nclocks}clk_{word_size}.txt"
            elif word_size=="8bit":
                content = generate_8bit_relations(nclocks)
                fname = f"strumok512_{nclocks}clk_{word_size}.txt"

            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)

            n_vars, n_rels, n_known = count_vars_relations(content)
            print(f"{fname}: {n_vars} vars, {n_rels} relations, "
                  f"{n_known} known vars")


if __name__=="__main__":
    main()
