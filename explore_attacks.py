#!/usr/bin/env python3

import os
import sys
from generate_autoguess_relations import generate_64bit_relations_clean,generate_32bit_relations,generate_8bit_relations,count_vars_relations


def analyze_configuration(name, content, word_bits):
    n_vars, n_rels, n_known = count_vars_relations(content)
    n_unknowns = n_vars-n_known

    print(f"  {name}:")
    print(f"    Variables: {n_vars} ({n_unknowns} unknown, {n_known} known)")
    print(f"    Relations: {n_rels}")
    print(f"    Word size: {word_bits} bits")
    print(f"    Total unknown bits: {n_unknowns*word_bits}")
    print(f"    Available constraints (relations): {n_rels}")

    if n_rels>=n_unknowns:
        print(f"    System is (potentially) over-determined: "
              f"{n_rels} relations >= {n_unknowns} unknowns")
        print(f"    Lower bound on guesses: 0 (may be fully determined)")
    else:
        deficit = n_unknowns-n_rels
        print(f"    System under-determined: deficit = {deficit} words")
        print(f"    Lower bound on guesses: {deficit} words "
              f"= {deficit*word_bits} bits")
        print(f"    Upper bound complexity: 2^{deficit*word_bits}")


def generate_all_files():
    output_dir = "autoguess_configs"
    os.makedirs(output_dir, exist_ok=True)

    print("AUTOGUESS EXPLORATION FOR STRUMOK-512")
    print()

    print()
    print("64-bit word configurations")
    for nclocks in [8,9,10,11,12,13,14,15]:
        content = generate_64bit_relations_clean(nclocks)
        fname = os.path.join(output_dir,
                             f"strumok512_{nclocks}clk_64bit.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        analyze_configuration(
            f"{nclocks} clocks / 64-bit", content, 64)

    print("\n32-bit word configurations")
    for nclocks in [11,12,13]:
        content = generate_32bit_relations(nclocks)
        fname = os.path.join(output_dir,
                             f"strumok512_{nclocks}clk_32bit.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        analyze_configuration(
            f"{nclocks} clocks / 32-bit", content, 32)

    print("\n8-bit word configurations")
    for nclocks in [11,12]:
        content = generate_8bit_relations(nclocks)
        fname = os.path.join(output_dir,
                             f"strumok512_{nclocks}clk_8bit.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        analyze_configuration(
            f"{nclocks} clocks / 8-bit", content, 8)

    print()
    print("SUMMARY OF GENERATED FILES")
    print()
    for fname in sorted(os.listdir(output_dir)):
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "r") as f:
            content = f.read()
        n_vars, n_rels, n_known = count_vars_relations(content)
        print(f"  {fname}: {n_vars} vars, {n_rels} rels, {n_known} known")

    print()
    print("THEORETICAL ANALYSIS")
    print()
    print("""
strumok-512 стан, 18x64=1152 біт
lfsr, 16x64-біт (s[0]..s[15])
fsm, 2x64-біт (r1,r2)

заявлена стійкість, 2^512

11 тактів, 64-біт слова,

11 відомих рівнянь + 33 внутрішніх = 44 всього
51 невідома змінна
мінімальний базис вгадування, 7 слів
складність, 7*64=448 біт, 2^448 < 2^512

базис {s_0,s_11,s_12,s_13,s_14,s_15,r_0},
s_0 і r_0 -> вихід fsm при t=0
s_11-s_15 -> коефіцієнти зворотного зв'язку lfsr
кожне z_t розкриває одну невідому комірку s_t
fsm повністю визначається після початкового стану

менші розміри слів,
32біт, перенесення додавання дають додаткові обмеження
8біт, ще більше обмежень від ланцюжків переносу
атака < 2^448

більше тактів (12-15),
додатковий такт, +1 відоме +4 нових рівняння +4 невідомих
на 64біт рівні ефект 0, але більше рівнянь допомагає sat/cp
""")


def verify_with_propagation():
    print()
    print("KNOWLEDGE PROPAGATION SIMULATION")
    print()

    nclocks=11

    content=generate_64bit_relations_clean(nclocks)

    relations=[]
    known_vars=set()

    parsing_rels=False
    parsing_known=False
    for line in content.strip().split("\n"):
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        if line=="connection relations":
            parsing_rels=True
            continue
        if line=="known":
            parsing_rels=False
            parsing_known=True
            continue
        if line=="end":
            break
        if parsing_rels:
            vars_in_rel=[v.strip() for v in line.split(",")]
            relations.append(vars_in_rel)
        elif parsing_known:
            known_vars.add(line.strip())

    guess_bases=[
        ("Basis A", ["S_0","S_11","S_12","S_13","S_14","S_15","R_0"]),
        ("Basis B", ["S_0","R_0","R_1","S_13","S_14","S_15","S_11"]),
        ("Basis C", ["R_0","R_1","S_0","S_1","S_2","S_3","S_4"]),
        ("Basis D (6 vars)", ["S_0","S_11","S_12","S_13","S_14","R_0"]),
        ("Basis E (8 vars)", ["S_0","S_11","S_12","S_13","S_14","S_15","R_0","R_1"]),
    ]

    all_vars=set()
    for rel in relations:
        all_vars.update(rel)
    all_vars.update(known_vars)

    for basis_name, guessed in guess_bases:
        known=set(known_vars)
        known.update(guessed)

        steps=0
        max_steps=100
        changed=True
        while changed and steps<max_steps:
            changed=False
            for rel in relations:
                unknown_in_rel=[v for v in rel if v not in known]
                if len(unknown_in_rel)==1:
                    known.add(unknown_in_rel[0])
                    changed=True
            steps+=1

        n_determined=len(known)-len(known_vars)-len(guessed)
        n_total=len(all_vars)-len(known_vars)
        n_remaining=n_total-len(guessed)-n_determined

        total_known=len(known)
        status="FULL" if total_known==len(all_vars) else "PARTIAL"

        guess_bits=len(guessed)*64
        print(f"\n  {basis_name}: guessed {len(guessed)} vars ({guess_bits} bits)")
        print(f"    Determined: {n_determined} more variables in {steps} steps")
        print(f"    Total known: {total_known}/{len(all_vars)} "
              f"({status} determination)")
        if n_remaining>0:
            print(f"    Remaining unknown: {n_remaining} variables")
            remaining=[v for v in sorted(all_vars) if v not in known]
            print(f"    Undetermined: {', '.join(remaining[:20])}")


if __name__=="__main__":
    generate_all_files()
    verify_with_propagation()
