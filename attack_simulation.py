import time
import sys
from strumok import Strumok, _bytes_to_words

MASK64 = 0xFFFFFFFFFFFFFFFF


def demonstrate_attack(key_hex=None, iv_hex=None):
    cipher = Strumok()

    if key_hex is None:
        key_hex = "80"+"00"*63
    if iv_hex is None:
        iv_hex = "00"*32

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)

    print("PARTIAL GUESSING ATTACK SIMULATION ON STRUMOK-512")
    print()
    print(f"Key : {key.hex()[:32]}...{key.hex()[-8:]}")
    print(f"IV  : {iv.hex()}")

    s_true, r1_true, r2_true = cipher.init_512(key, iv)
    print(f"\nTrue internal state after initialization")
    print(f"LFSR s[0..15]:")
    for i, val in enumerate(s_true):
        print(f"  S_{i:2d} = 0x{val:016x}")
    print(f"FSM  R_0 (r1) = 0x{r1_true:016x}")
    print(f"FSM  R_1 (r2) = 0x{r2_true:016x}")
    print(f"Total internal state: 18*64 = 1152 bits")

    nclocks = 11
    z_words, _, _, _ = cipher.keystream_words(s_true[:], r1_true, r2_true, nclocks)
    print(f"\nKnown keystream ({nclocks} words)")
    for t, z in enumerate(z_words):
        print(f"  z_{t:2d} = 0x{z:016x}")

    guess_basis = {
        "S_0":  s_true[0],
        "S_11": s_true[11],
        "S_12": s_true[12],
        "S_13": s_true[13],
        "S_14": s_true[14],
        "S_15": s_true[15],
        "R_0":  r1_true,
    }

    print(f"\nGuess basis (7*64-bit words = 448 bits)")
    for name, val in guess_basis.items():
        print(f"  {name:5s} = 0x{val:016x}")
    print(f"Attack complexity: 2^{{448}}")
    print(f"(standard claims security level 2^{{512}})")

    print(f"\nSTEP-BY-STEP DETERMINATION OF FULL INTERNAL STATE")
    print()

    T = cipher._T
    a_mul = cipher._a_mul
    ainv_mul = cipher._ainv_mul

    S = {}
    R = {}
    z = {}

    for t in range(nclocks):
        z[t] = z_words[t]

    S[0]  = guess_basis["S_0"]
    S[11] = guess_basis["S_11"]
    S[12] = guess_basis["S_12"]
    S[13] = guess_basis["S_13"]
    S[14] = guess_basis["S_14"]
    S[15] = guess_basis["S_15"]
    R[0]  = guess_basis["R_0"]

    step = 0

    def log_step(desc, var_name, value, verify_value=None):
        nonlocal step
        ok = ""
        if verify_value is not None:
            ok = "+" if value==verify_value else " - MISMATCH!"
        print(f"  Step {step:2d}: {var_name:6s} = 0x{value:016x}  "
              f"<- {desc}{ok}")
        step += 1

    print(f"\n[Clock t=0]")
    R[1] = ((S[15]+R[0])&MASK64) ^ (z[0]^S[0])
    log_step("z_0 = ((S_15 + R_0) ^ R_1) ^ S_0 -> R_1", "R_1", R[1], r2_true)

    R[3] = T(R[0])
    log_step("R_3 = T(R_0)", "R_3", R[3])

    R[2] = (R[1]+S[13])&MASK64
    log_step("R_2 = R_1 + S_13", "R_2", R[2])

    S[16] = a_mul(S[0])^ainv_mul(S[11])^S[13]
    log_step("S_16 = a(S_0) xor ainv(S_11) xor S_13", "S_16", S[16])

    for t in range(1, nclocks):
        print(f"\n[Clock t={t}]")
        s_15_t = 15+t
        r1_t = 2*t
        r2_t = 2*t+1
        r1_next = 2*t+2
        r2_next = 2*t+3
        s_13_t = 13+t
        s_new = 16+t
        s_11_t = 11+t

        S[t] = z[t]^(((S[s_15_t]+R[r1_t])&MASK64)^R[r2_t])
        verify = s_true[t] if t<=15 else None
        log_step(f"z_{t} = ((S_{s_15_t} + R_{r1_t}) ^ R_{r2_t}) ^ S_{t} -> S_{t}",
                 f"S_{t}", S[t], verify)

        R[r1_next] = (R[r2_t]+S[s_13_t])&MASK64
        log_step(f"R_{r1_next} = R_{r2_t} + S_{s_13_t}", f"R_{r1_next}", R[r1_next])

        R[r2_next] = T(R[r1_t])
        log_step(f"R_{r2_next} = T(R_{r1_t})", f"R_{r2_next}", R[r2_next])

        S[s_new] = a_mul(S[t])^ainv_mul(S[s_11_t])^S[s_13_t]
        log_step(f"S_{s_new} = a(S_{t}) xor ainv(S_{s_11_t}) xor S_{s_13_t}",
                 f"S_{s_new}", S[s_new])

    print(f"\nVERIFICATION")
    print()

    all_ok = True
    print("\nRecovered LFSR state vs. true state:")
    for i in range(16):
        recovered = S.get(i)
        true_val = s_true[i]
        ok = recovered==true_val
        all_ok = all_ok and ok
        status = "+" if ok else "- MISMATCH"
        print(f"  S_{i:2d}: recovered=0x{recovered:016x}  "
              f"true=0x{true_val:016x}  {status}")

    r1_recovered = R[0]
    r2_recovered = R[1]
    ok_r1 = r1_recovered==r1_true
    ok_r2 = r2_recovered==r2_true
    all_ok = all_ok and ok_r1 and ok_r2
    print(f"\nRecovered FSM state:")
    print(f"  r1: recovered=0x{r1_recovered:016x}  "
          f"true=0x{r1_true:016x}  {'+' if ok_r1 else '-'}")
    print(f"  r2: recovered=0x{r2_recovered:016x}  "
          f"true=0x{r2_true:016x}  {'+' if ok_r2 else '-'}")

    print(f"\nFull state recovery: {'SUCCESS' if all_ok else 'FAILED'}")

    if all_ok:
        print(f"\nGenerating keystream from recovered state and comparing")
        s_rec = [S[i] for i in range(16)]
        all_z_rec, _, _, _ = cipher.keystream_words(
            s_rec, r1_recovered, r2_recovered, nclocks+8)

        all_z_true, _, _, _ = cipher.keystream_words(
            list(s_true), r1_true, r2_true, nclocks+8)

        print(f"  First {nclocks} words (should match known keystream):")
        for i in range(nclocks):
            ok = all_z_rec[i]==z_words[i]
            all_ok = all_ok and ok
            print(f"    z_{i:2d}: 0x{all_z_rec[i]:016x}  {'+' if ok else '-'}")

        print(f"  Next 8 words (predicted from recovered state):")
        for i in range(nclocks, nclocks+8):
            ok = all_z_rec[i]==all_z_true[i]
            all_ok = all_ok and ok
            print(f"    z_{i:2d}: 0x{all_z_rec[i]:016x}  {'+' if ok else '-'}")

    return all_ok


def benchmark_determination():
    cipher = Strumok()
    T = cipher._T
    a_mul = cipher._a_mul
    ainv_mul = cipher._ainv_mul

    key = bytes(64)
    iv = bytes(32)
    s_true, r1_true, r2_true = cipher.init_512(key, iv)
    z_words, _, _, _ = cipher.keystream_words(s_true[:], r1_true, r2_true, 11)

    guesses = (s_true[0], s_true[11], s_true[12], s_true[13],
               s_true[14], s_true[15], r1_true)

    n_iters = 100000
    t0 = time.perf_counter()

    for _ in range(n_iters):
        S0, S11, S12, S13, S14, S15, R0 = guesses

        R1 = ((S15+R0)&MASK64) ^ (z_words[0]^S0)
        R3 = T(R0)
        R2 = (R1+S13)&MASK64
        S16 = a_mul(S0)^ainv_mul(S11)^S13

        S1 = z_words[1]^(((S16+R2)&MASK64)^R3)
        R4 = (R3+S14)&MASK64
        R5 = T(R2)
        S17 = a_mul(S1)^ainv_mul(S12)^S14

        S2 = z_words[2]^(((S17+R4)&MASK64)^R5)
        R6 = (R5+S15)&MASK64
        R7 = T(R4)
        S18 = a_mul(S2)^ainv_mul(S13)^S15


    elapsed = time.perf_counter()-t0
    rate = n_iters/elapsed
    print(f"\nDetermination benchmark (3 clock steps, {n_iters} iterations):")
    print(f"  Time: {elapsed:.3f} s, Rate: {rate:.0f} det/s")
    print(f"  Full 2^448 search at this rate would take: "
          f"~2^448 / {rate:.0f} seconds (infeasible)")


if __name__=="__main__":
    ok = demonstrate_attack()
    if ok:
        print()
        demonstrate_attack(
            key_hex="aa" * 64,
            iv_hex="00000000000000040000000000000003"
                   "00000000000000020000000000000001"
        )
    print()
    benchmark_determination()
