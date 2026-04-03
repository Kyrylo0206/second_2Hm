import re
import time

MASK64 = 0xFFFFFFFFFFFFFFFF

_TABLE_NAMES = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7',
                'alpha_mul', 'alphainv_mul']

def _load_tables_from_module() -> dict:
    import strumok_tables as _t
    return {name: getattr(_t, name) for name in _TABLE_NAMES}


def _load_tables_from_c(c_file: str) -> dict:
    with open(c_file, encoding='utf-8', errors='replace') as f:
        content = f.read()
    vals = [int(x, 16)
            for x in re.findall(r'0x([0-9a-fA-F]{16})[Uu][Ll][Ll]', content)]
    if len(vals) != 10 * 256:
        raise ValueError(f"Expected 2560 table values, found {len(vals)}.")
    return {name: vals[i * 256:(i + 1) * 256]
            for i, name in enumerate(_TABLE_NAMES)}


class Strumok:
    def __init__(self):
        t = _load_tables_from_module()
        T0, T1, T2, T3 = t['T0'], t['T1'], t['T2'], t['T3']
        T4, T5, T6, T7 = t['T4'], t['T5'], t['T6'], t['T7']
        am = t['alpha_mul']
        aim = t['alphainv_mul']

        def transform_T(x):
            return (T0[x & 0xff] ^ T1[(x >> 8) & 0xff] ^ T2[(x >> 16) & 0xff]
                    ^ T3[(x >> 24) & 0xff] ^ T4[(x >> 32) & 0xff]
                    ^ T5[(x >> 40) & 0xff] ^ T6[(x >> 48) & 0xff] ^ T7[x >> 56])

        def a_mul(x):
            return ((x << 8) & MASK64) ^ am[x >> 56]

        def ainv_mul(x):
            return (x >> 8) ^ aim[x & 0xff]

        self._T = transform_T
        self._a_mul = a_mul
        self._ainv_mul = ainv_mul

    def _fsm(self, x, r1, r2):
        return ((x + r1) & MASK64) ^ r2

    def _clock_init(self, s, r1, r2):
        fsm_out = self._fsm(s[15], r1, r2)
        new_r2 = self._T(r1)
        new_r1 = (r2 + s[13]) & MASK64
        new_s15 = fsm_out ^ self._a_mul(s[0]) ^ self._ainv_mul(s[11]) ^ s[13]
        return s[1:] + [new_s15], new_r1, new_r2

    def _clock_normal(self, s, r1, r2):
        z = self._fsm(s[15], r1, r2) ^ s[0]
        new_r2 = self._T(r1)
        new_r1 = (r2 + s[13]) & MASK64
        new_s15 = self._a_mul(s[0]) ^ self._ainv_mul(s[11]) ^ s[13]
        return z, s[1:] + [new_s15], new_r1, new_r2

    def _load_state_256(self, key, iv):
        K3, K2, K1, K0 = key[0], key[1], key[2], key[3]
        IV3, IV2, IV1, IV0 = iv[0], iv[1], iv[2], iv[3]
        s = [
            K3 ^ IV0,
            K2,
            K1 ^ IV1,
            K0 ^ IV2,
            K3,
            K2 ^ IV3,
            (~K1) & MASK64,
            (~K0) & MASK64,
            K3,
            K2,
            (~K1) & MASK64,
            K0,
            K3,
            (~K2) & MASK64,
            K1,
            (~K0) & MASK64,
        ]
        return s, 0, 0

    def _load_state_512(self, key, iv):
        K7, K6, K5, K4 = key[0], key[1], key[2], key[3]
        K3, K2, K1, K0 = key[4], key[5], key[6], key[7]
        IV3, IV2, IV1, IV0 = iv[0], iv[1], iv[2], iv[3]
        s = [
            K7 ^ IV0,
            K6,
            K5,
            K4 ^ IV1,
            K3,
            K2 ^ IV2,
            K1,
            (~K0) & MASK64,
            K4 ^ IV3,
            (~K6) & MASK64,
            K5,
            (~K7) & MASK64,
            K3,
            K2,
            (~K1) & MASK64,
            K0,
        ]
        return s, 0, 0

    def _init(self, s, r1, r2):
        for _ in range(32):
            s, r1, r2 = self._clock_init(s, r1, r2)
        _, s, r1, r2 = self._clock_normal(s, r1, r2)
        return s, r1, r2

    def init_256(self, key_bytes, iv_bytes):
        key = _bytes_to_words(key_bytes, 4)
        iv = _bytes_to_words(iv_bytes, 4)
        s, r1, r2 = self._load_state_256(key, iv)
        return self._init(s, r1, r2)

    def init_512(self, key_bytes, iv_bytes):
        key = _bytes_to_words(key_bytes, 8)
        iv = _bytes_to_words(iv_bytes, 4)
        s, r1, r2 = self._load_state_512(key, iv)
        return self._init(s, r1, r2)

    def keystream_words(self, s, r1, r2, n):
        out = []
        for _ in range(n):
            z, s, r1, r2 = self._clock_normal(s, r1, r2)
            out.append(z)
        return out, s, r1, r2

    def keystream_bytes(self, s, r1, r2, length):
        n_words = (length + 7) // 8
        words, s, r1, r2 = self.keystream_words(s, r1, r2, n_words)
        buf = b''.join(w.to_bytes(8, 'big') for w in words)
        return buf[:length], s, r1, r2

    def encrypt(self, key_bytes, iv_bytes, plaintext, key_len=256):
        if key_len not in (256, 512):
            raise ValueError(f"key_len must be 256 or 512, got {key_len}")
        if len(key_bytes) != key_len // 8:
            raise ValueError(f"Expected {key_len // 8}-byte key, got {len(key_bytes)}")
        if len(iv_bytes) != 32:
            raise ValueError(f"Expected 32-byte IV, got {len(iv_bytes)}")
        if key_len == 256:
            s, r1, r2 = self.init_256(key_bytes, iv_bytes)
        else:
            s, r1, r2 = self.init_512(key_bytes, iv_bytes)
        ks, *_ = self.keystream_bytes(s, r1, r2, len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, ks))

    def decrypt(self, key_bytes, iv_bytes, ciphertext, key_len=256):
        return self.encrypt(key_bytes, iv_bytes, ciphertext, key_len)

    def benchmark(self, key_len=256, mb=100):
        key = bytes(key_len // 8)
        iv = bytes(32)
        if key_len == 256:
            s, r1, r2 = self.init_256(key, iv)
        else:
            s, r1, r2 = self.init_512(key, iv)

        n_words = mb * 1024 * 1024 // 8
        t0 = time.perf_counter()
        self.keystream_words(s, r1, r2, n_words)
        elapsed = time.perf_counter() - t0
        speed_gbps = (mb * 8) / elapsed / 1000
        return speed_gbps, elapsed


def _bytes_to_words(data, n):
    assert len(data) == n * 8
    return [int.from_bytes(data[i*8:(i+1)*8], 'big') for i in range(n)]


def run_tests(strumok):
    print("Strumok 256 test vectors")

    tests_256 = [
        {
            'K': '8000000000000000' + '0' * 48,
            'IV': '0' * 64,
            'Z': ['e442d15345dc66ca', 'f47d700ecc66408a', 'b4cb284b5477e641', 'a2afc9092e4124b0',
                  '728e5fa26b11a7d9', 'e6a7b9288c68f972', '70eb3606de8ba44c', 'aced7956bd3e3de7'],
        },
        {
            'K': 'aa' * 32,
            'IV': '0' * 64,
            'Z': ['a7510b38c7a95d1d', 'cd5ea28a15b8654f', 'c5e2e2771d0373b2', '98ae829686d5fcee',
                  '45bddf65c523dbb8', '32a93fcdd950001f', '752a7fb588af8c51', '9de92736664212d4'],
        },
        {
            'K': '8000000000000000' + '0' * 48,
            'IV': '0000000000000004' + '0000000000000003' + '0000000000000002' + '0000000000000001',
            'Z': ['fe44a2508b5a2acd', 'af355b4ed21d2742', 'dcd7fdd6a57a9e71', '5d267bd2739fb5eb',
                  'b22eee96b2832072', 'c7de6a4cdaa9a847', '72d5da93812680f2', '4a0acb7e93da2ce0'],
        },
        {
            'K': 'aa' * 32,
            'IV': '0000000000000004' + '0000000000000003' + '0000000000000002' + '0000000000000001',
            'Z': ['e6d0efd9cea5abcd', '1e78ba1a9b0e401e', 'bcfbea2c02ba0781', '1bd375588ae08794',
                  '5493cf21e114c209', '66cd5d7cc7d0e69a', 'a5cdb9f3380d07fa', '2940d61a4d4e9ce4'],
        },
    ]

    all_ok = True
    for i, tv in enumerate(tests_256):
        key = bytes.fromhex(tv['K'])
        iv = bytes.fromhex(tv['IV'])
        s, r1, r2 = strumok.init_256(key, iv)
        got, _, _, _ = strumok.keystream_words(s, r1, r2, 8)
        expected = [int(x, 16) for x in tv['Z']]
        ok = got == expected
        all_ok = all_ok and ok
        print(f"  Test {i+1}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            for j, (g, e) in enumerate(zip(got, expected)):
                if g != e:
                    print(f"    Z{j}: got {g:016x}, expected {e:016x}")

    print()
    print("Strumok 512 test vectors")

    tests_512 = [
        {
            'K': '8000000000000000' + '0' * 112,
            'IV': '0' * 64,
            'Z': ['f5b9ab51100f8317', '898ef2086a4af395', '59571fecb5158d0b', 'b7c45b6744c71fbb',
                  'ff2efcf05d8d8db9', '7a585871e5c419c0', '6b5c4691b9125e71', 'a55be7d2b358ec6e'],
        },
        {
            'K': 'aa' * 64,
            'IV': '0' * 64,
            'Z': ['d2a6103c50bd4e04', 'dc6a21af5eb13b73', 'df4ca6cb07797265', 'f453c253d8d01876',
                  '039a64dc7a01800c', '688ce327dccb7e84', '41e0250b5e526403', '9936e478aa200f22'],
        },
        {
            'K': '8000000000000000' + '0' * 112,
            'IV': '0000000000000004' + '0000000000000003' + '0000000000000002' + '0000000000000001',
            'Z': ['cca12eae8133aaaa', '528d85507ce8501d', 'da83c7fe3e1823f1', '21416ebf63b71a42',
                  '26d76d2bf1a625eb', 'eec66ee0cd0b1efc', '02dd68f338a345a8', '47538790a5411adb'],
        },
        {
            'K': 'aa' * 64,
            'IV': '0000000000000004' + '0000000000000003' + '0000000000000002' + '0000000000000001',
            'Z': ['965648e775c717d5', 'a63c2a7376e92df3', '0b0eb0bbd47ca267', 'ea593d979ae5bd39',
                  'd773b5e5193cafe1', 'b0a26671d259422b', '85b2aa326b280156', '511ace6451435f0c'],
        },
    ]

    for i, tv in enumerate(tests_512):
        key = bytes.fromhex(tv['K'])
        iv = bytes.fromhex(tv['IV'])
        s, r1, r2 = strumok.init_512(key, iv)
        got, _, _, _ = strumok.keystream_words(s, r1, r2, 8)
        expected = [int(x, 16) for x in tv['Z']]
        ok = got == expected
        all_ok = all_ok and ok
        print(f"  Test {i+1}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            for j, (g, e) in enumerate(zip(got, expected)):
                if g != e:
                    print(f"Z{j}:got {g:016x}, expected {e:016x}")

    print()
    return all_ok


def run_benchmark(strumok):
    print("Performance (pure Python)")
    for key_len in (256, 512):
        speed_gbps, _ = strumok.benchmark(key_len, mb=10)
        speed_mbps = speed_gbps * 1000
        print(f"  Strumok-{key_len}: {speed_mbps:.1f} Mbit/s")


if __name__ == '__main__':
    cipher = Strumok()
    ok = run_tests(cipher)
    print("All tests:", "PASS" if ok else "FAIL")
    print()
    run_benchmark(cipher)
