# Shared infrastructure for QNAP firmware handlers.

FOOTER_LEN = 74

C_DEFINITIONS = """
    typedef struct qnap_header {
        char    magic[6];
        uint32  encrypted_len;
        char    device_id[16];
        char    file_version[16];
        char    firmware_date[16];
        char    revision[16];
    } qnap_header_t;
"""


# https://gist.github.com/ulidtko/966277a465f1856109b2d2674dcee741#file-qnap-qts-fw-cryptor-py-L114
class Cryptor:
    def __init__(self, secret):
        self.secret = list(bytes(secret, "ascii"))
        self.n = len(secret) // 2
        if self.n % 2 == 0:
            self.secret.append(0)
        self.precompute_k()
        self.acc = 0
        self.y = 0
        self.z = 0

    def scan(self, f, xs, s0):
        s = s0
        for x in xs:
            w, s = f(s, x)
            yield w

    def promote(self, char):
        return char if char < 0x80 else char - 0x101

    def precompute_k(self):
        self.k = {acc: self.table_for_acc(acc) for acc in range(256)}

    def table_for_acc(self, a):
        ks = [
            0xFFFFFFFF
            & (
                (self.promote(self.secret[2 * i] ^ a) << 8)
                + (self.secret[2 * i + 1] ^ a)
            )
            for i in range(self.n)
        ]

        def kstep(st, q):
            x = st ^ q
            y = self.lcg(x)
            z = 0xFFFF & (0x15A * x)
            return (z, y), y

        return list(self.scan(kstep, ks, 0))

    def lcg(self, x):
        return 0xFFFF & (0x4E35 * x + 1)

    def kdf(self):
        """self.secret -> 8bit hash (+ state effects)."""
        tt = self.k[self.acc]
        res = 0
        for i in range(self.n):
            yy = self.y
            self.y, t2 = tt[i]
            self.z = 0xFFFF & (self.y + yy + 0x4E35 * (self.z + i))
            res = res ^ t2 ^ self.z
        hi, lo = res >> 8, res & 0xFF
        return hi ^ lo

    def decrypt_byte(self, v):
        k = self.kdf()
        r = 0xFF & (v ^ k)
        self.acc = self.acc ^ r
        return r

    def decrypt_chunk(self, chunk):
        return bytes(map(self.decrypt_byte, chunk))
