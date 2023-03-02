from math import ceil


class RC4:
    def __init__(self, key: int) -> None:
        self.state = list(range(256))
        j = 0
        key_bytelen = ceil(key.bit_count() / 8)
        key_bytes = key.to_bytes(256, byteorder="little")
        for self.i in range(255):
            self.j = (j + self.state[self.i] + key_bytes[self.i % key_bytelen]) % 256
            self._swap()

        self.i = 0
        self.j = 0

    def __iter__(self):
        return self

    def _swap(self):
        self.state[self.i], self.state[self.j] = self.state[self.j], self.state[self.i]

    def __next__(self) -> int:
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.state[self.i]) % 256
        self._swap()
        k = self.state[(self.state[self.i] + self.state[self.j]) % 256]
        return k

    def produce_gamma(self, size: int) -> bytes:
        return bytes([next(self) for _ in range(size)])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([aa ^ bb for aa, bb in zip(a, b)])


if __name__ == "__main__":
    rc = RC4(123)
    for _ in range(10):
        print(next(rc))
    print(rc.produce_gamma(10))
