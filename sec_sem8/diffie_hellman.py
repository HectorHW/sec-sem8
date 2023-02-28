from typing import List
import re
import subprocess
from math import gcd
from sec_sem8.primes import get_random


def find_primitive_root(bitness: int, p: int) -> int:
    totient = p - 1
    divisors = list(set(factorize(totient)))
    print(f"totient: {totient}, factors: {divisors}")
    while True:
        g = get_random(bitness)
        if gcd(g, p) != 1:
            continue
        if test_totient_divisors(g, p, totient, divisors):
            return g


def test_totient_divisors(g: int, p: int, totient: int, divisors: List[int]) -> bool:
    for prime_factor in divisors:
        l = totient // prime_factor
        if pow(g, l, p) == 1:
            return False
    return True


def factorize(n: int) -> List[int]:
    completed_process = subprocess.run(
        ["./sqsieve", str(n)], env={"THREADS": "6"}, capture_output=True
    )

    output = completed_process.stdout.decode()
    result = next(
        line.strip()
        for line in output.split("\n")
        if "SUCCESS" in line or "ERROR" in line
    )

    if "number is too big" in result:
        raise ValueError("number is too big to factor")

    if "ERROR" in result:
        return [n]  # as n is prime

    numbers = re.findall(r"\d+", result)
    return list(map(int, numbers))
