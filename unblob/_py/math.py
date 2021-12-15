import math


def shannon_entropy(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    ent = 0.0

    for c in counts:
        if c == 0:
            continue
        p = c / len(data)
        ent -= p * math.log(p, 2)

    return ent
