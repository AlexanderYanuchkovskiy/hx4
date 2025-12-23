from time import perf_counter_ns, process_time_ns
from os import getpid

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

def hash_x3(text: str, hash_size=64) -> int:
    primes = [
        11400714819323198549, 14029467366897019727,
        9849436588331569723, 17251063006581978429,
        1181783497276652981, 16687778622034443957,
        8122499608501904533, 7686654374113864019,
        3247399388949857333, 12692087312028222571,
        11248105054058442559, 14933009040333932477,
        17497970288684076713, 18066874198837322347,
        3895657407620216663, 12992637208314873099
    ]

    chars = text.encode('utf-8')
    ln = len(chars)
    dynamic_seed = primes[ln & 0b1111]
    hash_value = dynamic_seed

    if ln % 8 != 0:
        chars += b'\xAA' * (8 - (ln % 8))

    for i in range(0, len(chars), 8):
        chunk = chars[i:i + 8]
        num = int.from_bytes(chunk, 'little')

        s_num = 0
        s_byte = 0
        for shift in range(0, 64, 8):
            byte = (num >> shift) & 0xFF
            s_byte ^= S_BOX[byte]
            s_num |= (s_byte << shift)

        pr_idx = (ln * (i + 5)) & 0b1111
        prime = primes[pr_idx]

        mixed = (s_num * prime) ^ ((s_num >> 32) | (s_num << 32))
        mixed ^= (mixed >> 17) * primes[(pr_idx + 7) & 0b1111]
        mixed += (mixed << 13) ^ primes[(pr_idx + 3) & 0b1111]
        mixed = (mixed >> 11) | (mixed << (64 - 11))

        hash_value ^= mixed
        hash_value = (hash_value * primes[(i // 8) & 0b1111]) + primes[(i // 8 + 5) & 0b1111]

    return hash_value & ((1 << hash_size) - 1)


def hash_x4(text: str, size=128):
    primes = [
        11400714819323198549, 14029467366897019727,
        9849436588331569723, 17251063006581978429,
        1181783497276652981, 16687778622034443957,
        8122499608501904533, 7686654374113864019,
        3247399388949857333, 12692087312028222571,
        11248105054058442559, 14933009040333932477,
        17497970288684076713, 18066874198837322347,
        3895657407620216663, 12992637208314873099
    ]
    chars = text.encode('utf-8')
    ln = len(chars)
    dynamic_seed = primes[ln & 0b1111]
    hash_value = dynamic_seed
    size_mask = (1 << size) - 1
    pr_idx_mask = 0b1111

    if ln % 8 != 0:
        chars += b'\xAA' * (8 - (ln % 8))
        ln = len(chars)

    ln_mod_size = ln & (size - 1)
    size_minus_ln_mod = size - ln_mod_size

    for i in range(0, ln, 8):
        chunk = chars[i:i + 8]
        num = int.from_bytes(chunk, 'little')
        round_key = hash_x3(f'key_{i}_{dynamic_seed}')

        for _ in range(8):
            pr_idx = (ln * (i + _ + 3)) & pr_idx_mask
            prime = primes[pr_idx]
            next_pr_idx = (pr_idx + _ + 4) & pr_idx_mask
            rot_pr_idx = (pr_idx + 15) & pr_idx_mask

            s_num = 0
            for x in range(0, 64, 8):
                byte = (num >> x) & 0xFF
                s_num ^= (S_BOX[byte] << x)

            mixed = (s_num << ln_mod_size) | (s_num >> size_minus_ln_mod)
            mixed ^= (round_key | (round_key << 64))
            mixed ^= ((mixed * prime) << 17) ^ primes[next_pr_idx]
            mixed = (mixed | (mixed >> 13) * primes[rot_pr_idx]) & (mixed - ~round_key)

            rot_bits = (_ + 11) % size
            mixed = ((mixed << rot_bits) | (mixed >> (size - rot_bits))) & size_mask

            num = (mixed ^ dynamic_seed) | (mixed & (dynamic_seed << _))
            dynamic_seed_shift = (dynamic_seed << 10) ^ primes[(pr_idx * 3 + 6) & pr_idx_mask]
            dynamic_seed = (dynamic_seed_shift | (dynamic_seed_shift >> 10)) & 0xFFFFFFFFFFFFFFFF

        hash_value ^= num

    # Final mixing
    pr_idx = (ln * (i + _ + 3)) & pr_idx_mask
    hash_value = (hash_value * primes[(pr_idx + 1) & pr_idx_mask]) + primes[(pr_idx + 11) & pr_idx_mask]
    hash_value = ((hash_value >> 7) | (hash_value << (64 - 7))) & size_mask

    return hash_value & size_mask


def get_rand64(seed: int) -> int:

    def get_time(oper):
        st = perf_counter_ns()
        op_l = oper()
        tm_l = perf_counter_ns() - st
        return tm_l, int(op_l)

    def get_time_arg(oper, arg):
        st = perf_counter_ns()
        op_l = oper(arg)
        tm_l = perf_counter_ns() - st
        return tm_l, op_l

    gt1, tm = get_time_arg(hash_x4, str(seed ** 2))
    gt2, pid = get_time(getpid)
    gt3, uid = get_time_arg(id, pid)

    nano_time = perf_counter_ns()
    process_time = process_time_ns()

    combined = (
            seed ^ tm ^ pid ^ uid ^ nano_time ^ process_time +
            hash_x4(str(gt1)) ^ hash_x4(hex(gt2)) ^ hash_x4(oct(gt3))
    )

    combined = hash_x4(hex(combined))
    combined = (combined >> 32) ^ (combined & 0xFFFFFFFF)
    combined = hash_x4(str(combined + perf_counter_ns()))

    return combined & 0xFFFFFFFFFFFFFFFF


def randint(a: int, b: int) -> int:
    rnd = get_rand64(a*b)
    rnd %= b
    if (rnd < b) and (rnd > a):
        return rnd
    if (rnd + a) > b:
        return a
    else:
        return rnd + a

def random(n: int):
    a = []
    for i in range(n):
        a.append(randint(0, 255))

    return a


from time import sleep

pid = getpid()
with open('mempool.txt', 'w') as file:
	file.write(str(pid)+'\n')
l = []
while True:
	d = random(6)
	b = bytes(d)
	b = int.from_bytes(b, 'big')
	h = hex(get_rand64(b))
	print(h)
	l += [h]
	if len(l) > 512:
		with open('mempool.txt', 'a') as file:
			for el in l:
				file.write(el+'\n')

		l = []
	t = randint(10, 100)
	sleep(t/1000)


