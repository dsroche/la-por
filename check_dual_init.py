#!/usr/bin/env python3

from sys import argv

P57 = 144115188075855859

def read8(f):
    return int.from_bytes(f.read(8), byteorder='little', signed=False)

def read7(f):
    return int.from_bytes(f.read(7), byteorder='little', signed=False)

def main(datfile, clifile):
    df = open(datfile, 'rb')
    cf = open(clifile, 'rb')

    n = read8(cf)
    m = read8(cf)
    print('n = ', n)
    print('m = ', m)

    r = []
    for _ in range(m):
        r.append(read8(cf))

    s = []
    for _ in range(n):
        s.append(read8(cf))

    assert cf.read() == b''

    M = []
    for _ in range(m):
        row = []
        for _ in range(n):
            row.append(read7(df))
        M.append(row)

    s2 = [sum(ri * Mi[k] for (ri, Mi) in zip(r,M)) % P57 for k in range(n)]

    print(s == s2)

if __name__ == '__main__':
    main(argv[1], argv[2])
