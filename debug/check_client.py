#!/usr/bin/env python3

import socket
from sys import argv

P57 = 144115188075855859

def recv8(f):
    return int.from_bytes(f.recv(8), byteorder='little', signed=False)

def read8(f):
    return int.from_bytes(f.read(8), byteorder='little', signed=False)

def read7(f):
    return int.from_bytes(f.read(7), byteorder='little', signed=False)

def main(datfile, clifile, port):
    df = open(datfile, 'rb')
    cf = open(clifile, 'rb')

    n = read8(cf)
    m = read8(cf)
    print('n = ', n)
    print('m = ', m)

    r = []
    for _ in range(m):
        r.append(read8(cf))

    secret = []
    for _ in range(n):
        secret.append(read8(cf))

    assert cf.read() == b''

    M = []
    for _ in range(m):
        row = []
        for _ in range(n):
            row.append(read7(df))
        M.append(row)

    #s2 = [sum(ri * Mi[k] for (ri, Mi) in zip(r,M)) % P57 for k in range(n)]
    #print(secret == s2)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        print('listening on port {}...'.format(port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('connected')
            cmd = conn.recv(1)
            assert cmd == b'A'
            challenge = []
            for _ in range(n):
                challenge.append(recv8(conn))
            print('got challenge vector')
            print('challenge[0] =', challenge[0])
            print('challenge[n-1] =', challenge[n-1])
            conn.sendall(b'1')

            resp = [sum(Mik * ci for (Mik, ci) in zip(Mi, challenge)) % P57 for Mi in M]
            print("response computed")
            for x in resp:
                conn.sendall(x.to_bytes(8, byteorder='little', signed=False))
            print("response sent")
            recv8(conn) # comm time, read but ignored

            rxr = sum(a*b for (a,b) in zip(r, resp)) % P57
            sxc = sum(a*b for (a,b) in zip(secret,challenge)) % P57
            print("rxr =", rxr)
            print("sxc =", sxc)


if __name__ == '__main__':
    datfile = argv[1]
    clifile = argv[2]
    try:
        port = int(argv[3])
    except IndexError:
        port = 2020
    main(datfile, clifile, port)
