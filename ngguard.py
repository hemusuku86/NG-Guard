import hashlib
import base64
import time

def H(buf):
    e = 0
    for r in buf:
        if r == 0:
            e += 8
        else:
            e += (len(bin(r)[2:].rjust(32, "0")) - len(bin(r)[2:])) - 24
            break
    return e

def solveChallenge(bits, payload, signature):
    start = int(time.time()*1000)
    s = base64.urlsafe_b64decode(payload + ("=" * (len(payload) % 4)))
    g = [0] * (len(s) + 1 + 20)
    g[0:len(s)] = list(s)
    g[len(s)] = ord(":")
    l = 0
    while True:
        E = str(l)
        b = [ord(b) for b in E]
        w = len(s) + 1 + len(E)
        if w > len(g):
            h = [0] * w
            h = g[:len(s)+1] + h[len(g[:len(s)+1]):]
            g = h
        g[len(s)+1:len(s)+1+len(b)] = b
        S = hashlib.sha256(bytes(g[:w])).digest()
        if H(S) >= bits:
            return {
                "bits": bits,
                "demo": False,
                "nonce": str(l),
                "payload": payload,
                "sig": signature,
                "solveTimeMs": int(time.time()*1000) - start
            }
        l += 1

if __name__ == "__main__":
    print(solveChallenge(16, "MTc2Mzk2MzEzNzYyMXxlYTNhNmI5ZA", "DAaw3r2BKyHS2R5sYB9DJFnFnYoG-cExJQuKIm8bjMo"))
