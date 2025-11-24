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

# example

if __name__ == "__main__":
    import requests
    s = requests.Session()
    s.headers.update({"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"})
    r = s.get("https://newgrounds.com/")
    if r.status_code == 200:
        print("NG Guard didn't detected.")
        print(f"scraped :\n{r.text[:200]}...")
    elif r.status_code == 403:
        r = s.get("https://newgrounds.com/_guard/api/v1/challenge")
        captcha_result = solveChallenge(r.json()["bits"], r.json()["payload"], r.json()["sig"])
        r = s.post("https://newgrounds.com/_guard/api/v1/verify", json=captcha_result)
        if r.json()["ok"] == True:
            r = s.get("https://newgrounds.com/")
            print("Successfully solved captcha.")
            print(f"scraped :\n{r.text[:200]}...")
        else:
            print("Failed to solve captcha.")
    else:
        print("Failed with unknown error.")
