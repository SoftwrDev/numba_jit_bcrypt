import time
from numba import jit
import bcrypt

def check(password: str, password_digest: str):
    return bcrypt.checkpw(
        password.encode(), password_digest.encode()
    )

@jit(forceobj=True, cache=True)
def check_jitted(password: str, password_digest: str) -> bool:
    result = bcrypt.checkpw(
        password.encode(), password_digest.encode()
    )
    return True

def hash(password: str):
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(prefix=b"2b", rounds=5)
    ).decode("utf-8")

@jit(forceobj=True, cache=True)
def hash_jitted(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(prefix=b"2b", rounds=5)
    ).decode("utf-8")

def main():
    start = time.time()
    digest = hash("foobar")
    print(check("foobar", "$2b$10$BW.QFCejUsHeThfhaStArOIvGkeTbzxc2w6.9ZuCW7AtdpwQoVysW"))
    end = time.time()
    print("Normal version: elapsed (after compilation) = %s" % (end - start))

    start = time.time()
    digest = hash_jitted("foobar")
    print(check_jitted("foobar", "$2b$10$BW.QFCejUsHeThfhaStArOIvGkeTbzxc2w6.9ZuCW7AtdpwQoVysW"))
    end = time.time()
    print("Jitted version: elapsed (after compilation) = %s" % (end - start))
    

if __name__ == "__main__":
    main()