 import timeit, statistics
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


# =========================
# Config
# =========================
MSG = b"A" * 1024
REPEATS = 10
LOOPS = 2000
LOOPS_KEYGEN = 500


# =========================
# Warmup + Bootstrap
# =========================

def warmup(fn, loops=200):
    """Rulează funcția de câteva ori pentru a încălzi cache-ul CPU."""
    for _ in range(loops):
        fn()


def bootstrap_ci(data, n_iter=1000):
    """Calculează intervalul de încredere 95% prin bootstrap."""
    rng = np.random.default_rng()
    means = [
        np.mean(rng.choice(data, size=len(data), replace=True))
        for _ in range(n_iter)
    ]
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


# =========================
# Măsurare timp
# =========================

def measure(fn, loops, repeats=REPEATS):
    warmup(fn)

    raw_times = timeit.repeat(fn, number=loops, repeat=repeats)
    per_call_ms = [(t / loops) * 1000.0 for t in raw_times]

    ci_low, ci_high = bootstrap_ci(per_call_ms)

    return {
        "loops": loops,
        "repeats": repeats,
        "mean_ms": statistics.mean(per_call_ms),
        "stdev_ms": statistics.pstdev(per_call_ms),
        "min_ms": min(per_call_ms),
        "max_ms": max(per_call_ms),
        "ci95_low": ci_low,
        "ci95_high": ci_high,
    }


# =========================
# Verificare corectitudine
# =========================

def verify_correctness():
    """Verifică Ed25519 și X25519 înainte de benchmark."""
    msg = b"test message"

    # Ed25519: semnătură validă + respingere semnătură coruptă
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(msg)
    pub.verify(sig, msg)  # trebuie să nu arunce

    bad = bytearray(sig)
    bad[0] ^= 0xFF
    try:
        pub.verify(bytes(bad), msg)
        raise Exception("Semnatura corupta a fost acceptata!")
    except Exception:
        pass  # corect: trebuie să arunce

    # X25519: secrete comune egale
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    secret_a = a.exchange(b.public_key())
    secret_b = b.exchange(a.public_key())
    assert secret_a == secret_b, "X25519: secretele comune nu coincid"


# =========================
# Key / signature sizes
# =========================

def sizes_ed25519():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    sig = priv.sign(b"test")

    return {
        "algorithm": "Ed25519 (Edwards)",
        "private_key_bytes": len(priv_raw),
        "public_key_bytes": len(pub_raw),
        "output_bytes": len(sig),
    }


def sizes_x25519():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    peer = x25519.X25519PrivateKey.generate().public_key()
    shared = priv.exchange(peer)

    return {
        "algorithm": "X25519 (Montgomery)",
        "private_key_bytes": len(priv_raw),
        "public_key_bytes": len(pub_raw),
        "output_bytes": len(shared),
    }


# =========================
# Main benchmark
# =========================

def main():

    # === Folder rezultate ===
    OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rezultate_benchmark")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Fișierele vor fi salvate în:", os.path.abspath(OUTPUT_DIR))

    # verificare corectitudine înainte de măsurători
    verify_correctness()

    rows = []

    # =========================
    # Ed25519
    # =========================

    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_sig = ed_priv.sign(MSG)

    rows.append({
        "algorithm": "Ed25519 (Edwards)",
        "operation": "keygen",
        **measure(lambda: ed25519.Ed25519PrivateKey.generate(), loops=LOOPS_KEYGEN)
    })

    rows.append({
        "algorithm": "Ed25519 (Edwards)",
        "operation": "sign",
        **measure(lambda: ed_priv.sign(MSG), loops=LOOPS)
    })

    rows.append({
        "algorithm": "Ed25519 (Edwards)",
        "operation": "verify",
        **measure(lambda: ed_pub.verify(ed_sig, MSG), loops=LOOPS)
    })

    # =========================
    # X25519 (Montgomery)
    # =========================

    x_priv = x25519.X25519PrivateKey.generate()
    peer_priv = x25519.X25519PrivateKey.generate()
    peer_pub = peer_priv.public_key()

    rows.append({
        "algorithm": "X25519 (Montgomery)",
        "operation": "keygen",
        **measure(lambda: x25519.X25519PrivateKey.generate(), loops=LOOPS_KEYGEN)
    })

    rows.append({
        "algorithm": "X25519 (Montgomery)",
        "operation": "shared_secret",
        **measure(lambda: x_priv.exchange(peer_pub), loops=LOOPS)
    })

    # =========================
    # Save benchmark results
    # =========================

    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(OUTPUT_DIR, "bench_results.csv"), index=False)

    print("\n=== Benchmark results (ms per call) ===")
    print(df[["algorithm", "operation", "mean_ms", "stdev_ms", "min_ms", "max_ms",
              "ci95_low", "ci95_high"]])

    # =========================
    # Key sizes
    # =========================

    sdf = pd.DataFrame([
        sizes_ed25519(),
        sizes_x25519()
    ])

    sdf.to_csv(os.path.join(OUTPUT_DIR, "sizes.csv"), index=False)

    print("\n=== Key / output sizes (bytes) ===")
    print(sdf)

    # =========================
    # Plot
    # =========================

    pivot = df.pivot(index="operation", columns="algorithm", values="mean_ms")

    ax = pivot.plot(kind="bar")

    ax.set_ylabel("Mean time (ms)")
    ax.set_title("ECC Benchmark: Ed25519 (Edwards) vs X25519 (Montgomery)")

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "bench_plot.png"), dpi=200)
    plt.show()


if __name__ == "__main__":
    main()
