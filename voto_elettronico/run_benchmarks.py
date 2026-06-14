import argparse
import json
import sys
import base64
import os

# Support execution both as a package (-m voto_elettronico.run_benchmarks)
# and as a script (python run_benchmarks.py)
try:
	from .benchmarks import utils as bench_utils
	from .crypto import rsa_utils, hash_utils, merkle_tree, shamir_sharing
except Exception:
	# If running as a script, ensure the package directory is on sys.path
	sys.path.insert(0, os.path.dirname(__file__))
	from benchmarks import utils as bench_utils
	from crypto import rsa_utils, hash_utils, merkle_tree, shamir_sharing


def bench_hash(iterations: int = 100):
	salt = hash_utils.genera_salt(32)
	cf = "RSSMRA85M01H501U"  # esempio codice fiscale

	t_h0 = bench_utils.measure_time(hash_utils.calcola_h0, cf, salt, iterations=iterations)
	h0 = hash_utils.calcola_h0(cf, salt)
	t_h1 = bench_utils.measure_time(hash_utils.calcola_h1, h0, iterations=iterations)
	h1 = hash_utils.calcola_h1(h0)

	bench_utils.print_benchmark_result("Hash H0 (SHA-256)", t_h0, iterations)
	bench_utils.print_benchmark_result("Hash H1 (SHA-256)", t_h1, iterations)
	bench_utils.print_size_result("H0 size", len(h0))
	bench_utils.print_size_result("H1 size", len(h1))


def bench_rsa(iter_keygen: int = 1, iter_sign: int = 50, iter_verify: int = 50, iter_enc: int = 20):
	# Key generation (costly, keep low iterations)
	t_keygen = bench_utils.measure_time(rsa_utils.genera_coppia_chiavi, iterations=iter_keygen)
	priv, pub = rsa_utils.genera_coppia_chiavi()

	message = b"test message for rsa operations"
	# Signature
	t_sign = bench_utils.measure_time(rsa_utils.firma_messaggio, priv, message, iterations=iter_sign)
	sig = rsa_utils.firma_messaggio(priv, message)
	t_verify = bench_utils.measure_time(rsa_utils.verifica_firma, pub, sig, message, iterations=iter_verify)

	# Encryption / Decryption
	t_enc = bench_utils.measure_time(rsa_utils.cifra_oaep, pub, message, iterations=iter_enc)
	ct = rsa_utils.cifra_oaep(pub, message)
	t_dec = bench_utils.measure_time(rsa_utils.decifra_oaep, priv, ct, iterations=iter_enc)
	pt = rsa_utils.decifra_oaep(priv, ct)

	pem = pub.public_bytes(encoding=rsa_utils.serialization.Encoding.PEM,
						   format=rsa_utils.serialization.PublicFormat.SubjectPublicKeyInfo)

	bench_utils.print_benchmark_result("RSA keygen", t_keygen, iter_keygen)
	bench_utils.print_benchmark_result("RSA sign", t_sign, iter_sign)
	bench_utils.print_benchmark_result("RSA verify", t_verify, iter_verify)
	bench_utils.print_benchmark_result("RSA encrypt (OAEP)", t_enc, iter_enc)
	bench_utils.print_benchmark_result("RSA decrypt (OAEP)", t_dec, iter_enc)

	bench_utils.print_size_result("PublicKey (PEM)", len(pem))
	bench_utils.print_size_result("Signature", len(sig))
	bench_utils.print_size_result("Ciphertext", len(ct))


def bench_merkle(num_leaves: int = 256, iterations: int = 100):
	mt = merkle_tree.MerkleTree()

	# prepare synthetic leaves
	leaves = [f"leaf-{i}".encode('utf-8') for i in range(num_leaves)]

	# measure add_leaf (average)
	def add_all():
		for l in leaves:
			mt.add_leaf(l)

	t_build = bench_utils.measure_time(add_all, iterations=1)
	root = mt.get_root_hash() or b''

	# proof generation and verification for a sample index
	sample_idx = num_leaves // 2
	t_proof = bench_utils.measure_time(mt.get_proof_of_membership, sample_idx, iterations=iterations)
	proof = mt.get_proof_of_membership(sample_idx)
	leaf_hash = merkle_tree.MerkleTree()._hash_pair if False else None
	# compute leaf hash of the sample manually as done in MerkleTree.add_leaf
	from cryptography.hazmat.primitives import hashes
	digest = hashes.Hash(hashes.SHA256())
	digest.update(leaves[sample_idx])
	leaf_h = digest.finalize()

	t_verify = bench_utils.measure_time(merkle_tree.MerkleTree.verify_proof, leaf_h, proof, root, iterations=iterations)

	bench_utils.print_benchmark_result("Merkle build (full)", t_build, 1)
	bench_utils.print_benchmark_result("Merkle proof gen", t_proof, iterations)
	bench_utils.print_benchmark_result("Merkle proof verify", t_verify, iterations)
	bench_utils.print_size_result("Merkle root", len(root))


def bench_shamir(iterations: int = 100):
	# Use a small integer secret for simulation
	secret = 12345678901234567890
	t_split = bench_utils.measure_time(shamir_sharing.split_secret, secret, 2, 3, iterations=iterations)
	shares = shamir_sharing.split_secret(secret, 2, 3)
	t_recover = bench_utils.measure_time(shamir_sharing.recover_secret, shares[:2], iterations=iterations)
	recovered = shamir_sharing.recover_secret(shares[:2])

	bench_utils.print_benchmark_result("Shamir split", t_split, iterations)
	bench_utils.print_benchmark_result("Shamir recover", t_recover, iterations)
	bench_utils.print_size_result("Share payload (approx)", bench_utils.get_payload_size(shares))


def main():
	parser = argparse.ArgumentParser(description="Run crypto benchmarks for the project")
	parser.add_argument("--iterations", type=int, default=100, help="Iterations for fast operations (default: 100)")
	parser.add_argument("--merkle-leaves", type=int, default=256, help="Number of Merkle leaves to simulate")
	args = parser.parse_args()

	print("\n--- Crypto benchmarks: Hashes ---")
	bench_hash(iterations=args.iterations)

	print("\n--- Crypto benchmarks: RSA ---")
	bench_rsa(iter_keygen=1, iter_sign=max(10, args.iterations), iter_verify=max(10, args.iterations), iter_enc=20)

	print("\n--- Data structure benchmarks: Merkle Tree ---")
	bench_merkle(num_leaves=args.merkle_leaves, iterations=max(10, args.iterations))

	print("\n--- Secret sharing benchmarks: Shamir ---")
	bench_shamir(iterations=args.iterations)


if __name__ == "__main__":
	main()

