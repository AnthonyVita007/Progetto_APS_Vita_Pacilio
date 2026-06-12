"""
Modulo per le primitive crittografiche RSA del protocollo Vita-Pacilio.

Questo modulo espone le funzioni necessarie per la generazione delle chiavi,
la cifratura randomizzata (RSA-OAEP) e l'apposizione/verifica delle firme
digitali, garantendo le proprietà di segretezza e autenticità.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def genera_coppia_chiavi(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Genera una nuova coppia di chiavi asimmetriche RSA.

    Args:
        key_size (int, optional): Dimensione in bit della chiave. Default a 2048 per bilanciare sicurezza e performance.

    Returns:
        tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]: Una tupla contenente la chiave privata inestraibile e la chiave pubblica associata.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def cifra_oaep(chiave_pubblica: rsa.RSAPublicKey, messaggio: bytes) -> bytes:
    """Cifra un payload in chiaro utilizzando RSA con padding OAEP.
    
    Garantisce la resistenza contro attacchi CPA randomizzando il crittogramma finale.

    Args:
        chiave_pubblica (rsa.RSAPublicKey): La chiave pubblica del destinatario (es. PK_Elezione).
        messaggio (bytes): Il messaggio in chiaro da cifrare.

    Returns:
        bytes: Il crittogramma generato.
    """
    crittogramma = chiave_pubblica.encrypt(
        messaggio,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return crittogramma


def decifra_oaep(chiave_privata: rsa.RSAPrivateKey, crittogramma: bytes) -> bytes:
    """Decifra un crittogramma precedentemente cifrato con padding RSA-OAEP.

    Args:
        chiave_privata (rsa.RSAPrivateKey): La chiave privata del destinatario (es. SK_Elezione ricostruita).
        crittogramma (bytes): Il dato cifrato da processare.

    Returns:
        bytes: Il messaggio decifrato in chiaro.
    """
    messaggio_chiaro = chiave_privata.decrypt(
        crittogramma,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return messaggio_chiaro


def firma_messaggio(chiave_privata: rsa.RSAPrivateKey, messaggio: bytes) -> bytes:
    """Appone una firma digitale su un messaggio utilizzando la chiave privata fornita.
    
    Viene impiegato il padding PSS con digest SHA-256 (equivalente moderno del FDH).

    Args:
        chiave_privata (rsa.RSAPrivateKey): La chiave privata dell'entità firmante (es. SK_CA2).
        messaggio (bytes): Il messaggio originale su cui calcolare l'hash e apporre la firma.

    Returns:
        bytes: La firma digitale generata.
    """
    firma = chiave_privata.sign(
        messaggio,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma


def verifica_firma(chiave_pubblica: rsa.RSAPublicKey, firma: bytes, messaggio: bytes) -> bool:
    """Verifica l'autenticità di una firma digitale rispetto a un messaggio specifico.

    Args:
        chiave_pubblica (rsa.RSAPublicKey): La chiave pubblica presunta dell'entità firmante (es. PK_CA2).
        firma (bytes): La firma digitale da validare.
        messaggio (bytes): Il messaggio su cui è stata calcolata la firma.

    Returns:
        bool: True se la firma è valida e il messaggio integro, False altrimenti.
    """
    try:
        chiave_pubblica.verify(
            firma,
            messaggio,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def calcola_fingerprint_pk(pk: rsa.RSAPublicKey) -> bytes:
    """Calcola l'impronta SHA-256 della rappresentazione PEM di una Public Key."""
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pem)
    return digest.finalize()
