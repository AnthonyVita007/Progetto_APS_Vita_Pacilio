"""
Modulo Utente: crea chiavi, genera pacchetti di voto e gestisce l'autenticazione
con CA2.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from voto_elettronico.crypto.rsa_utils import genera_coppia_chiavi, cifra_oaep, decifra_oaep, calcola_fingerprint_pk
from voto_elettronico.crypto.hash_utils import calcola_h0
from voto_elettronico import config


class Utente:
    """Rappresenta un elettore che partecipa alla procedura.

    L'utente genera una coppia di chiavi per il pseudonimo e può creare il
    pacchetto di voto cifrato destinato alla Commissione.
    """

    def __init__(self, dati_anagrafici: dict):
        self.sk, self.pk = genera_coppia_chiavi(config.RSA_KEY_SIZE)
        self.dati = dati_anagrafici

    def serializza_pk(self) -> bytes:
        return self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def crea_pacchetto_voto(self, voto: str, pk_elezione) -> tuple[bytes, bytes]:
        """Crea il pacchetto di voto cifrato.

        Invece di cifrare l'intera chiave pubblica della Commissione (PEM) con OAEP
        (che può superare la dimensione massima consentita), cifriamo l'impronta
        SHA-256 della chiave pubblica. Il pacchetto contiene:
            - utente_enc: cifratura dell'impronta PK_Utente con PK_CA2 (OAEP)
            - voto_enc: cifratura del voto con PK_Elezione (OAEP)

        Args:
            voto (str): La scelta dell'elettore.
            pk_elezione: La chiave pubblica dell'elezione.

        Returns:
            tuple[bytes, bytes]: (utente_enc, voto_enc)
        """
        # 1. Calcolo impronta della PK dell'elettore
        fingerprint = calcola_fingerprint_pk(self.pk)

        # 2. cifratura dell'impronta con PK_CA2 (in simulazione useremo PK_Elezione per semplicità)
        utente_enc = cifra_oaep(pk_elezione, fingerprint)

        # 3. cifratura del voto
        voto_enc = cifra_oaep(pk_elezione, voto.encode('utf-8'))

        return utente_enc, voto_enc
