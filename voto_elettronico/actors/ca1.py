"""
Modulo per l'attore CA1 (Autorità Identità Reale) del protocollo.

Implementa l'ente fiduciario incaricato di certificare l'esistenza 
dell'identità reale dell'elettore senza conoscerne i dati in chiaro, 
rilasciando il Certificato di Identità.
"""

from voto_elettronico.crypto.rsa_utils import genera_coppia_chiavi, firma_messaggio
from voto_elettronico.crypto.hash_utils import calcola_h1
from voto_elettronico import config


class CA1:
    """Rappresenta l'Autorità per la dimostrazione dell'identità reale.

    Questa CA è rigorosamente disaccoppiata dall'Ente Fisico (che detiene 
    i dati anagrafici) e da CA2 (che gestirà gli pseudonimi). Opera 
    esclusivamente sul digest opaco H0.

    Attributes:
        sk_ca1 (rsa.RSAPrivateKey): Chiave privata per firmare i certificati.
        pk_ca1 (rsa.RSAPublicKey): Chiave pubblica per verificare le firme.
    """

    def __init__(self):
        """Inizializza CA1 generando la propria coppia di chiavi RSA."""
        self.sk_ca1, self.pk_ca1 = genera_coppia_chiavi(config.RSA_KEY_SIZE)

    def emetti_certificato(self, hash_h0: bytes) -> bytes:
        """Emette il Certificato di Identità partendo dall'hash H0.

        Applica un secondo livello di hash (H1) sull'H0 ricevuto per inibire
        correlazioni dirette con il database dell'Ente Fisico, per poi apporre
        la propria firma digitale a garanzia dell'autenticità.

        Args:
            hash_h0 (bytes): Il digest H0 ricevuto dall'Ente Fisico.

        Returns:
            bytes: Il Certificato di Identità firmato (Sign_CA1(H1(H0))).
        """
        # 1. Calcolo dell'hash di secondo livello (H1)
        hash_h1 = calcola_h1(hash_h0)
        
        # 2. Apposizione della firma digitale (RSA-PSS)
        certificato_identita = firma_messaggio(self.sk_ca1, hash_h1)
        
        return certificato_identita
