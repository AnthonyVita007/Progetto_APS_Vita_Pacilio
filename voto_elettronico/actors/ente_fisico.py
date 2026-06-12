"""
Modulo per l'Ente Fisico (anagrafe) nel protocollo.

Fornisce i dati anagrafici necessari per certificare l'esistenza fisica 
dell'elettore e calcola l'hash H0 che verrà passato a CA1.
"""

from voto_elettronico.crypto.hash_utils import genera_salt, calcola_h0


class EnteFisico:
    """Rappresenta l'anagrafe che produce H0 dall'identità reale.

    Questa classe non memorizza né espone dati in chiaro: restituisce soltanto
    l'H0 (salt || Hash(nome||codice_fiscale||...)).
    """

    def __init__(self):
        pass

    def calcola_h0_per_elektor(self, dati_anagrafici: dict) -> bytes:
        """Calcola H0 a partire dai dati anagrafici forniti.

        Args:
            dati_anagrafici (dict): Dizionario con i campi anagrafici dell'utente.

        Returns:
            bytes: L'H0 (digest + salt) da consegnare a CA1.
        """
        salt = genera_salt()
        # Serializziamo i campi in modo ordinato e stabile
        payload = "||".join(str(dati_anagrafici[k]) for k in sorted(dati_anagrafici.keys()))
        return calcola_h0(payload, salt)
