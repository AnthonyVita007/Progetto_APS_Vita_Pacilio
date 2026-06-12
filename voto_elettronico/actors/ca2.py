"""
Modulo per l'attore CA2 (Autorità Identità Digitale) del protocollo.

Implementa l'ente fiduciario incaricato di gestire gli pseudonimi digitali
degli elettori. Si occupa di validare i certificati emessi da CA1, generare
i token di voto firmati e autenticare gli utenti tramite un protocollo
Challenge-Response (standard FIDO2) per prevenire Replay Attacks.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from voto_elettronico.crypto.rsa_utils import genera_coppia_chiavi, firma_messaggio, verifica_firma
from voto_elettronico import config


class CA2:
    """Rappresenta l'Autorità per la dimostrazione dell'Identità Digitale.

    Mantiene il disaccoppiamento con l'identità reale gestendo esclusivamente
    le chiavi pubbliche degli utenti (pseudonimi). Mappa rigorosamente ogni
    pseudonimo a un singolo token per inibire il double-spending alla radice.

    Attributes:
        sk_ca2 (rsa.RSAPrivateKey): Chiave privata per firmare i token e decifrare pacchetti.
        pk_ca2 (rsa.RSAPublicKey): Chiave pubblica dell'Autorità.
        database_pseudonimi (dict[bytes, bytes]): Mappa la chiave pubblica dell'utente (serializzata) al suo Token.
        sfide_attive (dict[bytes, bytes]): Mappa lo pseudonimo al Nonce attuale (Challenge FIDO2).
    """

    def __init__(self):
        """Inizializza CA2 generando le chiavi RSA e i database in memoria."""
        self.sk_ca2, self.pk_ca2 = genera_coppia_chiavi(config.RSA_KEY_SIZE)
        self.database_pseudonimi: dict[bytes, bytes] = {}
        self.sfide_attive: dict[bytes, bytes] = {}

    def _serializza_pk(self, pk_utente: rsa.RSAPublicKey) -> bytes:
        """Serializza una chiave pubblica in bytes per poterla usare come chiave nei dizionari.

        Args:
            pk_utente (rsa.RSAPublicKey): La chiave pubblica da serializzare.

        Returns:
            bytes: Rappresentazione PEM della chiave pubblica.
        """
        return pk_utente.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def registra_pseudonimo_e_genera_token(
        self,
        pk_utente: rsa.RSAPublicKey,
        certificato_ca1: bytes,
        hash_h1_atteso: bytes,
        pk_ca1: rsa.RSAPublicKey
    ) -> tuple[bytes, bytes]:
        """Esegue la Registration Ceremony per lo pseudonimo digitale.

        Verifica che l'utente sia stato autorizzato da CA1 controllandone la firma.
        Se valido e non duplicato, registra lo pseudonimo e rilascia un Token
        monouso firmato.

        Args:
            pk_utente (rsa.RSAPublicKey): Lo pseudonimo digitale dell'elettore.
            certificato_ca1 (bytes): La firma di CA1 sul digest dell'utente.
            hash_h1_atteso (bytes): L'hash H1 in chiaro per validare la firma di CA1.
            pk_ca1 (rsa.RSAPublicKey): La chiave pubblica di CA1 per la verifica.

        Raises:
            ValueError: Se la firma del certificato non è valida.
            ValueError: Se lo pseudonimo risulta già registrato.

        Returns:
            tuple[bytes, bytes]: Una tupla contenente il token in chiaro e la sua 
            versione firmata digitalmente da CA2 (Token_Signed).
        """
        # 1. Verifica dell'autenticità del Certificato di Identità
        is_valid = verifica_firma(pk_ca1, certificato_ca1, hash_h1_atteso)
        if not is_valid:
            raise ValueError("Validazione fallita: Certificato CA1 non autentico o manomesso.")

        pk_bytes = self._serializza_pk(pk_utente)

        # 2. Controllo Unicità (Prevenzione identità duplicate/multi-voto)
        if pk_bytes in self.database_pseudonimi:
            raise ValueError("Pseudonimo già registrato. Tentativo di registrazione multipla bloccato.")

        # 3. Generazione e salvataggio Token Monouso (32 bytes = 256 bits)
        token = os.urandom(32)
        self.database_pseudonimi[pk_bytes] = token

        # 4. Apposizione della firma di CA2 sul token per garantirne l'origine
        token_signed = firma_messaggio(self.sk_ca2, token)

        return token, token_signed

    def genera_challenge(self, pk_utente: rsa.RSAPublicKey) -> bytes:
        """Genera una challenge (nonce) per l'Authentication Ceremony (FIDO2).

        Args:
            pk_utente (rsa.RSAPublicKey): Lo pseudonimo che richiede l'accesso.

        Raises:
            KeyError: Se lo pseudonimo non è presente nel database.

        Returns:
            bytes: Un nonce crittografico casuale di 16 bytes.
        """
        pk_bytes = self._serializza_pk(pk_utente)
        
        if pk_bytes not in self.database_pseudonimi:
            raise KeyError("Accesso Negato: Pseudonimo non riconosciuto da CA2.")

        # Genera un Nonce fresco per garantire la validità limitata alla sessione
        nonce = os.urandom(16)
        self.sfide_attive[pk_bytes] = nonce
        
        return nonce

    def verifica_challenge(self, pk_utente: rsa.RSAPublicKey, firma_challenge: bytes) -> bool:
        """Verifica la risposta alla challenge firmata con la SK dell'Utente.

        L'esito positivo dimostra il possesso fisico della chiave (User Presence)
        e sventa tentativi di Replay Attack.

        Args:
            pk_utente (rsa.RSAPublicKey): Lo pseudonimo registrato.
            firma_challenge (bytes): Il nonce firmato ricevuto dal client.

        Raises:
            ValueError: Se non ci sono challenge attive per lo pseudonimo.

        Returns:
            bool: True se l'autenticazione ha successo, False altrimenti.
        """
        pk_bytes = self._serializza_pk(pk_utente)
        nonce_atteso = self.sfide_attive.get(pk_bytes)

        if not nonce_atteso:
            raise ValueError("Authentication Fallita: Nessuna challenge attiva per la sessione.")

        # Verifica crittografica: solo la SK_Utente associata a PK_Utente può generare questa firma
        is_valid = verifica_firma(pk_utente, firma_challenge, nonce_atteso)
        
        if is_valid:
            # Invalida il nonce immediatamente per evitare Replay Attacks
            del self.sfide_attive[pk_bytes]
            return True
            
        return False
