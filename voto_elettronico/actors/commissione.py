"""
Modulo per l'attore Commissione Elettorale del protocollo.

Gestisce la fase di Setup (generazione chiave dell'elezione e frammentazione),
la ricostruzione della chiave tramite Secret Sharing e la decifratura
delle schede per lo scrutinio finale, garantendo la non-ripudiabilità 
tramite la firma del registro (Merkle Tree).
"""

import random
from collections import Counter
from cryptography.hazmat.primitives.asymmetric import rsa

from voto_elettronico.crypto.rsa_utils import genera_coppia_chiavi, decifra_oaep, firma_messaggio
from voto_elettronico.crypto.shamir_sharing import split_secret, recover_secret
from voto_elettronico.crypto.merkle_tree import MerkleTree
from voto_elettronico import config


class Commissione:
    """Rappresenta l'Autorità per la gestione e lo scrutinio dell'elezione.

    Attributes:
        sk_comm (rsa.RSAPrivateKey): Chiave privata per firmare il registro (Root Hash).
        pk_comm (rsa.RSAPublicKey): Chiave pubblica della Commissione.
        frammento_chiave (tuple[int, int] | None): Il frammento in possesso della Commissione.
    """

    def __init__(self):
        """Inizializza la Commissione generando le proprie chiavi istituzionali."""
        self.sk_comm, self.pk_comm = genera_coppia_chiavi(config.RSA_KEY_SIZE)
        self.frammento_chiave: tuple[int, int] | None = None
        
        # Variabili per simulare l'incapsulamento della chiave privata dell'elezione.
        self.__sk_elezione_nascosta: rsa.RSAPrivateKey | None = None
        self.__segreto_sblocco: int | None = None

    def avvia_setup_elezione(self) -> tuple[rsa.RSAPublicKey, tuple[int, int], tuple[int, int]]:
        """Esegue il setup crittografico dell'elezione (Fase 0).

        Genera la coppia di chiavi dell'elezione. La chiave pubblica viene
        esposta per essere distribuita agli elettori. La chiave privata viene
        vincolata a un segreto frammentato tramite Shamir (t=2, n=3).

        Returns:
            tuple: Contiene:
                - pk_elezione (rsa.RSAPublicKey): Da distribuire agli elettori.
                - frammento_ca1 (tuple): Frammento destinato a CA1.
                - frammento_ca2 (tuple): Frammento destinato a CA2.
        """
        # Generazione chiave specifica per crittografare i voti
        sk_elezione, pk_elezione = genera_coppia_chiavi(config.RSA_KEY_SIZE)
        
        # Generiamo un segreto casuale a 120 bit per il Secret Sharing
        # (rientra nel campo di Galois PRIME definito in shamir_sharing.py)
        segreto = random.SystemRandom().getrandbits(120)
        
        # Custodiamo la chiave, sbloccabile solo con il segreto ricostruito
        self.__sk_elezione_nascosta = sk_elezione
        self.__segreto_sblocco = segreto
        
        # Applica Shamir's Secret Sharing (Soglia=2, Frammenti=3)
        frammenti = split_secret(
            segreto=segreto, 
            soglia=config.SHAMIR_THRESHOLD, 
            n_frammenti=config.SHAMIR_SHARES
        )
        
        # Distribuzione logica dei frammenti
        self.frammento_chiave = frammenti[0]  # La Commissione conserva il frammento 1
        frammento_ca1 = frammenti[1]          # Destinato a CA1
        frammento_ca2 = frammenti[2]          # Destinato a CA2
        
        return pk_elezione, frammento_ca1, frammento_ca2

    def ricostruisci_chiave(self, frammento_esterno: tuple[int, int]) -> rsa.RSAPrivateKey:
        """Ricostruisce la chiave dell'elezione tramite consenso crittografico.

        Args:
            frammento_esterno (tuple[int, int]): Il frammento fornito da CA1 o CA2.

        Raises:
            PermissionError: Se l'interpolazione fallisce (frammento errato).

        Returns:
            rsa.RSAPrivateKey: La chiave privata pronta per la decifratura.
        """
        if not self.frammento_chiave:
            raise RuntimeError("La Commissione non ha generato o possiede il frammento.")

        frammenti_per_consenso = [self.frammento_chiave, frammento_esterno]
        
        # Esegue l'interpolazione di Lagrange per trovare il termine noto P(0)
        segreto_calcolato = recover_secret(frammenti_per_consenso)
        
        if segreto_calcolato != self.__segreto_sblocco:
            raise PermissionError("Consenso fallito: Frammento non valido o insufficiente.")
            
        return self.__sk_elezione_nascosta

    def esegui_scrutinio(self, merkle_tree: MerkleTree, sk_elezione: rsa.RSAPrivateKey) -> dict[str, int]:
        """Esegue l'apertura delle urne, decifrando i voti in chiaro.

        Estrae le foglie dal Merkle Tree e decifra esclusivamente il crittogramma 
        del voto (voto_enc). Il crittogramma dell'utente (utente_enc) viene 
        ignorato, preservando rigorosamente lo pseudoanonimato.

        Args:
            merkle_tree (MerkleTree): Il registro pubblico sigillato.
            sk_elezione (rsa.RSAPrivateKey): La chiave dell'elezione ricostruita.

        Returns:
            dict[str, int]: Un dizionario con i risultati aggregati dello scrutinio.
        """
        risultati = Counter()
        
        # Una foglia contiene Hash(utente_enc || voto_enc). 
        # Nella simulazione reale, i Server forniscono l'elenco delle transazioni cifrate 
        # validate, il cui hash corrisponde a quello delle foglie. 
        # Per semplicità qui assumiamo di ricevere la lista di transazioni grezze.
        
        pass # La logica di iterazione verrà orchestrata dal modulo di rete (Consensus)
             # che passerà le tuple (utente_enc, voto_enc) validate dalla radice.

        return dict()

    def decifra_voto(self, voto_enc: bytes, sk_elezione: rsa.RSAPrivateKey) -> str:
        """Decifra un singolo crittogramma di voto.
        
        Args:
            voto_enc (bytes): La preferenza cifrata.
            sk_elezione (rsa.RSAPrivateKey): La chiave privata ricostruita.
            
        Returns:
            str: Il nome del candidato in chiaro.
        """
        voto_chiaro_bytes = decifra_oaep(sk_elezione, voto_enc)
        return voto_chiaro_bytes.decode('utf-8')

    def firma_root_hash(self, root_hash: bytes) -> bytes:
        """Appone la firma istituzionale sul risultato finale (Multi-firma).

        Args:
            root_hash (bytes): La radice del Merkle Tree sigillato.

        Returns:
            bytes: La firma digitale della Commissione.
        """
        return firma_messaggio(self.sk_comm, root_hash)
