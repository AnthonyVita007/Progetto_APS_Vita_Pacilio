"""
Modulo per le primitive di hashing del protocollo Vita-Pacilio.

Questo modulo fornisce le funzioni crittografiche unidirezionali (one-way)
necessarie per la fase di Identity Proofing, garantendo il disaccoppiamento
tra l'identità reale dell'elettore e il circuito digitale (pseudoanonimato).
Viene utilizzato lo standard SHA-256.
"""

import os
from cryptography.hazmat.primitives import hashes


def genera_salt(dimensione: int = 32) -> bytes:
    """Genera un salt crittografico ad alta entropia.

    Args:
        dimensione (int, optional): La lunghezza del salt in byte. Default a 32 byte (256 bit).

    Returns:
        bytes: Sequenza di byte casuali generati dal CSPRNG del sistema operativo.
    """
    return os.urandom(dimensione)


def calcola_h0(codice_fiscale: str, salt: bytes) -> bytes:
    """Calcola l'hash H0 a partire dall'identità reale (Codice Fiscale) e un salt.

    Questa funzione modella l'operazione eseguita localmente dall'elettore
    (o tramite il suo dispositivo) presso l'Ente Fisico. L'uso del salt ad alta
    entropia è cruciale per prevenire attacchi a dizionario o rainbow table 
    nel caso in cui il registro degli hash dell'Ente Fisico venga compromesso.

    Args:
        codice_fiscale (str): Il Codice Fiscale dell'utente in chiaro.
        salt (bytes): Il salt ad alta entropia generato per lo specifico utente.

    Returns:
        bytes: Il digest SHA-256 risultante dalla concatenazione H(CF || Salt).
    """
    digest = hashes.Hash(hashes.SHA256())
    
    # Concatenazione logica del Codice Fiscale (codificato in UTF-8) e del salt
    payload = codice_fiscale.encode('utf-8') + salt
    digest.update(payload)
    
    return digest.finalize()


def calcola_h1(hash_h0: bytes) -> bytes:
    """Calcola l'hash H1 applicando una seconda passata di hashing su H0.

    Questa operazione viene eseguita dalla CA1. Apponendo un ulteriore
    livello di hash prima della firma (Certificato di Identità), si aggiunge un
    layer di sicurezza che isola ulteriormente la struttura dati dell'Ente Fisico
    da quella della CA1.

    Args:
        hash_h0 (bytes): L'hash H0 ricevuto dall'Ente Fisico.

    Returns:
        bytes: Il digest SHA-256 risultante da H(H0).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(hash_h0)
    
    return digest.finalize()
