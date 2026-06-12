"""
Entry point del simulatore del sistema di Voto Elettronico.

Questo script orchestra l'esecuzione del protocollo Vita-Pacilio, 
istanzia gli attori, simula il passaggio di messaggi (TLS) e 
mostra a video i log delle operazioni crittografiche per ogni fase.
"""

import binascii
import sys
from typing import Any

from voto_elettronico import config
from voto_elettronico.crypto import genera_salt, calcola_h1, MerkleTree
from voto_elettronico.actors import EnteFisico, CA1, CA2, Commissione, Utente, ServerNode
from voto_elettronico.network import OrchestratorRete
from voto_elettronico.crypto.rsa_utils import firma_messaggio


def log_step(fase: str, attore: str, azione: str, dettaglio: Any = "") -> None:
    """Stampa a video un'operazione formattata per la tracciabilità.

    Args:
        fase (str): Il numero o nome della fase corrente.
        attore (str): L'entità che sta eseguendo l'azione.
        azione (str): Descrizione dell'operazione.
        dettaglio (Any, optional): Dati crittografici o risultati (troncati se bytes).
    """
    det_str = ""
    if isinstance(dettaglio, bytes):
        det_str = f" [0x{binascii.hexlify(dettaglio[:8]).decode()}...]"
    elif dettaglio:
        det_str = f" [{dettaglio}]"
        
    print(f"[{fase}] - [{attore:^11}] -> {azione}{det_str}")


def main():
    """Funzione principale che esegue la simulazione interattiva."""
    print("="*60)
    print(" SIMULATORE VOTO ELETTRONICO (Protocollo Vita-Pacilio)")
    print("="*60 + "\n")

    # Inizializzazione Attori
    log_step("INIT", "SYSTEM", "Istanziazione degli attori fiduciari e dei Server...")
    ente_fisico = EnteFisico()
    ca1 = CA1()
    ca2 = CA2()
    commissione = Commissione()
    servers = [ServerNode() for _ in range(3)]
    rete = OrchestratorRete(servers)

    # ---------------------------------------------------------
    # FASE 0: Setup Iniziale
    # ---------------------------------------------------------
    print("\n--- FASE 0: SETUP E GENERAZIONE CHIAVI ---")
    pk_elezione, frammento_ca1, frammento_ca2 = commissione.avvia_setup_elezione()
    log_step("FASE 0", "COMMISSIONE", "Generata coppia chiavi Elezione (RSA-OAEP).")
    log_step("FASE 0", "SHAMIR", "Chiave privata frammentata (t=2, n=3).", "Distribuzione completata")

    # ---------------------------------------------------------
    # FASE 1: Registrazione Utente
    # ---------------------------------------------------------
    print("\n--- FASE 1: IDENTITY PROOFING & REGISTRATION ---")
    # Registrazione Utente e Identity Proofing
    dati_anagrafici = {
        'nome': 'Mario',
        'cognome': 'Rossi',
        'codice_fiscale': 'RSSMRA80A01H501Z'
    }
    utente = Utente(dati_anagrafici)

    # Ente Fisico calcola H0
    h0 = ente_fisico.calcola_h0_per_elektor(dati_anagrafici)
    log_step("FASE 1", "ENTE FISICO", "Generato H0 per l'utente.", h0)

    # CA1 emette certificato su H1(H0)
    cert_ca1 = ca1.emetti_certificato(h0)
    log_step("FASE 1", "CA1", "Emesso Certificato di Identità firmato.", cert_ca1)

    # Registrazione presso CA2
    hash_h1_atteso = calcola_h1(h0)
    token, token_signed = ca2.registra_pseudonimo_e_genera_token(
        utente.pk, cert_ca1, hash_h1_atteso, ca1.pk_ca1
    )
    log_step("FASE 1", "CA2", "Rilasciato Token Monouso.", token)

    # ---------------------------------------------------------
    # FASE 2: Autenticazione FIDO2
    # ---------------------------------------------------------
    print("\n--- FASE 2: AUTHENTICATION CEREMONY ---")
    # FIDO2 Authentication (simulata): l'utente firma la challenge con la propria SK
    nonce = ca2.genera_challenge(utente.pk)
    firma_challenge = firma_messaggio(utente.sk, nonce)
    auth_ok = ca2.verifica_challenge(utente.pk, firma_challenge)
    log_step("FASE 2", "CA2", "Verifica firma FIDO2: ", "SUCCESS" if auth_ok else "FAILED")

    # ---------------------------------------------------------
    # FASE 3: Voto e Trasmissione
    # ---------------------------------------------------------
    print("\n--- FASE 3: ESPRESSIONE DEL VOTO ---")
    scelta = config.CANDIDATI_VALIDI[0]
    log_step("FASE 3", "UTENTE", f"Candidato selezionato: {scelta}")
    utente_enc, voto_enc = utente.crea_pacchetto_voto(scelta, pk_elezione)
    log_step("FASE 3", "CRYPTO", "Cifratura RSA-OAEP di Pseudonimo e Voto eseguita.")

    # ---------------------------------------------------------
    # FASE 4: Consenso e Registrazione
    # ---------------------------------------------------------
    print("\n--- FASE 4: NETWORK CONSENSUS (MERKLE TREE) ---")
    log_step("FASE 4", "RETE", "Trasmissione pacchetto in broadcast ai 3 Server...")
    # Trasmetti ai server e costruisci i Merkle Tree
    for s in servers:
        s.aggiungi_transazione(utente_enc, voto_enc)
        s.costruisci_merkle()

    root_consenso = rete.raccogli_root()
    log_step("FASE 4", "RETE", "Root di consenso calcolata.", root_consenso)
    
    # ---------------------------------------------------------
    # FASE 5 & 6: Scrutinio e Verifica
    # ---------------------------------------------------------
    print("\n--- FASE 5/6: SCRUTINIO E PUBBLICAZIONE ---")
    # Sigilliamo gli alberi (urne chiuse)
    for s in servers:
        if s.merkle:
            s.merkle.seal_tree()
    log_step("FASE 5", "SERVER", "Urne chiuse. Merkle Tree sigillati.")

    # Ricostruzione Chiave (Commissione + frammento da CA2)
    sk_elezione_ricostruita = commissione.ricostruisci_chiave(frammento_ca2)
    log_step("FASE 5", "COMMISSIONE", "Chiave privata ricostruita tramite interpolazione Shamir.")

    # Scrutinio (Simulato sul Merkle Tree del primo server)
    albero_ufficiale = servers[0].merkle
    voti_in_chiaro = []

    log_step("FASE 6", "COMMISSIONE", "Inizio decifratura asimmetrica delle foglie...")
    # Decifriamo il voto di ogni transazione nel primo server
    for (utente_cip, voto_cip) in servers[0].esporta_transazioni():
        voto_decifrato = commissione.decifra_voto(voto_cip, sk_elezione_ricostruita)
        voti_in_chiaro.append(voto_decifrato)

    print(f"\n>> RISULTATI ELEZIONE: {voti_in_chiaro} <<\n")

    root_hash = albero_ufficiale.get_root_hash() if albero_ufficiale else None
    if root_hash:
        firma_comm = commissione.firma_root_hash(root_hash)
        log_step("FASE 6", "COMMISSIONE", "Root Hash firmata. Registro ufficiale pubblicato.", root_hash)

    print("\nSimulazione completata con successo.")


if __name__ == "__main__":
    main()