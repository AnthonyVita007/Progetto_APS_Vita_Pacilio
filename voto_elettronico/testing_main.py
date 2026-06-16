"""
Ambiente di testing per il sistema di Voto Elettronico (Protocollo Vita-Pacilio).
Il file è suddiviso in tre MACRO-PARTI:
1. Test delle primitive crittografiche (mostrando input e output).
2. Simulazione dettagliata passo-passo del flusso per un SINGOLO UTENTE, mostrando 
   i dati in chiaro e la loro evoluzione crittografica.
3. Simulazione di un'elezione massiva e procedure finali di scrutinio.
"""

import binascii
import random
import string

# Importazioni rigorosamente dal package fornito
from voto_elettronico import config
from voto_elettronico.crypto.hash_utils import genera_salt, calcola_h0, calcola_h1
from voto_elettronico.crypto.rsa_utils import (
    genera_coppia_chiavi, cifra_oaep, decifra_oaep, firma_messaggio, verifica_firma
)
from voto_elettronico.crypto.shamir_sharing import split_secret, recover_secret
from voto_elettronico.actors import EnteFisico, CA1, CA2, Commissione, Utente, ServerNode
from voto_elettronico.network import OrchestratorRete

# =========================================================================
# UTILITY DI STAMPA
# =========================================================================
def stampa_titolo(testo: str):
    print(f"\n{'='*70}\n {testo} \n{'='*70}")

def tronca_dati(dati) -> str:
    """Utility per mostrare solo una porzione leggibile di dati crittografici lunghi."""
    if isinstance(dati, bytes):
        hex_str = binascii.hexlify(dati).decode()
        return f"{hex_str[:16]}...{hex_str[-8:]}" if len(hex_str) > 24 else hex_str
    elif isinstance(dati, int):
        str_int = str(dati)
        return f"{str_int[:10]}...{str_int[-5:]}" if len(str_int) > 15 else str_int
    return str(dati)

def genera_cf_casuale():
    """Genera un Codice Fiscale fittizio per le simulazioni massive."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))


# =========================================================================
# SEZIONE 1: TESTING DELLE PRIMITIVE CRITTOGRAFICHE
# =========================================================================
def test_primitive_crittografiche():
    stampa_titolo("Sezione 1: TESTING DELLE PRIMITIVE CRITTOGRAFICHE")

    print("[*] 1. Test Funzioni di Hashing (SHA-256)")
    testo_in_chiaro = "CodiceFiscaleDiProva123"
    print(f"    - Input in chiaro: '{testo_in_chiaro}'")
    salt = genera_salt(32)
    print(f"    - Salt generato: {tronca_dati(salt)}")
    h0 = calcola_h0(testo_in_chiaro, salt)
    print(f"    - Output H0 (Digest irreversibile): {tronca_dati(h0)}")
    h1 = calcola_h1(h0)
    print(f"    - Output H1 (Hashing di H0): {tronca_dati(h1)}\n")

    print("[*] 2. Test Crittografia Asimmetrica (RSA-OAEP)")
    testo_segreto = b"Candidato X"
    print(f"    - Dato in chiaro da cifrare: {testo_segreto}")
    sk, pk = genera_coppia_chiavi(config.RSA_KEY_SIZE)
    print(f"    - Chiave Pubblica (PK) generata: {tronca_dati(pk)}")
    cifrato = cifra_oaep(pk, testo_segreto)
    print(f"    - Dato cifrato (Incomprensibile): {tronca_dati(cifrato)}")
    decifrato = decifra_oaep(sk, cifrato)
    print(f"    - Dato decifrato con SK (Verifica): {decifrato}\n")

    print("[*] 3. Test Firme Digitali (RSA-PSS)")
    messaggio_da_firmare = b"Token Autorizzativo 001"
    print(f"    - Messaggio in chiaro: {messaggio_da_firmare}")
    firma = firma_messaggio(sk, messaggio_da_firmare)
    print(f"    - Firma apposta sul digest: {tronca_dati(firma)}")
    verifica = verifica_firma(pk, firma, messaggio_da_firmare)
    print(f"    - Esito verifica matematica della firma: {'Valida' if verifica else 'Non Valida'}\n")

    print("[*] 4. Test Shamir's Secret Sharing")
    segreto_originale = 987654321
    print(f"    - Segreto in chiaro da frammentare: {segreto_originale}")
    frammenti = split_secret(segreto_originale, soglia=config.SHAMIR_THRESHOLD, n_frammenti=config.SHAMIR_SHARES)
    for i, f in enumerate(frammenti):
        print(f"    - Frammento {i+1}: P({f[0]}) = {tronca_dati(f[1])}")
    segreto_recostruito = recover_secret([frammenti[0], frammenti[2]])
    print(f"    - Segreto ricostruito unendo Frammento 1 e 3: {segreto_recostruito}\n")


# =========================================================================
# Sezione 2: FLUSSO DETTAGLIATO PER UN SINGOLO UTENTE
# =========================================================================
def simula_singolo_utente():
    stampa_titolo("Sezione 2: PROCEDURE DI VOTO PER UN SINGOLO UTENTE")
    print("In questa sezione seguiremo i dati in chiaro di un singolo Elettore e \nmostreremo come vengono trasformati nelle varie fasi.\n")

    # [ SETUP FASE 0 ]
    # L'utilizzatore può istanziare gli attori. Non vi sono dati specifici da variare.
    ente_fisico = EnteFisico()
    ca1 = CA1()
    ca2 = CA2()
    commissione = Commissione()
    server = ServerNode() # Ne usiamo uno per mostrare il log interno

    # [ ESECUZIONE FASE 0 ]
    print("--- FASE 0: SETUP ELEZIONE ---")
    pk_elezione, frammento_ca1, frammento_ca2 = commissione.avvia_setup_elezione()
    print(f"    Chiave Pubblica Elezione generata: {tronca_dati(pk_elezione)}")
    print(f"    Frammenti SK assegnati a CA1 e CA2 (nascosti).")


    # [ SETUP FASE 1 ]
    # L'utilizzatore può modificare l'identità in chiaro dell'elettore.
    dati_utente_chiaro = {
        'nome': 'Mario',
        'cognome': 'Rossi',
        'codice_fiscale': 'RSSMRA80A01H501Z'
    }

    # [ ESECUZIONE FASE 1 ]
    print("\n--- FASE 1: IDENTITY PROOFING & REGISTRATION ---")
    print(f"    Dati Elettore in chiaro: {dati_utente_chiaro['nome']} {dati_utente_chiaro['cognome']}, CF: {dati_utente_chiaro['codice_fiscale']}")
    utente = Utente(dati_utente_chiaro)
    
    # Processo Identity Proofing
    h0 = ente_fisico.calcola_h0_per_elektor(dati_utente_chiaro)
    print(f"    Ente Fisico calcola H0: {tronca_dati(h0)}")
    cert_ca1 = ca1.emetti_certificato(h0)
    print(f"    CA1 emette certificato d'identità: {tronca_dati(cert_ca1)}")
    
    # Processo Registration (Creazione Pseudonimo)
    print(f"    Dispositivo Elettore genera Pseudonimo (PK_Utente): {tronca_dati(utente.pk)}")
    hash_h1 = calcola_h1(h0)
    token, token_signed = ca2.registra_pseudonimo_e_genera_token(utente.pk, cert_ca1, hash_h1, ca1.pk_ca1)
    print(f"    CA2 genera Token Monouso: {tronca_dati(token)}")
    print(f"    CA2 firma il Token: {tronca_dati(token_signed)}")


    # [ SETUP FASE 2 ]
    # Nessun parametro in input per il tester.
    
    # [ ESECUZIONE FASE 2 ]
    print("\n--- FASE 2: AUTHENTICATION CEREMONY ---")
    challenge = ca2.genera_challenge(utente.pk)
    print(f"    CA2 invia Challenge (Nonce in chiaro): {tronca_dati(challenge)}")
    firma_chall = firma_messaggio(utente.sk, challenge)
    print(f"    Dispositivo Elettore firma Challenge con SK_Utente: {tronca_dati(firma_chall)}")
    if ca2.verifica_challenge(utente.pk, firma_chall):
         print("    CA2 verifica la firma: Esito Positivo. Accesso accordato.")


    # [ SETUP FASE 3 ]
    # L'utilizzatore sceglie il candidato per l'Elettore test.
    scelta_voto_chiaro = config.CANDIDATI_VALIDI[0]

    # [ ESECUZIONE FASE 3 ]
    print("\n--- FASE 3: ESPRESSIONE DEL VOTO ---")
    print(f"    Voto espresso in chiaro dall'utente: '{scelta_voto_chiaro}'")
    utente_enc, voto_enc = utente.crea_pacchetto_voto(scelta_voto_chiaro, pk_elezione)
    print(f"    Package di voto generato:")
    print(f"      - utente_enc (Pseudonimo Cifrato): {tronca_dati(utente_enc)}")
    print(f"      - voto_enc (Preferenza Cifrata): {tronca_dati(voto_enc)}")
    print(f"      - token_signed (Inviato in chiaro a logica): {tronca_dati(token_signed)}")


    # [ SETUP FASE 4 ]
    # Numero di server = 1 per visualizzare chiaramente l'inserimento
    
    # [ ESECUZIONE FASE 4 ]
    print("\n--- FASE 4: REGISTRAZIONE NEL SERVER ---")
    server.aggiungi_transazione(utente_enc, voto_enc)
    server.costruisci_merkle()
    print("    Server riceve il pacchetto. Token invalidato.")
    print("    Transazione crittografica inserita come foglia nel Merkle Tree.")
    print(f"    Root Hash provvisoria: {tronca_dati(server.merkle.get_root_hash())}")

    # Ritorna i parametri necessari per testare lo scrutinio nella Sezione 3
    return pk_elezione, frammento_ca1, frammento_ca2, commissione, ca1, ca2, ente_fisico


# =========================================================================
# Sezione 3: SIMULAZIONE MASSIVA, SCRUTINIO E PUBBLICAZIONE
# =========================================================================
def simula_elezione_massiva(pk_elezione, frammento_ca1, frammento_ca2, commissione, ca1, ca2, ente_fisico):
    stampa_titolo("Sezione 3: SIMULAZIONE ELEZIONE MASSIVA E SCRUTINIO")
    print("Abbiamo mostrato il funzionamento delle primitive. Abbiamo mostrato il")
    print("funzionamento di tutto ciò che riguarda un singolo utente votante in")
    print("chiaro. In questa fase simuleremo un'intera votazione completa in cui")
    print("ci sono 10 votanti (scalabile a 100) i cui dati sono definiti randomicamente")
    print("e mostreremo la fase di scrutinio e pubblicazione dei risultati.\n")

    # [ SETUP SIMULAZIONE MASSIVA ]
    NUMERO_VOTANTI = 10
    nodi_server = [ServerNode() for _ in range(3)]
    rete = OrchestratorRete(nodi_server)
    print(f"[*] Avvio simulazione con {NUMERO_VOTANTI} Elettori e 3 Nodi Server distribuiti...")

    # [ ESECUZIONE SIMULAZIONE MASSIVA ]
    for _ in range(NUMERO_VOTANTI):
        # Dati random
        dati_random = {'nome': 'Test', 'cognome': 'User', 'codice_fiscale': genera_cf_casuale()}
        voto_random = random.choice(config.CANDIDATI_VALIDI)
        
        # Astrazione logica Fasi 1-3
        utente = Utente(dati_random)
        h0 = ente_fisico.calcola_h0_per_elektor(dati_random)
        cert = ca1.emetti_certificato(h0)
        ca2.registra_pseudonimo_e_genera_token(utente.pk, cert, calcola_h1(h0), ca1.pk_ca1)
        utente_enc, voto_enc = utente.crea_pacchetto_voto(voto_random, pk_elezione)
        
        # Fase 4: Invio ai server
        for srv in nodi_server:
            srv.aggiungi_transazione(utente_enc, voto_enc)

    for srv in nodi_server:
        srv.costruisci_merkle()
    
    # Consenso
    root_hash_ufficiale = rete.raccogli_root()
    print(f"    Tutti i voti archiviati. Consenso raggiunto tra i server.")
    print(f"    Root Hash Definitiva: {tronca_dati(root_hash_ufficiale)}\n")

    
    # [ SETUP FASE 5 & 6 ]
    # L'utilizzatore decide quale frammento fornire alla commissione per aprire l'urna
    frammento_scelto = frammento_ca2 

    # [ ESECUZIONE FASE 5: CHIUSURA URNE E RICOSTRUZIONE ]
    print("--- FASE 5: CHIUSURA DELLE URNE E RICOSTRUZIONE CHIAVE ---")
    for srv in nodi_server:
        if srv.merkle: srv.merkle.seal_tree()
    print("    Urne chiuse e sigillate (Append-only bloccato).")
    
    sk_elezione_ricostruita = commissione.ricostruisci_chiave(frammento_scelto)
    print(f"    Chiave Privata dell'Elezione recuperata tramite Secret Sharing (2-su-3).")


    # [ ESECUZIONE FASE 6: DECODIFICA E PUBBLICAZIONE ]
    print("\n--- FASE 6: SCRUTINIO CONDIVISO E PUBBLICAZIONE ---")
    voti_in_chiaro = []
    
    # Utilizziamo il Ledger del Server 0 (essendo giunti a consenso sono identici)
    for (ut_cip, vt_cip) in nodi_server[0].esporta_transazioni():
        voto_decifrato = commissione.decifra_voto(vt_cip, sk_elezione_ricostruita)
        voti_in_chiaro.append(voto_decifrato)

    # Conteggio
    risultati = {c: voti_in_chiaro.count(c) for c in config.CANDIDATI_VALIDI}
    print("    Risultati Elettorali:")
    for candidato, voti in risultati.items():
        print(f"      - {candidato}: {voti} voti")
    
    # Multi-firma finale
    firma_commissione = commissione.firma_root_hash(root_hash_ufficiale)
    print(f"\n    Root Hash firmata dalla Commissione Elettorale: {tronca_dati(firma_commissione)}")
    print("    *** Registro pubblico ufficializzato e verificabile (Verificabilità Universale). ***")


if __name__ == "__main__":
    # Esegue in sequenza le tre Macro-parti
    test_primitive_crittografiche()
    
    # Salva gli attori e le chiavi della Fase Singola per passarli alla massiva
    pk_elezione, frag1, frag2, comm, c1, c2, ef = simula_singolo_utente()
    
    simula_elezione_massiva(pk_elezione, frag1, frag2, comm, c1, c2, ef)