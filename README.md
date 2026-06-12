# Progetto_APS_Vita_Pacilio

Breve descrizione
-----------------
Questo repository contiene una simulazione didattica del protocollo di voto elettronico
"Vita-Pacilio". L'implementazione è organizzata come package Python `voto_elettronico` e
modella le fasi principali del protocollo (identity proofing, registrazione, autenticazione,
espressione del voto, consenso e scrutinio).

Scopo
------
- Fornire un'implementazione sperimentale delle primitive crittografiche usate nel protocollo.
- Simulare l'interazione tra attori (Ente Fisico, CA1, CA2, Commissione, Utenti) e nodi server.
- Mostrare le problematiche pratiche (packaging Python, limiti di RSA-OAEP, Shamir Secret Sharing, Merkle Tree).

Struttura principale
--------------------
- `voto_elettronico/crypto` — primitive crittografiche (RSA, Merkle, Shamir).
- `voto_elettronico/actors` — attori della simulazione (CA1, CA2, Commissione, Ente Fisico, Utente, ServerNode).
- `voto_elettronico/network` — orchestratore di consenso simulato.
- `voto_elettronico/main.py` — entrypoint della simulazione.

Prerequisiti
------------
- Python 3.10+ (o la stessa versione usata nell'ambiente Anaconda della macchina).
- Pacchetto `cryptography` installato.

Suggerimento: crea e attiva un ambiente virtuale (opzionale ma consigliato):

```powershell
# Windows PowerShell (conda)
conda create -n voto_env python=3.10 -y
conda activate voto_env

# oppure con venv/pip
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Installazione dipendenze
------------------------
Installa la dipendenza principale con pip:

```powershell
pip install cryptography
# oppure, se fornisci un requirements.txt, usa:
# pip install -r requirements.txt
```

Esecuzione della simulazione
-----------------------------
È importante eseguire il modulo dal root del progetto (la cartella che contiene `voto_elettronico`),
in modo che il package venga risolto correttamente.

PowerShell (consigliato):

```powershell
cd "C:\Users\vitaa\Desktop\DataManager\UNISA\MAGISTRALE_1ANNO\2_A&P_per_la_sicurezza\Progetto_APS_Vita_Pacilio"
& "C:\Users\vitaa\anaconda3\python.exe" -m voto_elettronico.main
```

Alternativa generica (se `python` è impostato correttamente nell'ambiente):

```powershell
cd Progetto_APS_Vita_Pacilio
python -m voto_elettronico.main
```

Errori comuni
-------------
- Se ottieni `ModuleNotFoundError: No module named 'voto_elettronico'` significa che sei entrato nella
	cartella `voto_elettronico` prima di eseguire il comando: torna alla cartella superiore e rilancia con `-m`.
- Non usare solo `-m voto_elettronico.main` in PowerShell senza anteporre `python`.

Esempio di output atteso
------------------------
La simulazione stampa i passaggi principali (fase di setup, registrazione, autenticazione, consenso,
scrutinio) e alla fine mostra i risultati dell'elezione e la Root Hash firmata.

Pulizia e note sul codice
-------------------------
- Durante la ristrutturazione ho normalizzato gli import in package-qualified e spostato i sottopacchetti
	sotto `voto_elettronico`. Rimangono solo i file compilati `__pycache__` che possono essere eliminati se desiderato.

Domande / step successivi
-------------------------
Se vuoi, posso:
- aggiungere un `requirements.txt` completo;
- rimuovere i residui `__pycache__` dal repository;
- creare uno script di test/CI che esegua automaticamente la simulazione.



