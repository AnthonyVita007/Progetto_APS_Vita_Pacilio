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
in modo che il package venga risolto correttamente:

```powershell
cd Progetto_APS_Vita_Pacilio
python -m voto_elettronico.main
```



