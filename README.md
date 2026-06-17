# Algoritmi e Protocolli per la Sicurezza (APS) - Gruppo 15

- *Antonio Pacilio (IE22700198)*
- *Anthony Vita (IE22700195)*

## Descrizione del Progetto

Questo repository contiene l'implementazione in Python di un protocollo crittografico per la conduzione di un'elezione elettronica sicura. Il sistema è modellato per supportare un'elezione con **lista chiusa e voto singolo**, garantendo proprietà fondamentali quali:

* **Autenticità e Segretezza** dell'elettore.

* **Integrità** del voto (nessuna alterazione possibile).

* **Verificabilità** del processo di scrutinio.

Il protocollo fa uso di primitive crittografiche avanzate tra cui crittografia asimmetrica (RSA), funzioni di hash, Alberi di Merkle e frammentazione del segreto (Shamir's Secret Sharing).

## Struttura del Repository

L'architettura software è divisa nei seguenti moduli principali all'interno del package `voto_elettronico/`:

* **`actors/`**: Implementa le entità del sistema (`utente`, `commissione`, `server_node`, `ca1`, `ca2`, `ente_fisico`).

* **`crypto/`**: Modulo con le utility crittografiche (`rsa_utils`, `hash_utils`, `merkle_tree`, `shamir_sharing`).

* **`network/`**: Gestisce il layer di rete e l'algoritmo di consenso (`consensus`).

* **`benchmarks/`**: Utility per l'analisi delle prestazioni e il tracciamento dei tempi di esecuzione (`utils`).

* **`config.py`**: Parametri di configurazione globali del sistema.

* **`docs/`**: Documentazione generata automaticamente del codice sorgente.

## 🚀 Come Eseguire il Codice

Il progetto richiede **Python 3** (testato su Python 3.13). Assicurati di avere un ambiente Python configurato e di trovarti nella root del progetto.

### 1. Simulazione del Sistema di Voto

Per avviare l'esecuzione standard del protocollo, che simula un'intera elezione (registrazione, voto, consenso, scrutinio), esegui il file main:

```
python voto_elettronico/main.py

```

*L'output a terminale mostrerà i log di sistema, confermando il successo o il fallimento delle singole fasi crittografiche.*

### 2. Analisi delle Prestazioni (Benchmark)

Per avviare i test prestazionali relativi alle operazioni crittografiche e di rete (come descritto nel Work Package dei Benchmark), esegui:

```
python voto_elettronico/run_benchmarks.py

```

*Verranno generati i tempi di esecuzione delle singole primitive per valutare l'impatto computazionale del protocollo.*

### 3. Testing del protocollo

Per testare il codice in tutte le sue parti è stato predisposto un apposito file. In esso sono presenti test con relative stampe
di ogni primitiva crittografica utilizzata, test relativi alla procedura di voto che segue il singolo utente e che attraversano tutte le fasi
del protocollo, e infine test relativi ad una piccola simulazione di voto completa con 10 votanti randomizzati.

Ognuno dei test presenti è predisposto per essere personalizzabile con parametri a proprio piacimento:

```
python voto_elettronico/rtesting_main.py

```

*Verranno stampati dei log che mostrano tutti i test configurati all'interno del file*

## 📚 Documentazione del Codice (pdoc)

L'intero progetto è stato ampiamente documentato seguendo gli standard delle **Docstring** a livello di modulo, classe e metodo, come indicato nella relazione tecnica.

Per usufruire della documentazione, è stata generata un'interfaccia HTML navigabile tramite la libreria `pdoc`.

**Come consultare la documentazione:**

1. Naviga all'interno della cartella `docs/` presente nella root del progetto.

2. Apri il file **`index.html`** (o in alternativa `voto_elettronico.html`) utilizzando un qualsiasi browser web (Chrome, Firefox, Safari, Edge).

3. Utilizza il menu di navigazione laterale o la barra di ricerca integrata per esplorare:

   * Le descrizioni dei singoli moduli.

   * Le classi, i loro attributi (es. ledger, merkle) e i loro metodi.

   * I tipi di parametri accettati (`Args`) e restituiti (`Returns`) da ciascuna funzione crittografica.

*(Nota: Non è necessario avere `pdoc` installato per leggere la documentazione, i file HTML statici sono già pre-generati nella cartella).*
