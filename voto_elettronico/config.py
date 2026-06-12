"""
Modulo di configurazione globale per il sistema di Voto Elettronico.

Definisce i parametri crittografici, le impostazioni del Secret Sharing
e l'elenco immutabile dei candidati per l'elezione a lista chiusa e voto singolo.
"""

# --- Parametri Crittografici ---
# Dimensione delle chiavi asimmetriche (bilancia sicurezza PPT e performance)
RSA_KEY_SIZE: int = 2048

# Lunghezza in byte del salt per garantire alta entropia nell'Identity Proofing
SALT_SIZE: int = 32

# --- Parametri Shamir's Secret Sharing ---
# Soglia minima per la ricostruzione della Chiave dell'Elezione (t=2)
SHAMIR_THRESHOLD: int = 2

# Numero totale di frammenti distribuiti alle Autorità (n=3)
SHAMIR_SHARES: int = 3

# --- Configurazione Elezione ---
# Elenco predefinito e immutabile per impedire inserimenti arbitrari (Superficie d'attacco ridotta)
CANDIDATI_VALIDI: list[str] = [
    "Candidato 1 - Partito Innovazione Digitale",
    "Candidato 2 - Coalizione Sicurezza Dati",
    "Candidato 3 - Alleanza Trasparenza"
]