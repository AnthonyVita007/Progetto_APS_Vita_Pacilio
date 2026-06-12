"""Pacchetto `voto_elettronico.crypto`.

Raggruppa le primitive crittografiche usate nel progetto.
"""

from .hash_utils import genera_salt, calcola_h0, calcola_h1
from .merkle_tree import MerkleTree
from .rsa_utils import (
    genera_coppia_chiavi,
    cifra_oaep,
    decifra_oaep,
    firma_messaggio,
    verifica_firma,
)
from .shamir_sharing import split_secret, recover_secret

__all__ = [
    'genera_salt', 'calcola_h0', 'calcola_h1',
    'MerkleTree',
    'genera_coppia_chiavi', 'cifra_oaep', 'decifra_oaep', 'firma_messaggio', 'verifica_firma',
    'split_secret', 'recover_secret'
]
