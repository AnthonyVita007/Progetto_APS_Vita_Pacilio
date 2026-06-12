"""
Nodo di server che mantiene il registro distribuito (Merkle Tree)
e partecipa al protocollo di consenso simulato.
"""

from typing import List, Tuple
from voto_elettronico.crypto.merkle_tree import MerkleTree


class ServerNode:
    """Replica di un server che conserva le transazioni validate.

    Attributes:
        ledger (list[tuple[bytes, bytes]]): Lista di tuple (utente_enc, voto_enc).
        merkle (MerkleTree | None): Merkle Tree costruito sulle transazioni.
    """

    def __init__(self):
        self.ledger: List[Tuple[bytes, bytes]] = []
        self.merkle: MerkleTree | None = None

    def aggiungi_transazione(self, utente_enc: bytes, voto_enc: bytes) -> None:
        """Aggiunge una transazione al ledger (non ancora sigillata)."""
        self.ledger.append((utente_enc, voto_enc))

    def costruisci_merkle(self) -> bytes:
        """Costruisce il Merkle Tree sullo stato corrente e restituisce la radice."""
        # La rappresentazione di ciascuna foglia è Hash(utente_enc || voto_enc)
        leaf_datas = [utente + voto for (utente, voto) in self.ledger]
        self.merkle = MerkleTree()
        for ld in leaf_datas:
            self.merkle.add_leaf(ld)
        return self.merkle.get_root_hash()

    def esporta_transazioni(self):
        """Esporta la lista di transazioni per il processo di scrutinio."""
        return list(self.ledger)
