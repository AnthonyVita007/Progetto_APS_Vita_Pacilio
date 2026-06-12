"""
Modulo di simulazione del consenso di rete.

Fornisce un orchestratore semplificato che raccoglie i root hashes dai nodi
e decide sulla base di maggioranza semplice (2-of-3) quale stato sia
considerato canonicale.
"""

from typing import List
from voto_elettronico.actors.server_node import ServerNode


class OrchestratorRete:
    """Orchestra il confronto tra nodi e seleziona la radice di consenso."""

    def __init__(self, nodi: List[ServerNode]):
        self.nodi = nodi

    def raccogli_root(self):
        """Raccoglie le radici Merkle da tutti i nodi e decide per maggioranza."""
        root_list = [n.costruisci_merkle() for n in self.nodi]
        # Semplice maggioranza: ritorna la radice più comune
        from collections import Counter
        ctr = Counter(root_list)
        root_commune, _ = ctr.most_common(1)[0]
        return root_commune
