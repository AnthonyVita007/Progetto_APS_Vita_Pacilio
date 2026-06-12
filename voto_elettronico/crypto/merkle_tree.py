"""
Modulo per l'implementazione del Merkle Tree.

Questo modulo fornisce la struttura dati crittografica append-only (solo inserimento)
utilizzata per memorizzare le tuple elettorali (utente_enc, voto_enc). 
Garantisce l'integrità del registro e permette la generazione delle 
Proof of Membership per la verificabilità individuale.
"""

from cryptography.hazmat.primitives import hashes
import math


class MerkleNode:
    """Rappresenta un singolo nodo all'interno del Merkle Tree.

    Attributes:
        hash_val (bytes): Il digest SHA-256 memorizzato in questo nodo.
        left (MerkleNode | None): Riferimento al figlio sinistro (None se foglia).
        right (MerkleNode | None): Riferimento al figlio destro (None se foglia).
        is_leaf (bool): True se il nodo è una foglia, False se è un nodo intermedio.
    """
    def __init__(self, hash_val: bytes, left=None, right=None, is_leaf: bool = False):
        self.hash_val = hash_val
        self.left = left
        self.right = right
        self.is_leaf = is_leaf


class MerkleTree:
    """Struttura dati per il registro elettorale immutabile.

    Implementa un albero di hash binario. Le foglie contengono l'hash della
    transazione (utente_enc || voto_enc), mentre i nodi genitore contengono
    l'hash della concatenazione dei figli.
    """

    def __init__(self):
        """Inizializza un Merkle Tree vuoto."""
        self.leaves: list[MerkleNode] = []
        self.root: MerkleNode | None = None
        self._is_sealed = False

    def _hash_pair(self, left_hash: bytes, right_hash: bytes) -> bytes:
        """Calcola l'hash della concatenazione di due hash figli.

        Args:
            left_hash (bytes): L'hash del nodo figlio sinistro.
            right_hash (bytes): L'hash del nodo figlio destro.

        Returns:
            bytes: Il digest SHA-256 della coppia.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(left_hash + right_hash)
        return digest.finalize()

    def add_leaf(self, transaction_data: bytes) -> None:
        """Aggiunge una nuova foglia all'albero e ricalcola la Root Hash.

        Args:
            transaction_data (bytes): La concatenazione (utente_enc || voto_enc).
                Se l'albero è sigillato (urne chiuse), l'inserimento viene rifiutato.
        
        Raises:
            RuntimeError: Se si tenta di aggiungere una foglia a un albero sigillato.
        """
        if self._is_sealed:
            raise RuntimeError("Operazione non consentita: Urne chiuse, albero sigillato.")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(transaction_data)
        leaf_hash = digest.finalize()
        
        new_node = MerkleNode(hash_val=leaf_hash, is_leaf=True)
        self.leaves.append(new_node)
        self._build_tree()

    def _build_tree(self) -> None:
        """Ricalcola l'intero albero bottom-up a partire dalle foglie attuali.
        
        Se il numero di nodi a un certo livello è dispari, l'ultimo nodo
        viene duplicato per completare la coppia (padding crittografico standard).
        """
        if not self.leaves:
            self.root = None
            return

        current_level = self.leaves
        
        while len(current_level) > 1:
            next_level = []
            # Processa a coppie
            for i in range(0, len(current_level), 2):
                left_node = current_level[i]
                
                # Se è dispari, duplica l'ultimo nodo
                if i + 1 < len(current_level):
                    right_node = current_level[i + 1]
                else:
                    right_node = left_node
                    
                parent_hash = self._hash_pair(left_node.hash_val, right_node.hash_val)
                parent_node = MerkleNode(hash_val=parent_hash, left=left_node, right=right_node)
                next_level.append(parent_node)
                
            current_level = next_level
            
        self.root = current_level[0]

    def get_root_hash(self) -> bytes | None:
        """Restituisce la Root Hash corrente dell'albero.

        Returns:
            bytes | None: Il digest della radice o None se l'albero è vuoto.
        """
        return self.root.hash_val if self.root else None

    def seal_tree(self) -> None:
        """Congela l'albero impedendo ulteriori inserimenti (Chiusura Urne)."""
        self._is_sealed = True

    def get_proof_of_membership(self, transaction_index: int) -> list[tuple[bytes, str]]:
        """Genera il percorso crittografico (Proof) per una determinata transazione.

        Questo metodo permette la Verificabilità Individuale. Viene restituita la
        lista degli hash "fratelli" necessari per ricalcolare la Root Hash a
        partire dalla foglia specificata.

        Args:
            transaction_index (int): L'indice della foglia (transazione) nell'elenco.

        Returns:
            list[tuple[bytes, str]]: Una lista di tuple. Ogni tupla contiene 
                l'hash fratello e la direzione ('left' o 'right') da cui concatenarlo.
                
        Raises:
            IndexError: Se l'indice fornito non è valido.
        """
        if transaction_index < 0 or transaction_index >= len(self.leaves):
            raise IndexError("Indice transazione non valido.")
        
        if not self.root or len(self.leaves) == 1:
            return []

        proof = []
        current_index = transaction_index
        num_nodes_at_level = len(self.leaves)
        
        # Scendiamo nell'albero per identificare i "fratelli" iterativamente
        # Nota: L'implementazione qui è semplificata per la simulazione e si basa
        # sulla conoscenza dell'indice per ricavare il partner a ogni livello.
        
        level_nodes = [node.hash_val for node in self.leaves]
        
        while len(level_nodes) > 1:
            next_level = []
            
            # Se l'indice è pari, il fratello è a destra (se esiste)
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                if sibling_index < len(level_nodes):
                    proof.append((level_nodes[sibling_index], 'right'))
                else:
                    # Caso dispari: il fratello è se stesso duplicato
                    proof.append((level_nodes[current_index], 'right'))
            # Se l'indice è dispari, il fratello è a sinistra
            else:
                sibling_index = current_index - 1
                proof.append((level_nodes[sibling_index], 'left'))
            
            # Calcolo del livello superiore per il prossimo ciclo
            for i in range(0, len(level_nodes), 2):
                left_h = level_nodes[i]
                right_h = level_nodes[i+1] if i+1 < len(level_nodes) else left_h
                
                digest = hashes.Hash(hashes.SHA256())
                digest.update(left_h + right_h)
                next_level.append(digest.finalize())
            
            level_nodes = next_level
            current_index = current_index // 2
            
        return proof

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: list[tuple[bytes, str]], expected_root: bytes) -> bool:
        """Verifica una Proof of Membership in modo indipendente.

        Questa funzione è stateless (statica) e simula il calcolo eseguito dal
        client dell'utente per validare che il suo voto sia nel registro.

        Args:
            leaf_hash (bytes): L'hash calcolato dal client della propria tupla.
            proof (list[tuple[bytes, str]]): Il path crittografico fornito dal server.
            expected_root (bytes): La Root Hash pubblica firmata dalla Commissione.

        Returns:
            bool: True se la ricostruzione combacia con la Root Hash attesa.
        """
        current_hash = leaf_hash
        
        for sibling_hash, position in proof:
            digest = hashes.Hash(hashes.SHA256())
            if position == 'right':
                digest.update(current_hash + sibling_hash)
            else:
                digest.update(sibling_hash + current_hash)
            current_hash = digest.finalize()
            
        return current_hash == expected_root
