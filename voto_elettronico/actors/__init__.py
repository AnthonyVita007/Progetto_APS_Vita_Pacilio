"""Package actors per `voto_elettronico`.

Raggruppa le classi attore per import semplificato.
"""

from .ca1 import CA1
from .ca2 import CA2
from .commissione import Commissione
from .ente_fisico import EnteFisico
from .server_node import ServerNode
from .utente import Utente

__all__ = [
    'CA1', 'CA2', 'Commissione', 'EnteFisico', 'ServerNode', 'Utente'
]
