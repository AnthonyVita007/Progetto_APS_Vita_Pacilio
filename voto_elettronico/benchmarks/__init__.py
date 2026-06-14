"""Package ``benchmarks`` per ``voto_elettronico``.

Raggruppa le utility per effettuare i test temporali e spaziali del core del
progetto. Questo modulo re-esporta le funzioni principali definite in
``benchmarks.utils`` in modo che strumenti di documentazione automatici
come ``pdoc`` mostrino il subpackage e le sue API direttamente nella pagina
del package.
"""

from .utils import (
	measure_time,
	get_payload_size,
	print_benchmark_result,
	print_size_result,
)

__all__ = [
	"measure_time",
	"get_payload_size",
	"print_benchmark_result",
	"print_size_result",
]