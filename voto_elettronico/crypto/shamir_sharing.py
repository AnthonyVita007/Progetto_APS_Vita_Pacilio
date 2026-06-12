"""
Modulo per l'implementazione dello Shamir's Secret Sharing (t, n).

Questo modulo fornisce le primitive per frammentare e ricostruire un segreto
(nello specifico, la chiave privata dell'elezione) utilizzando l'interpolazione
polinomiale su un campo finito. Il protocollo prevede t=2 e n=3.
"""

import os
import random

# Definizione di un numero primo molto grande per il campo di Galois.
# In un'implementazione di produzione, questo primo deve essere maggiore 
# del segreto più grande possibile (la chiave RSA).
# Per simulazione, usiamo il 12° numero di Mersenne (2^127 - 1).
PRIME = 2**127 - 1 


def _eval_poly(poly: list[int], x: int, prime: int) -> int:
    """Valuta il polinomio P(x) in un campo finito.

    Args:
        poly (list[int]): I coefficienti del polinomio [c_0, c_1, ..., c_{t-1}].
        x (int): L'ascissa in cui valutare il polinomio.
        prime (int): L'ordine del campo finito.

    Returns:
        int: Il valore P(x) mod prime.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def split_secret(segreto: int, soglia: int, n_frammenti: int) -> list[tuple[int, int]]:
    """Divide un segreto in n frammenti, dei quali ne servono almeno t (soglia) per la ricostruzione.

    L'algoritmo genera un polinomio casuale di grado (soglia - 1) il cui
    termine noto (coefficiente 0) è il segreto stesso.

    Args:
        segreto (int): Il segreto numerico da frammentare (es. interi estratti dalla SK).
        soglia (int): Il numero minimo di frammenti per la ricostruzione (t=2 nel progetto).
        n_frammenti (int): Il numero totale di frammenti da generare (n=3 nel progetto).

    Returns:
        list[tuple[int, int]]: Una lista di coppie (x, y) che rappresentano i frammenti.
    """
    if soglia > n_frammenti:
        raise ValueError("La soglia non può essere maggiore del numero di frammenti.")
    
    # Il polinomio ha grado (soglia - 1). Il termine noto poly[0] è il segreto.
    poly = [segreto] + [random.SystemRandom().randint(1, PRIME - 1) for _ in range(soglia - 1)]
    
    frammenti = []
    # Generiamo i frammenti calcolando il polinomio per x = 1, 2, ..., n
    for x in range(1, n_frammenti + 1):
        y = _eval_poly(poly, x, PRIME)
        frammenti.append((x, y))
        
    return frammenti


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Algoritmo di Euclide esteso per trovare l'inverso moltiplicativo modulare."""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def _mod_inverse(k: int, prime: int) -> int:
    """Calcola l'inverso moltiplicativo di k modulo prime."""
    k = k % prime
    if k < 0:
        r = _extended_gcd(prime, -k)[2]
    else:
        r = _extended_gcd(prime, k)[2]
    return (prime + r) % prime


def recover_secret(frammenti: list[tuple[int, int]]) -> int:
    """Ricostruisce il segreto utilizzando l'interpolazione di Lagrange.

    Args:
        frammenti (list[tuple[int, int]]): Una lista di almeno 't' frammenti (x, y).

    Returns:
        int: Il segreto ricostruito (il termine noto del polinomio originale).
    """
    segreto_ricostruito = 0
    
    # Interpolazione di Lagrange per trovare P(0)
    for j, (x_j, y_j) in enumerate(frammenti):
        numeratore = 1
        denominatore = 1
        
        for m, (x_m, _) in enumerate(frammenti):
            if j == m:
                continue
            numeratore = (numeratore * (-x_m)) % PRIME
            denominatore = (denominatore * (x_j - x_m)) % PRIME
            
        lagrange_poly = (y_j * numeratore * _mod_inverse(denominatore, PRIME)) % PRIME
        segreto_ricostruito = (segreto_ricostruito + lagrange_poly) % PRIME
        
    return (segreto_ricostruito + PRIME) % PRIME
