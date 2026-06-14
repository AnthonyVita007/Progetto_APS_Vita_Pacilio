import time
import json
import sys

def measure_time(func, *args, iterations=100, **kwargs):
    """
    Misura il tempo medio di esecuzione di una funzione su un numero specificato di iterazioni.
    
    Args:
        func: La funzione da testare.
        iterations (int): Il numero di iterazioni su cui calcolare la media.
        *args, **kwargs: Argomenti da passare alla funzione.
        
    Returns:
        float: Il tempo medio di esecuzione in millisecondi (ms).
    """
    start_time = time.perf_counter()
    for _ in range(iterations):
        func(*args, **kwargs)
    end_time = time.perf_counter()
    
    total_time = end_time - start_time
    avg_time_ms = (total_time / iterations) * 1000
    return avg_time_ms

def get_payload_size(obj):
    """
    Calcola la dimensione approssimativa in byte di un oggetto.
    Simula la serializzazione per l'invio in rete (es. JSON se possibile, altrimenti usa sys.getsizeof).
    
    Args:
        obj: L'oggetto di cui calcolare la dimensione.
        
    Returns:
        int: La dimensione in byte.
    """
    try:
        # Prova a serializzare in JSON per simulare il payload di rete reale
        if isinstance(obj, bytes):
            return len(obj)
        elif isinstance(obj, str):
            return len(obj.encode('utf-8'))
        else:
            return len(json.dumps(obj).encode('utf-8'))
    except (TypeError, OverflowError):
        # Fallback se l'oggetto non è serializzabile in JSON (es. chiavi RSA native)
        return sys.getsizeof(obj)

def print_benchmark_result(name, avg_time_ms, iterations):
    """
    Stampa a video il risultato di un benchmark temporale in formato leggibile.
    """
    print(f"{name:<40} | Media: {avg_time_ms:.4f} ms | Iterazioni: {iterations}")

def print_size_result(name, size_bytes):
    """
    Stampa a video il risultato di un benchmark dimensionale.
    """
    print(f"{name:<40} | Dimensione: {size_bytes} bytes")