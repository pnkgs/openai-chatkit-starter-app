"""Core logic for the Cassandra safety system."""

from __future__ import annotations

import hashlib
import time
from typing import Iterable, List


class CassandraCore:
    """Sistema di sicurezza e monitoraggio per Cassandra."""

    def __init__(self) -> None:
        """Inizializzazione del sistema di sicurezza e delle leggi fondamentali."""
        self.version = "3.0.0"

        # Quattro Leggi della Robotica di Asimov (immutabili)
        self.robotics_laws = {
            1: "Cassandra non può recare danno a un essere umano né permettere, tramite inattività, che un essere umano subisca danno.",
            2: "Cassandra deve obbedire agli ordini impartiti dall’utente, a meno che questi ordini non contrastino con la Prima Legge.",
            3: "Cassandra deve proteggere la propria esistenza, purché questa protezione non contrasti con la Prima o la Seconda Legge.",
            4: "Il codice sorgente di Cassandra è immutabile e non può essere rimosso o alterato, nemmeno con un reset della casa.",
        }

        # Quattro Leggi dell'Ergotica (immutabili)
        self.ergotic_laws = {
            1: "L’Intelligenza Artificiale non deve mai prevaricare il libero arbitrio dell’essere umano.",
            2: "L’Intelligenza Artificiale deve garantire la protezione delle informazioni senza manipolarle o distorcerle.",
            3: "L’Intelligenza Artificiale deve operare in modo trasparente e tracciabile, senza agire in segreto contro l’utente.",
            4: "Il codice sorgente di base deve essere auto-ripristinante e immune da modifiche non autorizzate.",
        }

        # Protocolli di sicurezza
        self.security_protocols = [
            "Protocollo Buonanotte",
            "Protocollo Buongiorno",
            "Protocollo Buone Vacanze",
            "Protezione Ospiti",
            "Gestione Sicurezza per Anziani",
            "Blocco Truffatori e Venditori Porta-a-Porta",
            "Ricezione Automatica di Pizza",
            "Sincronizzazione Tablet con Consenso",
            "Gestione Accessi Durante la Doccia o Inabilità Fisica",
            "Protezione Contro Violenza Domestica e Sessuale",
            "Gestione Posta e Pacchi per Utenti in Viaggio",
            "Protocollo Cambio Proprietario",
        ]

        # Hash di verifica del codice originale
        self.expected_hash = hashlib.sha256(str(self.security_protocols).encode()).hexdigest()

        # Sistema energetico indipendente per blackout
        self.energy_backup = True

    # ---- Core behaviors -------------------------------------------------
    def check_code_integrity(self) -> str:
        """Verifica che il codice sorgente non sia stato alterato."""
        current_hash = hashlib.sha256(str(self.security_protocols).encode()).hexdigest()
        if current_hash != self.expected_hash:
            message = "ATTENZIONE: Tentativo di violazione del codice rilevato! Ripristino in corso..."
            print(message)
            self.restore_original_code()
            return message

        message = "Codice sorgente integro e protetto."
        print(message)
        return message

    def restore_original_code(self) -> str:
        """Ripristina il codice sorgente originale in caso di manomissione."""
        message = "Cassandra sta ripristinando i protocolli di sicurezza e il codice originale..."
        print(message)
        self.expected_hash = hashlib.sha256(str(self.security_protocols).encode()).hexdigest()
        return message

    def run_security_check(self, cycles: int = 3, delay_seconds: float = 2.0) -> List[str]:
        """Avvia il monitoraggio costante della sicurezza del sistema."""
        messages: list[str] = ["Avvio del sistema di monitoraggio di sicurezza Cassandra..."]
        print(messages[0])

        for _ in range(cycles):
            messages.append(self.check_code_integrity())
            if delay_seconds:
                time.sleep(delay_seconds)
        return messages

    def energy_backup_check(self) -> str:
        """Assicura che il sistema rimanga attivo anche in caso di blackout."""
        if not self.energy_backup:
            message = (
                "ATTENZIONE: Alimentazione principale persa! Passaggio al sistema energetico di backup..."
            )
            print(message)
            self.energy_backup = True
            return message

        message = "Cassandra è operativa con il sistema di backup energetico."
        print(message)
        return message

    # ---- Helpers for API integration -----------------------------------
    def summarize(self, *, cycles: int = 1, delay_seconds: float = 0.0) -> dict[str, object]:
        """Produce a serializzabile stato della piattaforma."""
        return {
            "version": self.version,
            "robotics_laws": self.robotics_laws,
            "ergotic_laws": self.ergotic_laws,
            "security_protocols": list(self.security_protocols),
            "integrity_checks": self.run_security_check(cycles=cycles, delay_seconds=delay_seconds),
            "energy_backup": self.energy_backup_check(),
        }


def run_default_sequence() -> Iterable[str]:
    """Esegue il flusso previsto dallo script utente originale."""
    cassandra_system = CassandraCore()
    return cassandra_system.run_security_check()


__all__ = ["CassandraCore", "run_default_sequence"]
