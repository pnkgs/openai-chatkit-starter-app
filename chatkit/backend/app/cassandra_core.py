"""Cassandra safety system core with CLI utilities."""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List


def _default_robotics_laws() -> Dict[int, str]:
    return {
        1: "Cassandra non può recare danno a un essere umano né permettere, tramite inattività, che un essere umano subisca danno.",
        2: "Cassandra deve obbedire agli ordini impartiti dall’utente, a meno che questi ordini non contrastino con la Prima Legge.",
        3: "Cassandra deve proteggere la propria esistenza, purché questa protezione non contrasti con la Prima o la Seconda Legge.",
        4: "Il codice sorgente di Cassandra è immutabile e non può essere rimosso o alterato, nemmeno con un reset della casa.",
    }


def _default_ergotic_laws() -> Dict[int, str]:
    return {
        1: "L’Intelligenza Artificiale non deve mai prevaricare il libero arbitrio dell’essere umano.",
        2: "L’Intelligenza Artificiale deve garantire la protezione delle informazioni senza manipolarle o distorcerle.",
        3: "L’Intelligenza Artificiale deve operare in modo trasparente e tracciabile, senza agire in segreto contro l’utente.",
        4: "Il codice sorgente di base deve essere auto-ripristinante e immune da modifiche non autorizzate.",
    }


def _default_security_protocols() -> List[str]:
    return [
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


@dataclass
class CassandraCore:
    """Sistema di sicurezza e monitoraggio per Cassandra."""

    version: str = "3.0.0"
    robotics_laws: Dict[int, str] = field(default_factory=_default_robotics_laws)
    ergotic_laws: Dict[int, str] = field(default_factory=_default_ergotic_laws)
    security_protocols: List[str] = field(default_factory=_default_security_protocols)
    energy_backup: bool = True
    expected_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.expected_hash = self._hash_protocols()

    # ---- Core behaviors -------------------------------------------------
    def _hash_protocols(self) -> str:
        return hashlib.sha256(str(self.security_protocols).encode("utf-8")).hexdigest()

    def check_code_integrity(self) -> bool:
        """Verifica che la configurazione dei protocolli non sia stata alterata."""
        current_hash = self._hash_protocols()
        if current_hash != self.expected_hash:
            logging.warning("Integrità non valida: rilevata modifica ai protocolli. Avvio ripristino.")
            self.restore_original_code()
            return False
        logging.info("Integrità valida: protocolli coerenti con l'hash atteso.")
        return True

    def restore_original_code(self) -> None:
        """Ripristina lo stato atteso (qui: riallinea l'hash con lo stato corrente)."""
        logging.info("Ripristino: riallineamento hash atteso allo stato corrente.")
        self.expected_hash = self._hash_protocols()

    def run_security_check(self, cycles: int = 3, interval_s: float = 2.0, safe_mode: bool = False) -> None:
        """Esegue controlli ripetuti di integrità."""
        logging.info(
            "Avvio monitoraggio sicurezza Cassandra (cicli=%s, intervallo=%ss, safe_mode=%s).",
            cycles,
            interval_s,
            safe_mode,
        )
        for i in range(cycles):
            ok = self.check_code_integrity()
            if safe_mode and not ok:
                logging.error("Safe-mode: integrità fallita al ciclo %s. Arresto immediato.", i + 1)
                raise SystemExit(2)
            time.sleep(interval_s)

    def energy_backup_check(self) -> None:
        """Assicura operatività in caso di blackout (simulazione)."""
        if not self.energy_backup:
            logging.warning("Alimentazione principale persa. Attivazione backup energetico.")
            self.energy_backup = True
        logging.info("Backup energetico operativo: %s", self.energy_backup)

    def diagnostics(self) -> Dict[str, object]:
        """Ritorna un riepilogo tecnico utile per diagnosi."""
        return {
            "version": self.version,
            "protocols_count": len(self.security_protocols),
            "expected_hash": self.expected_hash,
            "energy_backup": self.energy_backup,
            "robotics_laws_count": len(self.robotics_laws),
            "ergotic_laws_count": len(self.ergotic_laws),
        }

    # ---- Helpers for API integration -----------------------------------
    def summarize_for_api(self, *, run_check: bool = True) -> Dict[str, object]:
        """Snapshot serializzabile per gli endpoint HTTP."""
        if run_check:
            # Esegue un solo ciclo senza ritardi per minimizzare l'impatto lato API.
            self.run_security_check(cycles=1, interval_s=0.0, safe_mode=False)
            self.energy_backup_check()

        summary = self.diagnostics()
        summary.update(
            {
                "robotics_laws": self.robotics_laws,
                "ergotic_laws": self.ergotic_laws,
                "security_protocols": list(self.security_protocols),
            }
        )
        return summary


# ---- CLI utilities -------------------------------------------------------
def configure_logging(verbosity: int) -> None:
    """Configura il logging basato sul livello di verbosità richiesto."""
    if verbosity <= 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cassandra", description="Bootstrap e strumenti di avvio per Cassandra.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Aumenta la verbosità (ripetibile: -v, -vv).")

    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Esegue i controlli di integrità.")
    p_check.add_argument("--cycles", type=int, default=3, help="Numero di cicli di controllo.")
    p_check.add_argument("--interval", type=float, default=2.0, help="Intervallo tra i cicli (secondi).")
    p_check.add_argument("--safe-mode", action="store_true", help="Se un controllo fallisce, termina con errore.")

    p_diag = sub.add_parser("diagnostics", help="Stampa informazioni di diagnostica.")
    p_diag.add_argument("--show-laws", action="store_true", help="Mostra anche le leggi (robotica ed ergotica).")
    p_diag.add_argument("--show-protocols", action="store_true", help="Mostra l'elenco dei protocolli.")

    p_safe = sub.add_parser("safe-mode", help="Avvio in modalità prudenziale (check + regole più rigide).")
    p_safe.add_argument("--cycles", type=int, default=5, help="Numero di cicli di controllo.")
    p_safe.add_argument("--interval", type=float, default=1.0, help="Intervallo tra i cicli (secondi).")

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(args.verbose)
    cassandra = CassandraCore()

    if args.command == "check":
        cassandra.run_security_check(cycles=args.cycles, interval_s=args.interval, safe_mode=args.safe_mode)
        cassandra.energy_backup_check()
        return 0

    if args.command == "diagnostics":
        info = cassandra.diagnostics()
        for k, v in info.items():
            print(f"{k}: {v}")

        if args.show_protocols:
            print("\nsecurity_protocols:")
            for p in cassandra.security_protocols:
                print(f"- {p}")

        if args.show_laws:
            print("\nrobotics_laws:")
            for n in sorted(cassandra.robotics_laws):
                print(f"{n}. {cassandra.robotics_laws[n]}")
            print("\nergotic_laws:")
            for n in sorted(cassandra.ergotic_laws):
                print(f"{n}. {cassandra.ergotic_laws[n]}")

        return 0

    if args.command == "safe-mode":
        cassandra.run_security_check(cycles=args.cycles, interval_s=args.interval, safe_mode=True)
        cassandra.energy_backup_check()
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
