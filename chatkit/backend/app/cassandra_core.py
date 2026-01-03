"""Cassandra safety system with HMAC-signed state and CLI tools."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# =========================
#  Storage sicuro (firma HMAC)
# =========================


def _atomic_write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def _hmac_sha256(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


@dataclass
class SignedStateStore:
    """
    Salva stato (hash atteso + snapshot protocolli) su file JSON, firmato via HMAC.
    Nota: l'HMAC è valido solo se il segreto resta segreto. Per demo: ENV var.
    """

    state_path: Path
    secret_env_var: str = "CASSANDRA_STATE_SECRET"

    def _get_secret(self) -> bytes:
        secret = os.getenv(self.secret_env_var, "")
        if not secret:
            raise RuntimeError(f"Segreto mancante: impostare la variabile d'ambiente {self.secret_env_var}")
        return secret.encode("utf-8")

    def write_state(self, payload: Dict[str, object]) -> None:
        secret = self._get_secret()
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        sig = _hmac_sha256(secret, body)
        envelope = {"payload": payload, "signature": sig, "alg": "HMAC-SHA256"}
        _atomic_write_text(self.state_path, json.dumps(envelope, ensure_ascii=False, indent=2))

    def read_state(self) -> Dict[str, object]:
        if not self.state_path.exists():
            raise FileNotFoundError(f"State file non trovato: {self.state_path}")

        secret = self._get_secret()
        envelope = json.loads(self.state_path.read_text(encoding="utf-8"))

        payload = envelope.get("payload")
        signature = envelope.get("signature")
        alg = envelope.get("alg")

        if alg != "HMAC-SHA256":
            raise ValueError("Algoritmo firma non supportato o manomesso.")

        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        expected_sig = _hmac_sha256(secret, body)

        if not hmac.compare_digest(str(signature), expected_sig):
            raise ValueError("Firma non valida: file di stato manomesso o segreto errato.")

        if not isinstance(payload, dict):
            raise ValueError("Payload non valido.")

        return payload


# =========================
#  Cassandra Core
# =========================


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    version: str = "3.1.0"
    robotics_laws: Dict[int, str] = field(default_factory=_default_robotics_laws)
    ergotic_laws: Dict[int, str] = field(default_factory=_default_ergotic_laws)
    security_protocols: List[str] = field(default_factory=_default_security_protocols)
    energy_backup: bool = True
    expected_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.expected_hash = self.compute_expected_hash()

    def compute_expected_hash(self) -> str:
        # Canonicalizzazione semplice e stabile
        canon = json.dumps(self.security_protocols, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        return _sha256_text(canon)

    def verify_protocols(self) -> bool:
        current = self.compute_expected_hash()
        ok = current == self.expected_hash
        if ok:
            logging.info("Integrità protocolli OK.")
        else:
            logging.warning("Integrità protocolli FALLITA.")
        return ok

    def restore(self) -> None:
        # In questa demo: "ripristino" significa riallineare l'hash atteso allo stato corrente.
        # In produzione, qui si ricaricherebbe una configurazione 'golden' read-only.
        logging.info("Ripristino: riallineamento hash atteso allo stato corrente.")
        self.expected_hash = self.compute_expected_hash()

    def security_check_loop(self, cycles: int, interval_s: float, safe_mode: bool, dry_run: bool) -> None:
        logging.info(
            "Monitoraggio sicurezza (cycles=%s, interval=%ss, safe_mode=%s, dry_run=%s).",
            cycles,
            interval_s,
            safe_mode,
            dry_run,
        )

        for i in range(cycles):
            ok = self.verify_protocols()
            if not ok:
                if dry_run:
                    logging.error("Dry-run: sarebbe stato avviato un ripristino (ciclo %s).", i + 1)
                else:
                    self.restore()

                if safe_mode:
                    raise SystemExit(2)

            time.sleep(interval_s)

    def energy_backup_check(self) -> None:
        if not self.energy_backup:
            logging.warning("Alimentazione principale persa. Attivazione backup.")
            self.energy_backup = True
        logging.info("Backup energetico operativo: %s", self.energy_backup)

    def diagnostics(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "protocols_count": len(self.security_protocols),
            "expected_hash": self.expected_hash,
            "energy_backup": self.energy_backup,
        }

    # ---- Helpers per integrazione API -----------------------------------
    def summarize_for_api(self) -> Dict[str, object]:
        """Esegue un controllo rapido (dry-run) e restituisce uno snapshot serializzabile."""
        self.security_check_loop(cycles=1, interval_s=0.0, safe_mode=False, dry_run=True)
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


# =========================
#  CLI
# =========================


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity <= 0 else (logging.INFO if verbosity == 1 else logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def default_state_path() -> Path:
    # ~/.cassandra/state.json
    return Path.home() / ".cassandra" / "state.json"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cassandra", description="Bootstrap Cassandra (check/diagnostics/state).")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Aumenta la verbosità (-v, -vv).")
    p.add_argument("--state-path", type=str, default=str(default_state_path()), help="Percorso file stato (JSON firmato).")

    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="Esegue controlli di integrità.")
    c.add_argument("--cycles", type=int, default=3)
    c.add_argument("--interval", type=float, default=2.0)
    c.add_argument("--safe-mode", action="store_true", help="Esce con errore al primo fallimento.")
    c.add_argument("--dry-run", action="store_true", help="Non ripristina: segnala soltanto.")

    d = sub.add_parser("diagnostics", help="Mostra diagnostica.")
    d.add_argument("--show-protocols", action="store_true")
    d.add_argument("--show-laws", action="store_true")

    s = sub.add_parser("state", help="Gestisce lo stato firmato.")
    ssub = s.add_subparsers(dest="state_cmd", required=True)

    init = ssub.add_parser("init", help="Inizializza/sovrascrive lo stato firmato a partire dai valori correnti.")
    init.add_argument("--force", action="store_true", help="Forza sovrascrittura anche se esiste già.")

    ssub.add_parser("load", help="Carica lo stato firmato e lo applica a Cassandra (hash atteso + protocolli).")
    ssub.add_parser("save", help="Salva lo stato firmato (hash atteso + protocolli).")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    cassandra = CassandraCore()
    store = SignedStateStore(state_path=Path(args.state_path))

    if args.cmd == "diagnostics":
        info = cassandra.diagnostics()
        for k, v in info.items():
            print(f"{k}: {v}")

        if args.show_protocols:
            print("\nsecurity_protocols:")
            for x in cassandra.security_protocols:
                print(f"- {x}")

        if args.show_laws:
            print("\nrobotics_laws:")
            for n in sorted(cassandra.robotics_laws):
                print(f"{n}. {cassandra.robotics_laws[n]}")
            print("\nergotic_laws:")
            for n in sorted(cassandra.ergotic_laws):
                print(f"{n}. {cassandra.ergotic_laws[n]}")
        return 0

    if args.cmd == "check":
        cassandra.security_check_loop(
            cycles=args.cycles,
            interval_s=args.interval,
            safe_mode=args.safe_mode,
            dry_run=args.dry_run,
        )
        cassandra.energy_backup_check()
        return 0

    if args.cmd == "state":
        if args.state_cmd == "init":
            path = Path(args.state_path)
            if path.exists() and not args.force:
                raise SystemExit(f"State già esistente: {path} (usa --force per sovrascrivere).")

            payload = {
                "version": cassandra.version,
                "expected_hash": cassandra.expected_hash,
                "security_protocols": cassandra.security_protocols,
                "created_at": time.time(),
            }
            store.write_state(payload)
            print(f"State inizializzato: {path}")
            return 0

        if args.state_cmd == "save":
            payload = {
                "version": cassandra.version,
                "expected_hash": cassandra.expected_hash,
                "security_protocols": cassandra.security_protocols,
                "saved_at": time.time(),
            }
            store.write_state(payload)
            print(f"State salvato: {store.state_path}")
            return 0

        if args.state_cmd == "load":
            payload = store.read_state()

            # Applicazione controllata
            protocols = payload.get("security_protocols")
            expected_hash = payload.get("expected_hash")

            if not isinstance(protocols, list) or not all(isinstance(x, str) for x in protocols):
                raise SystemExit("State non valido: security_protocols malformato.")
            if not isinstance(expected_hash, str):
                raise SystemExit("State non valido: expected_hash mancante.")

            cassandra.security_protocols = list(protocols)
            cassandra.expected_hash = str(expected_hash)

            print("State caricato e applicato a Cassandra.")
            print(f"expected_hash: {cassandra.expected_hash}")
            print(f"protocols_count: {len(cassandra.security_protocols)}")
            return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
