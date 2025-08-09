#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scraper file-downloader (no CLI args):
- Effettua una GET su un URL
- Imposta uno User-Agent da browser
- Aggiunge cookie personalizzati
- Salva sul filesystem con nome file intelligente (Content-Disposition/URL)
- Riprova su errori transitori, timeout configurabile
- Supporto opzionale resume (Range) se abilitato
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import errno
import shutil
import string
import mimetypes
from pathlib import Path
from urllib.parse import urlparse, unquote
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    # urllib3 Retry API
    from urllib3.util.retry import Retry
except Exception:
    Retry = None  # Fallback: niente retry avanzati

# ========== CONFIG ==========
CONFIG = {
    # URL da scaricare
    "URL": "https://example.com/path/to/file.pdf",

    # Directory di output (verrà creata se non esiste). Se None => directory corrente.
    "OUTPUT_DIR": "downloads",

    # Nome file desiderato (opzionale). Se None => inferenza da Content-Disposition/URL.
    "FILENAME": None,

    # Abilita resume se esiste un file parziale con stesso nome (usa header Range)
    "ENABLE_RESUME": True,

    # Headers HTTP personalizzati (User-Agent da browser incluso)
    "HEADERS": {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
        "Referer": "https://vimm.net/",
    },

    # Cookie personalizzati (chiave: valore)
    "COOKIES": {
        "counted": 1,
        # "sessionid": "INSERISCI_IL_TUO_VALORE",
    },

    # Timeout secondi per la richiesta
    "TIMEOUT": 30,

    # Verifica SSL
    "VERIFY_SSL": False,

    # Retry su errori transitori (richiede urllib3 Retry)
    "RETRIES": {
        "enabled": True,
        "total": 3,
        "backoff_factor": 0.8,
        "status_forcelist": [429, 500, 502, 503, 504],
    },

    # Dimensione chunk per lo streaming
    "CHUNK_SIZE": 256 * 1024,  # 256 KiB
}
# ===========================

def extract_media_id_from_html(html_page: str) -> str | None:
    soup = BeautifulSoup(html_page, "html.parser")
    form = soup.find("form", id="dl_form")
    if not form:
        return None
    input_tag = form.find("input", {"type": "hidden", "name": "mediaId"})
    if input_tag and input_tag.has_attr("value"):
        return input_tag["value"]
    return None


def ensure_dir(path: Path) -> None:
    if path is None:
        return
    path.mkdir(parents=True, exist_ok=True)


def sanitize_filename(name: str) -> str:
    # Rimuove caratteri non validi per file system comuni
    safe_chars = f"-_.() {string.ascii_letters}{string.digits}"
    cleaned = "".join(c if c in safe_chars else "_" for c in name)
    # Evita nomi vuoti o solo estensione
    return cleaned.strip(" .") or "downloaded_file"


def infer_filename_from_cd(cd: str) -> str | None:
    # Parsing basilare di Content-Disposition per filename e filename*
    # Esempi: attachment; filename="report.pdf"
    #         attachment; filename*=UTF-8''relazione%20finale.pdf
    if not cd:
        return None
    params = {}
    parts = [p.strip() for p in cd.split(";")]
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip().lower()] = v.strip().strip('"\'')

    # RFC5987
    if "filename*" in params:
        val = params["filename*"]
        if "''" in val:
            # charset''urlencoded-filename
            try:
                _, _, enc_name = val.partition("''")
                return unquote(enc_name)
            except Exception:
                return val
        return val

    if "filename" in params:
        return params["filename"]
    return None


def infer_filename_from_url(url: str) -> str | None:
    path = urlparse(url).path
    if not path:
        return None
    name = os.path.basename(path)
    return unquote(name) if name else None


def maybe_add_extension(name: str, content_type: str | None) -> str:
    # Se il nome non ha estensione e content-type è noto, prova ad aggiungerla
    if not name or "." in name:
        return name
    if not content_type:
        return name
    ext = mimetypes.guess_extension(content_type.split(";")[0].strip())
    if ext and not name.endswith(ext):
        return name + ext
    return name


def build_session(cfg: dict) -> requests.Session:
    s = requests.Session()
    if cfg["RETRIES"]["enabled"] and Retry is not None:
        retries = Retry(
            total=cfg["RETRIES"]["total"],
            connect=cfg["RETRIES"]["total"],
            read=cfg["RETRIES"]["total"],
            status=cfg["RETRIES"]["total"],
            backoff_factor=cfg["RETRIES"]["backoff_factor"],
            status_forcelist=tuple(cfg["RETRIES"]["status_forcelist"]),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


def resolve_output_path(cfg: dict, response: requests.Response) -> Path:
    desired = cfg.get("FILENAME")
    if desired:
        filename = sanitize_filename(desired)
    else:
        # Prova da Content-Disposition
        cd_name = infer_filename_from_cd(response.headers.get("Content-Disposition", ""))
        if cd_name:
            filename = sanitize_filename(cd_name)
        else:
            # Prova da URL
            url_name = infer_filename_from_url(cfg["URL"])
            filename = sanitize_filename(url_name) if url_name else "downloaded_file"

    # Aggiungi estensione se manca
    filename = maybe_add_extension(filename, response.headers.get("Content-Type"))

    out_dir = Path(cfg["OUTPUT_DIR"]) if cfg.get("OUTPUT_DIR") else Path(".")
    ensure_dir(out_dir)
    return out_dir / filename


def download_file(cfg: dict) -> Path:
    session = build_session(cfg)

    headers = dict(cfg["HEADERS"]) if cfg.get("HEADERS") else {}
    cookies = {k: str(v) for k, v in dict(cfg["COOKIES"]).items()} if cfg.get("COOKIES") else {}

    # Prima richiesta HEAD o GET leggera per scoprire nome/size? Andiamo diretti con GET (stream)
    # Gestione resume
    temp_headers = headers.copy()
    target_path: Path | None = None
    mode = "wb"
    resume_from = 0

    # Se resume attivo e abbiamo un nome previsto senza risposta, faremo doppia richiesta:
    # 1) senza Range per ottenere Content-Disposition -> filename
    # 2) se esiste file locale e ENABLE_RESUME True, rilanciamo con Range
    # Per semplicità: prima GET senza Range, senza scrivere su disco, solo per headers
    probe_resp = session.get(
        cfg["URL"],
        headers=temp_headers,
        cookies=cookies,
        stream=True,
        timeout=cfg["TIMEOUT"],
        verify=cfg["VERIFY_SSL"],
        allow_redirects=True,
    )

    if probe_resp.status_code >= 400:
        raise RuntimeError(f"Errore HTTP {probe_resp.status_code} durante la richiesta iniziale")

    target_path = resolve_output_path(cfg, probe_resp)

    if cfg.get("ENABLE_RESUME", True) and target_path.exists():
        resume_from = target_path.stat().st_size
        if resume_from > 0:
            temp_headers["Range"] = f"bytes={resume_from}-"
            mode = "ab"
            # Chiudiamo la response di probe e apriamo una nuova con Range
            probe_resp.close()
            resp = session.get(
                cfg["URL"],
                headers=temp_headers,
                cookies=cookies,
                stream=True,
                timeout=cfg["TIMEOUT"],
                verify=cfg["VERIFY_SSL"],
                allow_redirects=True,
            )
        else:
            resp = probe_resp
    else:
        resp = probe_resp

    # Verifica codici ripresa
    if "Range" in temp_headers:
        if resp.status_code not in (206, 200):
            # Il server non supporta Range; riparti da zero
            resp.close()
            temp_headers.pop("Range", None)
            mode = "wb"
            resume_from = 0
            resp = session.get(
                cfg["URL"],
                headers=temp_headers,
                cookies=cookies,
                stream=True,
                timeout=cfg["TIMEOUT"],
                verify=cfg["VERIFY_SSL"],
                allow_redirects=True,
            )

    if resp.status_code >= 400:
        resp.close()
        raise RuntimeError(f"Errore HTTP {resp.status_code} durante il download")

    # Scrittura su disco
    chunk_size = int(cfg.get("CHUNK_SIZE", 256 * 1024))
    bytes_written = 0
    with open(target_path, mode) as f:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            f.write(chunk)
            bytes_written += len(chunk)

    resp.close()

    # Validazione semplice: se Content-Length disponibile, confronta
    cl = resp.headers.get("Content-Length") or resp.headers.get("content-length")
    if cl and "Range" not in temp_headers:
        try:
            expected = int(cl)
            actual = target_path.stat().st_size
            if actual < expected:
                raise IOError(f"File incompleto: atteso {expected}B, scritto {actual}B")
        except Exception:
            pass  # Non bloccare se non interpretabile

    return target_path


def main():
    try:
        # constrolla se ci sono linee duplicate in input.txt
        input_file = Path("input.txt")
        if input_file.exists():
            with input_file.open("r", encoding="utf-8") as f:
                lines = f.readlines()
            unique_lines = set(line.strip() for line in lines if line.strip() and not line.startswith("#"))
            if len(unique_lines) < len(lines):
                print("Attenzione: ci sono linee duplicate in input.txt, verranno ignorate.")
            with input_file.open("w", encoding="utf-8") as f:
                for line in unique_lines:
                    f.write(line + "\n")

        # Cicla le istruzioni per ogni riga di input.txt (se esiste)
        input_file = Path("input.txt")
        if input_file.exists():
            with input_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    print(f"[INPUT] Eseguo istruzione: {line}")

                    # extract digits at the end of the line
                    match = re.search(r"(\d+)$", line)
                    if match:
                        digits = match.group(1)
                        print(f"[INPUT] Trovati numeri alla fine della riga: {digits}")

                    # Ensure downloaded.txt exists
                    downloaded_path = Path("downloaded.txt")
                    if not downloaded_path.exists():
                        downloaded_path.touch()

                    # if digits already exists in downloaded.txt, skip
                    with downloaded_path.open("r", encoding="utf-8") as downloaded_file:
                        if digits in downloaded_file.read():
                            print(f"[INPUT] Già scaricato: {digits}, salto...")
                            continue

                    # save the digits in downloaded.txt
                    with downloaded_path.open("a", encoding="utf-8") as downloaded_file:
                        downloaded_file.write(f"{digits}\n")

                    


                    print(f"[1] Recupero media ID: {digits}")
                    html_page = requests.get(f"https://vimm.net/vault/{digits}", verify=False)
                    media_id = extract_media_id_from_html(html_page.text)
                    print(f"[1] OK: Media ID estratto: {media_id}")

                    print("[2] Costruzione URL finale")
                    final_url = f"https://dl2.vimm.net/?mediaId={media_id}"
                    CONFIG["URL"] = final_url
                    print(f"[2] OK: URL finale per il download: {CONFIG['URL']}")

                    # DEBUG CONFIG["URL"] = "https://dl2.vimm.net/?mediaId=87217"

                    print("[3] Inizio download")
                    out_path = download_file(CONFIG)
                    print(f"[3] OK: salvato in -> {out_path.resolve()}")

                    print("\n\n prossimo file...\n\n")

        # clean input.txt
        print("Pulizia input.txt...")
        if input_file.exists():
            input_file.unlink()
        input_file.touch()

    except Exception as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()