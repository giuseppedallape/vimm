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
- Barra di progresso su una sola riga con percentuale, velocità media ed ETA
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
    # URL da scaricare (verrà impostato dinamicamente in main)
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
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",  # usa "identity" per disabilitare la compressione
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


# -------- Utility di formato --------
def fmt_bytes(n: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"


def fmt_rate(bytes_per_sec: float) -> str:
    return f"{fmt_bytes(bytes_per_sec)}/s"


def fmt_time(seconds: float) -> str:
    s = int(seconds)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# -------- Parsing HTML --------
def extract_media_id_from_html(html_page: str) -> str | None:
    soup = BeautifulSoup(html_page, "html.parser")
    form = soup.find("form", id="dl_form")
    if not form:
        return None
    input_tag = form.find("input", {"type": "hidden", "name": "mediaId"})
    if input_tag and input_tag.has_attr("value"):
        return input_tag["value"]
    return None

def extract_media_id_latest_from_html(html_page: str) -> str | None:
    soup = BeautifulSoup(html_page, "html.parser")
    # Cerca la stringa json costante in uno script: const allMedia = [...];
    script_tag = soup.find("script", string=re.compile(r"const allMedia\s*=\s*\[.*\];", re.DOTALL))
    if not script_tag:
        return None
    match = re.search(r"const allMedia\s*=\s*(\[.*\]);", script_tag.string, re.DOTALL)
    if not match:
        return None
    try:
        json_data = json.loads(match.group(1))
    except Exception:
        return None
    # Restituisce l'ID dell'ultimo media
    return str(json_data[-1]["ID"]) if json_data else None

def extract_action_url_from_html(html_page: str) -> str | None:
    soup = BeautifulSoup(html_page, "html.parser")
    form = soup.find("form", id="dl_form")
    if not form:
        return None
    action_url = form.get("action")
    return action_url if action_url else None


# -------- FS helpers --------
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


# -------- HTTP session/retry --------
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


# -------- Downloader con progress bar --------
def download_file(cfg: dict) -> Path:
    session = build_session(cfg)
    headers = dict(cfg["HEADERS"]) if cfg.get("HEADERS") else {}
    cookies = {k: str(v) for k, v in dict(cfg["COOKIES"]).items()} if cfg.get("COOKIES") else {}

    # Prima request "probe" per headers/filename
    temp_headers = headers.copy()
    target_path: Path | None = None
    mode = "wb"
    resume_from = 0

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

    # Resume
    if cfg.get("ENABLE_RESUME", True) and target_path.exists():
        resume_from = target_path.stat().st_size
        if resume_from > 0:
            temp_headers["Range"] = f"bytes={resume_from}-"
            mode = "ab"
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

    # Se il server ignora il Range (ritorna 200), riparti da zero per evitare doppioni
    if "Range" in temp_headers and resp.status_code != 206:
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

    # Dimensione totale attesa (per %)
    total_size: int | None = None
    content_range = resp.headers.get("Content-Range")
    if content_range:
        # Esempio: "bytes 100-999/1000"
        m = re.match(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", content_range)
        if m and m.group(3) != "*":
            total_size = int(m.group(3))
    else:
        cl = resp.headers.get("Content-Length") or resp.headers.get("content-length")
        if cl:
            try:
                size_now = int(cl)
                # se non in resume, o il server ha inviato solo la parte residua, calcola totale
                total_size = resume_from + size_now if resume_from > 0 else size_now
            except Exception:
                total_size = None

    # Info compressione (utile per debug)
    content_encoding = resp.headers.get("Content-Encoding")
    print(f"[HTTP] Content-Encoding: {content_encoding or 'none'} | Accept-Encoding: {temp_headers.get('Accept-Encoding', headers.get('Accept-Encoding', 'auto'))}")

    chunk_size = int(cfg.get("CHUNK_SIZE", 256 * 1024))
    bytes_written = 0
    bytes_read_session = 0
    start_time = time.monotonic()
    last_render = 0.0
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    # Progress su stderr per non interferire con i print normali (cambia in sys.stdout se preferisci)
    progress_stream = sys.stderr
    cols = shutil.get_terminal_size(fallback=(80, 20)).columns
    bar_width = max(10, min(30, cols - 60))
    prev_out_len = 0  # per cancellare la coda della riga precedente

    def render(force: bool = False):
        nonlocal last_render, prev_out_len
        now = time.monotonic()
        if not force and (now - last_render) < 0.1:
            return

        elapsed = max(1e-6, now - start_time)
        avg_rate = bytes_read_session / elapsed
        downloaded_total = resume_from + bytes_written

        if total_size and total_size > 0:
            pct = min(100.0, 100.0 * downloaded_total / total_size)
            filled = int(bar_width * pct / 100.0)
            bar = "█" * filled + "░" * (bar_width - filled)
            remaining = max(0, total_size - downloaded_total)
            eta = remaining / avg_rate if avg_rate > 0 else None
            out = (
                f"[{'RESUME ' if resume_from else ''}{bar}] "
                f"{pct:6.2f}% | {fmt_bytes(downloaded_total)} / {fmt_bytes(total_size)} | "
                f"{fmt_rate(avg_rate)}"
                + (f" | ETA {fmt_time(eta)}" if eta is not None else "")
            )
        else:
            spin = spinner[int(now * 10) % len(spinner)]
            out = (
                f"{spin} {'RESUME ' if resume_from else ''}"
                f"{fmt_bytes(downloaded_total)} | {fmt_rate(avg_rate)} | elapsed {fmt_time(elapsed)}"
            )

        # Single-line update: ritorno carrello + spazi per pulire eventuali residui
        progress_stream.write("\r" + out + " " * max(0, prev_out_len - len(out)))
        progress_stream.flush()
        prev_out_len = len(out)
        last_render = now

    # Scrittura su disco con progress
    with open(target_path, mode) as f:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            f.write(chunk)
            bytes_written += len(chunk)
            bytes_read_session += len(chunk)
            render()

    resp.close()
    render(force=True)
    progress_stream.write("\n")
    progress_stream.flush()

    # Validazione semplice solo per full download (niente Range)
    cl = resp.headers.get("Content-Length") or resp.headers.get("content-length")
    if cl and "Range" not in temp_headers:
        try:
            expected = int(cl)
            actual = target_path.stat().st_size
            if actual < expected:
                raise IOError(f"File incompleto: atteso {expected}B, scritto {actual}B")
        except Exception:
            pass

    # Riepilogo finale
    elapsed_total = max(1e-6, time.monotonic() - start_time)
    avg_rate_final = bytes_read_session / elapsed_total
    total_now = target_path.stat().st_size
    print(f"[DL] {fmt_bytes(total_now)} in {fmt_time(elapsed_total)} | velocità media {fmt_rate(avg_rate_final)}")

    return target_path


# -------- Main --------
def main():
    try:
        # controlla e deduplica input.txt (ignora righe vuote e commenti)
        input_file = Path("input.txt")
        if input_file.exists():
            with input_file.open("r", encoding="utf-8") as f:
                lines = f.readlines()
            unique_lines = [ln for i, ln in enumerate(dict.fromkeys(line.strip() for line in lines)) if ln and not ln.startswith("#")]
            if len(unique_lines) < len([ln for ln in lines if ln.strip() and not ln.startswith("#")]):
                print("Attenzione: ci sono linee duplicate in input.txt, verranno ignorate.")
            with input_file.open("w", encoding="utf-8") as f:
                for line in unique_lines:
                    f.write(line + "\n")

        # Cicla le istruzioni per ogni riga di input.txt (se esiste)
        if input_file.exists():
            downloaded_path = Path("downloaded.txt")
            if not downloaded_path.exists():
                downloaded_path.touch()

            # carica già scaricati come set per confronto esatto riga
            with downloaded_path.open("r", encoding="utf-8") as df:
                already = set(ln.strip() for ln in df if ln.strip())

            with input_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    match = re.search(r"(\d+)$", line)
                    if not match:
                        print(f"[INPUT] Riga senza numeri finali, salto: {line}")
                        continue

                    digits = match.group(1)

                    if digits in already:
                        print(f"[INPUT] Già scaricato: {digits}, salto...")
                        continue

                    print(f"[INPUT] Eseguo istruzione: {line}")
                    print(f"[1] Recupero media ID: {digits}")

                    html_page = requests.get(f"https://vimm.net/vault/{digits}", verify=False, timeout=CONFIG["TIMEOUT"])
                    media_id = extract_media_id_from_html(html_page.text)
                    if not media_id:
                        print(f"[1] ERRORE: mediaId non trovato per {digits}, salto...")
                        continue


                    print(f"[1] Recupero media ID: {digits}")
                    html_page = requests.get(f"https://vimm.net/vault/{digits}", verify=False)
                    actionUrl = extract_action_url_from_html(html_page.text)
                    media_id = extract_media_id_latest_from_html(html_page.text)
                    print(f"[1] OK: Media ID estratto: {media_id}")
                    print("[2] Costruzione URL finale")
                    final_url = f"https:{actionUrl}?mediaId={media_id}"
                    CONFIG["URL"] = final_url
                    print(f"[2] OK: URL finale per il download: {CONFIG['URL']}")

                    print("[3] Inizio download")
                    out_path = download_file(CONFIG)
                    print(f"[3] OK: salvato in -> {out_path.resolve()}")

                    # aggiorna downloaded.txt
                    with downloaded_path.open("a", encoding="utf-8") as downloaded_file:
                        downloaded_file.write(f"{digits}\n")
                    already.add(digits)

                    print("\n\n prossimo file...\n\n")

        # pulizia input.txt
        print("Pulizia input.txt...")
        if input_file.exists():
            input_file.unlink()
        input_file.touch()

    except Exception as e:
        print(f"ERRORE: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Suggerimento: per aggiornamenti fluidi della barra, esegui in modalità unbuffered:
    # python -u script.py
    main()