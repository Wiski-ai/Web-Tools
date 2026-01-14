#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fentanyle.py - Terminal GUI wrapper for curl
Author : H8Laws (refactor)
License: Use responsibly
Requires: Python 3.6+, curl installed on PATH

Refactor notes:
- Improved streaming of stdout/stderr
- Better history handling (pathlib, json)
- Clearer structure and comments
- Minimal logging to ~/.fentanyle.log
"""
from __future__ import annotations

import curses
import curses.textpad
import subprocess
import shlex
import threading
import time
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Tuple, Optional
import shutil
import logging

ASCII_ART = r"""
█████▒▓█████  ███▄    █ ▄▄▄█████▓ ▄▄▄       ███▄    █▓██   ██▓ ██▓    ▓█████
▓██   ▒ ▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒▒████▄     ██ ▀█   █ ▒██  ██▒▓██▒    ▓█   ▀
▒████ ░ ▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░▒██  ▀█▄  ▓██  ▀█ ██▒ ▒██ ██░▒██░    ▒███
░▓█▒  ░ ▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▓██▒  ▐▌██▒ ░ ▐██▓░▒██░    ▒▓█  ▄
░▒█░    ░▒████▒▒██░   ▓██░  ▒██▒ ░  ▓█   ▓██▒▒██░   ▓██░ ░ ██▒▓░░██████▒░▒████▒
 ▒ ░    ░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░    ▒▒   ▓▒█░░ ▒░   ▒ ▒   ██▒▒▒ ░ ▒░▓  ░░░ ▒░ ░
 ░       ░ ░  ░░ ░░   ░ ▒░    ░      ▒   ▒▒ ░░ ░░   ░ ▒░▓██ ░▒░ ░ ░ ▒  ░ ░ ░  ░
 ░ ░       ░      ░   ░ ░   ░        ░   ▒      ░   ░ ░ ▒ ▒ ░░    ░ ░      ░
           ░  ░         ░                ░  ░         ░ ░ ░         ░  ░   ░  ░
                                                        ░ ░
"""

HISTORY_PATH = Path.home() / ".fentanyle_history"
LOG_PATH = Path.home() / ".fentanyle.log"
HISTORY_MAX = 200
OUTPUT_LINES_MAX = 1000

# Setup minimal logging
logging.basicConfig(filename=str(LOG_PATH), level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s")


def ensure_history_file() -> None:
    """Ensure history file exists and is a JSON array."""
    try:
        if not HISTORY_PATH.exists():
            HISTORY_PATH.write_text("[]", encoding="utf-8")
    except Exception as exc:
        logging.exception("Failed to create history file: %s", exc)


def append_history(entry: dict) -> None:
    """Append an entry to history; keep only last HISTORY_MAX entries."""
    try:
        ensure_history_file()
        with HISTORY_PATH.open("r+", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = []
            except json.JSONDecodeError:
                data = []
            data.append(entry)
            data = data[-HISTORY_MAX:]
            f.seek(0)
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.truncate()
    except Exception as exc:
        logging.exception("append_history failed: %s", exc)


def load_history() -> List[dict]:
    """Load history entries, return empty list on error."""
    try:
        ensure_history_file()
        with HISTORY_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as exc:
        logging.exception("load_history failed: %s", exc)
        return []


class CurlRunner(threading.Thread):
    """
    Run a curl command and stream stdout/stderr through callback.
    Callback signature: callback(text: str, is_err: bool) -> None
    """

    def __init__(self, cmd_list: List[str], callback: Optional[Callable[[str, bool], None]] = None):
        super().__init__(daemon=True)
        self.cmd_list = cmd_list
        self.callback = callback
        self.proc: Optional[subprocess.Popen] = None
        self.output = ""
        self.error = ""
        self.exitcode: Optional[int] = None

    def _reader(self, stream, is_err: bool, accumulate: List[str]) -> None:
        try:
            for line in iter(stream.readline, ""):
                if line == "":
                    break
                accumulate.append(line)
                if self.callback:
                    self.callback(line, is_err)
        except Exception as exc:
            logging.exception("reader exception: %s", exc)
            if self.callback:
                self.callback(f"Reader exception: {exc}\n", True)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def run(self):
        try:
            logging.debug("Executing: %s", self.cmd_list)
            self.proc = subprocess.Popen(
                self.cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1
            )
            out_lines: List[str] = []
            err_lines: List[str] = []
            threads = []
            if self.proc.stdout:
                t_out = threading.Thread(target=self._reader, args=(self.proc.stdout, False, out_lines), daemon=True)
                t_out.start()
                threads.append(t_out)
            if self.proc.stderr:
                t_err = threading.Thread(target=self._reader, args=(self.proc.stderr, True, err_lines), daemon=True)
                t_err.start()
                threads.append(t_err)
            # Wait for process to end
            self.proc.wait()
            # join readers
            for t in threads:
                t.join(timeout=1.0)
            self.output = "".join(out_lines)
            self.error = "".join(err_lines)
            self.exitcode = self.proc.returncode
            logging.debug("Process exited %s", self.exitcode)
        except Exception as exc:
            logging.exception("CurlRunner run failed: %s", exc)
            self.error += f"\nException running curl: {exc}"
            if self.callback:
                self.callback(str(exc) + "\n", True)


class Field:
    """
    Minimal text field for curses UI.
    Supports single-line and rudimentary multiline.
    """
    def __init__(self, y: int, x: int, h: int, w: int, label: str, default: str = ""):
        self.y = y
        self.x = x
        self.h = h
        self.w = w
        self.label = label
        self.text = default
        self.cursor = len(default)
        self.win: Optional[curses.window] = None

    def draw(self, stdscr, active: bool = False) -> None:
        """Draw the labeled box and text inside."""
        stdscr.addstr(self.y, self.x, self.label[:self.w - 2])
        win = curses.newwin(self.h, self.w, self.y + 1, self.x)
        win.border()
        txtwin = win.derwin(self.h - 2, self.w - 2, 1, 1)
        txtwin.erase()
        # Display text with wrapping for multiline
        lines = self.text.splitlines() or [""]
        for i, ln in enumerate(lines[: self.h - 2]):
            try:
                txtwin.addstr(i, 0, ln[: self.w - 3])
            except Exception:
                pass
        if active:
            curses.curs_set(1)
            # compute cursor position (row, col)
            cur_row = min(len(lines) - 1, (self.text[:self.cursor].count("\n")))
            cur_col = len(self.text[:self.cursor].split("\n")[-1])
            screen_row = self.y + 2 + cur_row
            screen_col = self.x + 1 + min(cur_col, self.w - 3)
            try:
                stdscr.move(screen_row, screen_col)
            except Exception:
                pass
        else:
            curses.curs_set(0)
        win.refresh()
        self.win = txtwin

    def handle_key(self, ch: int) -> None:
        """Handle typical editing keys."""
        # Common backspace codes
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.cursor > 0:
                self.text = self.text[:self.cursor - 1] + self.text[self.cursor:]
                self.cursor -= 1
        elif ch == curses.KEY_DC:  # Delete
            if self.cursor < len(self.text):
                self.text = self.text[:self.cursor] + self.text[self.cursor + 1:]
        elif ch == curses.KEY_LEFT:
            if self.cursor > 0:
                self.cursor -= 1
        elif ch == curses.KEY_RIGHT:
            if self.cursor < len(self.text):
                self.cursor += 1
        elif ch == curses.KEY_HOME:
            # move to start of current line
            prev_newline = self.text.rfind("\n", 0, self.cursor)
            self.cursor = 0 if prev_newline == -1 else prev_newline + 1
        elif ch == curses.KEY_END:
            next_newline = self.text.find("\n", self.cursor)
            self.cursor = len(self.text) if next_newline == -1 else next_newline
        elif ch in (10, 13):  # Enter -> insert newline for multiline fields
            # Only allow newline if field height > 1
            if self.h > 3:
                self.text = self.text[:self.cursor] + "\n" + self.text[self.cursor:]
                self.cursor += 1
        elif 32 <= ch <= 126:
            self.text = self.text[:self.cursor] + chr(ch) + self.text[self.cursor:]
            self.cursor += 1
        # ignore other keys


def build_curl_cmd(url: str, method: str, headers: str, data: str, extra: str, outfile: str) -> List[str]:
    """
    Build a curl command list safely.
    - headers are separated by ';' or newline.
    - data starting with @ is passed as --data-binary (file upload).
    """
    cmd = ["curl", "-sS", "--location"]
    method = (method or "GET").upper()
    if method and method != "GET":
        cmd += ["-X", method]
    # Headers: accept ';' separated or newlines
    hdrs = []
    for part in headers.replace("\r", "").split(";"):
        for sub in part.splitlines():
            s = sub.strip()
            if s:
                hdrs.append(s)
    for h in hdrs:
        cmd += ["-H", h]
    data = data or ""
    if data.strip():
        if data.strip().startswith("@"):
            cmd += ["--data-binary", data.strip()]
        else:
            cmd += ["--data-raw", data]
    if extra and extra.strip():
        try:
            extra_parts = shlex.split(extra)
            cmd += extra_parts
        except Exception:
            cmd += [extra]
    if outfile and outfile.strip():
        cmd += ["-o", outfile.strip()]
    cmd += [url]
    return cmd


def format_command_for_history(cmd_list: List[str]) -> str:
    """Return shell-friendly representation of the command."""
    try:
        # shlex.join available in 3.8+
        return shlex.join(cmd_list)  # type: ignore[attr-defined]
    except Exception:
        # fallback
        return " ".join(shlex.quote(p) for p in cmd_list)


def draw_centered(stdscr, lines: List[str]) -> None:
    h, w = stdscr.getmaxyx()
    for i, line in enumerate(lines):
        if i >= h:
            break
        try:
            stdscr.addstr(i, max(0, (w - len(line)) // 2), line)
        except Exception:
            pass


def show_splash(stdscr) -> None:
    stdscr.clear()
    try:
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
    except Exception:
        pass
    lines = ASCII_ART.splitlines()
    draw_centered(stdscr, lines)
    h, w = stdscr.getmaxyx()
    hint = "fentanyle - interface curl - appuyez sur une touche pour continuer"
    try:
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(min(h - 2, len(lines) + 2), max(0, (w - len(hint)) // 2), hint)
        stdscr.attroff(curses.color_pair(1))
    except Exception:
        try:
            stdscr.addstr(min(h - 2, len(lines) + 2), max(0, (w - len(hint)) // 2), hint)
        except Exception:
            pass
    stdscr.refresh()
    stdscr.getch()


def check_curl_installed() -> bool:
    return shutil.which("curl") is not None


# UI helper functions (show_message, show_history, show_output_screen) kept similar to original but cleaned


def show_message(stdscr, title: str, text: str) -> None:
    h, w = stdscr.getmaxyx()
    win_h = min(12, max(6, h - 4))
    win_w = min(int(w * 0.8), w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h) // 2, (w - win_w) // 2)
    win.border()
    win.addstr(0, 2, f" {title} ")
    lines = text.splitlines() or [text]
    for i, line in enumerate(lines[: win_h - 3]):
        try:
            win.addstr(1 + i, 1, line[: win_w - 2])
        except Exception:
            pass
    try:
        win.addstr(win_h - 2, 1, "Appuyez sur une touche pour fermer")
    except Exception:
        pass
    win.refresh()
    win.getch()
    win.clear()
    stdscr.touchwin()
    stdscr.refresh()


def show_history(stdscr, hist: List[dict]) -> None:
    h, w = stdscr.getmaxyx()
    win_h = min(h - 2, max(10, len(hist) + 4))
    win_w = min(w - 4, 120)
    win = curses.newwin(win_h, win_w, 1, (w - win_w) // 2)
    win.keypad(True)
    win.border()
    win.addstr(0, 2, " Historique ")
    if not hist:
        win.addstr(2, 2, "Aucun historique enregistré.")
        win.addstr(win_h - 2, 2, "Appuyez sur une touche pour revenir")
        win.refresh()
        win.getch()
        return
    idx = max(0, len(hist) - (win_h - 4))
    while True:
        win.erase()
        win.border()
        win.addstr(0, 2, " Historique ")
        display = hist[idx: idx + (win_h - 4)]
        for i, e in enumerate(display):
            t = e.get("time", "")[:19]
            cmd = e.get("cmd", "")[: win_w - 30]
            code = e.get("exitcode", "")
            try:
                win.addstr(1 + i, 2, f"{idx + i + 1:3d}. {t} ({code}) {cmd}")
            except Exception:
                pass
        win.addstr(win_h - 2, 2, "[Flèche haut/bas] pour naviguer  [Entrée] Voir sortie  [q] Quitter")
        win.refresh()
        c = win.getch()
        if c in (ord("q"), ord("Q")):
            break
        elif c == curses.KEY_UP:
            if idx > 0:
                idx -= 1
        elif c == curses.KEY_DOWN:
            if idx + (win_h - 4) < len(hist):
                idx += 1
        elif c in (10, 13):
            sel = idx
            if sel < len(hist):
                e = hist[sel]
                show_message(
                    stdscr,
                    f"Entrée #{sel + 1}",
                    f"Time: {e.get('time')}\nCmd: {e.get('cmd')}\nExit: {e.get('exitcode')}\n\nPreview:\n{e.get('output_preview')}",
                )
        else:
            continue


def show_output_screen(stdscr, output_lines: List[Tuple[str, str]], last_cmd: Optional[List[str]]) -> None:
    h, w = stdscr.getmaxyx()
    win_h = h - 2
    win_w = w - 2
    win = curses.newwin(win_h, win_w, 1, 1)
    win.keypad(True)
    win.border()
    win.addstr(0, 2, " Sortie complète (q pour quitter) ")
    idx = 0
    while True:
        win.erase()
        win.border()
        win.addstr(0, 2, " Sortie complète (q pour quitter) ")
        if last_cmd:
            try:
                win.addstr(1, 2, "Commande: " + format_command_for_history(last_cmd)[: win_w - 4])
            except Exception:
                pass
        max_lines = win_h - 5
        chunk = output_lines[idx: idx + max_lines]
        for i, (typ, ln) in enumerate(chunk):
            try:
                if typ == "ERR":
                    win.addstr(3 + i, 2, ln[: win_w - 4], curses.A_BOLD)
                else:
                    win.addstr(3 + i, 2, ln[: win_w - 4])
            except Exception:
                pass
        try:
            win.addstr(win_h - 2, 2, f"[PgUp/PgDn] scroll  {idx+1}/{max(1, len(output_lines))}  [q] quitter")
        except Exception:
            pass
        win.refresh()
        c = win.getch()
        if c in (ord("q"), ord("Q")):
            break
        elif c == curses.KEY_NPAGE:
            idx = min(len(output_lines) - max_lines, idx + max_lines) if len(output_lines) > max_lines else 0
            if idx < 0:
                idx = 0
        elif c == curses.KEY_PPAGE:
            idx = max(0, idx - max_lines)
        else:
            pass


def main_ui(stdscr) -> None:
    curses.curs_set(0)
    curses.use_default_colors()
    stdscr.nodelay(False)
    stdscr.keypad(True)
    try:
        curses.start_color()
    except Exception:
        pass

    # default fields
    url_field = Field(1, 2, 3, 70, "URL:", "https://example.com")
    method_field = Field(5, 2, 3, 20, "Method (GET/POST/...):", "GET")
    headers_field = Field(9, 2, 3, 70, "Headers (séparés par ;):", "")
    data_field = Field(13, 2, 5, 70, "Data (utilisez @file pour fichier):", "")
    extra_field = Field(19, 2, 3, 70, "Options curl supplémentaires :", "")
    outfile_field = Field(23, 2, 3, 70, "Sauvegarder sortie dans fichier :", "")

    fields = [url_field, method_field, headers_field, data_field, extra_field, outfile_field]
    active_index = 0

    output_lines: List[Tuple[str, str]] = []
    status = "Prêt"
    last_cmd: Optional[List[str]] = None
    last_output = ""
    runner: Optional[CurlRunner] = None

    def append_output(text: str, is_err: bool = False) -> None:
        nonlocal output_lines
        for line in text.splitlines(True):
            output_lines.append(("ERR" if is_err else "OUT", line.rstrip("\n")))
        if len(output_lines) > OUTPUT_LINES_MAX:
            output_lines = output_lines[-OUTPUT_LINES_MAX:]
        refresh_ui()

    def refresh_ui() -> None:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        title = "fentanyle - wrapper curl (interface terminal)"
        try:
            stdscr.addstr(0, max(0, (w - len(title)) // 2), title, curses.A_BOLD)
        except Exception:
            pass
        for idx, f in enumerate(fields):
            f.draw(stdscr, active=(idx == active_index))
        btns = "[TAB] suivant  [Entrée] exécuter  [h] historique  [o] voir sortie  [c] copier commande  [q] quitter"
        try:
            stdscr.addstr(h - 2, 2, btns[: w - 4])
            stdscr.addstr(h - 3, 2, f"Statut: {status}"[: w - 4])
        except Exception:
            pass
        preview_x = 76
        if w > 120:
            try:
                stdscr.addstr(1, preview_x, "Sortie (aperçu):", curses.A_UNDERLINE)
                max_preview_lines = h - 6
                for i, (typ, ln) in enumerate(output_lines[-max_preview_lines:]):
                    if typ == "ERR":
                        stdscr.addstr(2 + i, preview_x, ln[: w - preview_x - 2], curses.A_BOLD)
                    else:
                        stdscr.addstr(2 + i, preview_x, ln[: w - preview_x - 2])
            except Exception:
                pass
        stdscr.refresh()

    refresh_ui()

    while True:
        refresh_ui()
        ch = stdscr.getch()
        if ch == -1:
            time.sleep(0.03)
            continue
        if ch in (9, curses.KEY_TAB):
            active_index = (active_index + 1) % len(fields)
        elif ch in (curses.KEY_BTAB,):
            active_index = (active_index - 1) % len(fields)
        elif ch in (ord("q"), ord("Q")):
            break
        elif ch in (curses.KEY_ENTER, 10, 13):
            # Execute
            url = url_field.text.strip()
            method = method_field.text.strip() or "GET"
            headers = headers_field.text
            data = data_field.text
            extra = extra_field.text
            outfile = outfile_field.text.strip()
            if not url:
                status = "URL vide!"
                continue
            if not check_curl_installed():
                status = "curl introuvable sur le PATH"
                continue
            cmd_list = build_curl_cmd(url, method, headers, data, extra, outfile)
            last_cmd = cmd_list
            status = "Exécution..."
            output_lines = []
            runner = CurlRunner(cmd_list, callback=append_output)
            runner.start()

            def waiter(runner_obj: CurlRunner) -> None:
                nonlocal status, last_output
                runner_obj.join()
                status = f"Terminé (code {runner_obj.exitcode})"
                last_output = runner_obj.output + ("\n" + runner_obj.error if runner_obj.error else "")
                entry = {
                    "time": datetime.utcnow().isoformat() + "Z",
                    "cmd": format_command_for_history(cmd_list),
                    "exitcode": runner_obj.exitcode,
                    "output_preview": (runner_obj.output + runner_obj.error)[: 2000],
                }
                append_history(entry)

            t = threading.Thread(target=waiter, args=(runner,), daemon=True)
            t.start()
        elif ch in (ord("h"), ord("H")):
            hist = load_history()
            show_history(stdscr, hist)
        elif ch in (ord("o"), ord("O")):
            show_output_screen(stdscr, output_lines, last_cmd)
        elif ch in (ord("c"), ord("C")):
            if last_cmd:
                show_message(stdscr, "Commande:", format_command_for_history(last_cmd))
            else:
                show_message(stdscr, "Info", "Aucune commande exécutée encore.")
        else:
            if 0 <= active_index < len(fields):
                fields[active_index].handle_key(ch)


def main(stdscr) -> None:
    try:
        show_splash(stdscr)
        main_ui(stdscr)
    except Exception as e:
        # Ensure curses is cleaned up
        try:
            curses.endwin()
        except Exception:
            pass
        print("Erreur :", e)
        logging.exception("main crashed: %s", e)


if __name__ == "__main__":
    try:
        ensure_history_file()
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nInterrompu par utilisateur.")
    except Exception as exc:
        logging.exception("Unhandled exception: %s", exc)
        print("Erreur inattendue:", exc)