#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fentanyle.py - Terminal GUI wrapper for curl (single-file)
Author: H8Laws
License: Use responsibly
Requires: Python 3.6+, curl installed on PATH

Fonctionnalités :
- Affiche ASCII art au démarrage
- Formulaire minimal pour URL, méthode, headers, data, options supplémentaires
- Exécute curl et affiche stdout/stderr dans la fenêtre
- Sauvegarde historique dans ~/.fentanyle_history (commandes et sorties)
- Navigation clavier simple : TAB pour changer de champ, flèches pour menu, Entrée pour exécuter, q pour quitter
"""

import curses
import curses.textpad
import subprocess
import shlex
import threading
import time
import os
import json
from datetime import datetime

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

HISTORY_PATH = os.path.expanduser('~/.fentanyle_history')

# Ensure history file exists
if not os.path.exists(HISTORY_PATH):
    try:
        with open(HISTORY_PATH, 'w') as f:
            json.dump([], f)
    except Exception:
        pass

def append_history(entry):
    try:
        with open(HISTORY_PATH, 'r+', encoding='utf-8') as f:
            data = []
            try:
                data = json.load(f)
            except Exception:
                data = []
            data.append(entry)
            f.seek(0)
            json.dump(data[-200:], f, indent=2)  # keep last 200
            f.truncate()
    except Exception:
        pass

def load_history():
    try:
        with open(HISTORY_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

class CurlRunner(threading.Thread):
    def __init__(self, cmd_list, callback=None):
        super().__init__(daemon=True)
        self.cmd_list = cmd_list
        self.callback = callback
        self.proc = None
        self.output = ""
        self.error = ""
        self.exitcode = None

    def run(self):
        try:
            self.proc = subprocess.Popen(self.cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out_lines = []
            err_lines = []
            # Read progressively
            while True:
                out = self.proc.stdout.readline()
                if out:
                    out_lines.append(out)
                    if self.callback:
                        self.callback(out, False)
                elif self.proc.poll() is not None:
                    break
            # collect rest
            remaining_out, remaining_err = self.proc.communicate()
            if remaining_out:
                out_lines.append(remaining_out)
                if self.callback:
                    self.callback(remaining_out, False)
            if remaining_err:
                err_lines.append(remaining_err)
                if self.callback:
                    self.callback(remaining_err, True)
            self.output = ''.join(out_lines)
            self.error = ''.join(err_lines)
            self.exitcode = self.proc.returncode
        except Exception as e:
            self.error += f"\nException running curl: {e}"
            if self.callback:
                self.callback(str(e), True)

class Field:
    def __init__(self, y, x, h, w, label, default=""):
        self.win = None
        self.y = y
        self.x = x
        self.h = h
        self.w = w
        self.label = label
        self.text = default
        self.cursor = len(self.text)

    def draw(self, stdscr, active=False):
        stdscr.addstr(self.y, self.x, self.label)
        win = curses.newwin(self.h, self.w, self.y+1, self.x)
        win.border()
        txtwin = win.derwin(self.h-2, self.w-2, 1, 1)
        txtwin.addstr(0, 0, self.text[:self.w-3])
        if active:
            curses.curs_set(1)
            stdscr.move(self.y+2, self.x+1 + min(self.cursor, self.w-3))
        else:
            curses.curs_set(0)
        win.refresh()
        self.win = txtwin

    def handle_key(self, ch):
        if ch in (curses.KEY_BACKSPACE, 127):
            if self.cursor > 0:
                self.text = self.text[:self.cursor-1] + self.text[self.cursor:]
                self.cursor -= 1
        elif ch in (curses.KEY_LEFT,):
            if self.cursor > 0: self.cursor -= 1
        elif ch in (curses.KEY_RIGHT,):
            if self.cursor < len(self.text): self.cursor += 1
        elif ch in (curses.KEY_HOME,):
            self.cursor = 0
        elif ch in (curses.KEY_END,):
            self.cursor = len(self.text)
        elif 32 <= ch <= 126:
            self.text = self.text[:self.cursor] + chr(ch) + self.text[self.cursor:]
            self.cursor += 1

def build_curl_cmd(url, method, headers, data, extra, outfile):
    cmd = ['curl', '-sS', '--location']  # silent but show errors, follow redirects
    method = method.upper()
    if method and method != 'GET':
        cmd += ['-X', method]
    if headers.strip():
        for h in headers.split(';'):
            h = h.strip()
            if h:
                cmd += ['-H', h]
    if data.strip():
        # If data seems like @file, pass as is
        if data.strip().startswith('@'):
            cmd += ['--data-binary', data.strip()]
        else:
            cmd += ['--data-raw', data]
    if extra.strip():
        # split safely
        try:
            extra_parts = shlex.split(extra)
            cmd += extra_parts
        except Exception:
            cmd += [extra]
    if outfile.strip():
        cmd += ['-o', outfile]
    cmd += [url]
    return cmd

def format_command_for_history(cmd_list):
    # Return string form for display
    return ' '.join(shlex.quote(p) for p in cmd_list)

def draw_centered(stdscr, lines):
    h, w = stdscr.getmaxyx()
    for i, line in enumerate(lines):
        if i >= h: break
        try:
            stdscr.addstr(i, max(0, (w - len(line)) // 2), line)
        except:
            pass

def show_splash(stdscr):
    stdscr.clear()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    lines = ASCII_ART.splitlines()
    draw_centered(stdscr, lines)
    h, w = stdscr.getmaxyx()
    hint = "fentanyle - interface curl - appuyez sur une touche pour continuer"
    stdscr.attron(curses.color_pair(1))
    stdscr.addstr(min(h-2, len(lines)+2), max(0, (w - len(hint))//2), hint)
    stdscr.attroff(curses.color_pair(1))
    stdscr.refresh()
    stdscr.getch()

def main_ui(stdscr):
    curses.curs_set(0)
    curses.use_default_colors()
    stdscr.nodelay(False)
    stdscr.keypad(True)

    # default values
    url_field = Field(1, 2, 3, 70, "URL:", "https://example.com")
    method_field = Field(5, 2, 3, 20, "Method (GET/POST/...):", "GET")
    headers_field = Field(9, 2, 3, 70, "Headers (séparés par ; e.g. 'User-Agent: x; Authorization: Bearer ...'):", "")
    data_field = Field(13, 2, 5, 70, "Data (si POST, utilisez @filename pour fichier):", "")
    extra_field = Field(19, 2, 3, 70, "Options curl supplémentaires (ex: --insecure -k):", "")
    outfile_field = Field(23, 2, 3, 70, "Sauvegarder sortie dans fichier (laisser vide pour stdout):", "")

    fields = [url_field, method_field, headers_field, data_field, extra_field, outfile_field]
    active_index = 0

    output_lines = []
    status = "Prêt"
    last_cmd = None
    last_output = ""
    runner = None

    def append_output(text, is_err=False):
        nonlocal output_lines
        for line in text.splitlines(True):
            if is_err:
                output_lines.append(("ERR", line.rstrip('\n')))
            else:
                output_lines.append(("OUT", line.rstrip('\n')))
        # cap
        if len(output_lines) > 1000:
            output_lines = output_lines[-1000:]
        # refresh screen
        refresh_ui()

    def refresh_ui():
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        # Title
        title = "fentanyle - wrapper curl (interface terminal)"
        stdscr.addstr(0, max(0, (w - len(title))//2), title, curses.A_BOLD)
        # draw fields
        for idx, f in enumerate(fields):
            f.draw(stdscr, active=(idx == active_index))
        # buttons / help
        btns = "[TAB] suivant  [Entrée] exécuter  [h] historique  [o] voir sortie  [c] copier commande  [q] quitter"
        stdscr.addstr(h-2, 2, btns[:w-4])
        stdscr.addstr(h-3, 2, f"Statut: {status}"[:w-4])
        # output preview (right side)
        preview_x = 76
        if w > 120:
            stdscr.addstr(1, preview_x, "Sortie (aperçu):", curses.A_UNDERLINE)
            max_preview_lines = h - 6
            for i, (typ, ln) in enumerate(output_lines[-max_preview_lines:]):
                try:
                    if typ == "ERR":
                        stdscr.addstr(2+i, preview_x, ln[:w-preview_x-2], curses.color_pair(0) | curses.A_BOLD)
                    else:
                        stdscr.addstr(2+i, preview_x, ln[:w-preview_x-2])
                except:
                    pass
        stdscr.refresh()

    refresh_ui()

    while True:
        refresh_ui()
        ch = stdscr.getch()
        if ch == -1:
            time.sleep(0.05)
            continue
        if ch in (9, curses.KEY_TAB):
            active_index = (active_index + 1) % len(fields)
        elif ch in (curses.KEY_BTAB,):
            active_index = (active_index - 1) % len(fields)
        elif ch in (ord('q'), ord('Q')):
            break
        elif ch in (curses.KEY_ENTER, 10, 13):
            # Execute
            url = url_field.text.strip()
            method = method_field.text.strip() or "GET"
            headers = headers_field.text.strip()
            data = data_field.text
            extra = extra_field.text
            outfile = outfile_field.text.strip()
            if not url:
                status = "URL vide!"
                continue
            cmd_list = build_curl_cmd(url, method, headers, data, extra, outfile)
            last_cmd = cmd_list
            status = "Exécution..."
            output_lines = []
            runner = CurlRunner(cmd_list, callback=append_output)
            runner.start()
            # Wait for runner to finish in background, but keep UI responsive
            def waiter(runner_obj):
                nonlocal status, last_output
                runner_obj.join()
                status = f"Terminé (code {runner_obj.exitcode})"
                last_output = runner_obj.output + ("\n" + runner_obj.error if runner_obj.error else "")
                # save history
                entry = {
                    "time": datetime.utcnow().isoformat() + "Z",
                    "cmd": format_command_for_history(cmd_list),
                    "exitcode": runner_obj.exitcode,
                    "output_preview": (runner_obj.output + runner_obj.error)[:2000]
                }
                append_history(entry)
            t = threading.Thread(target=waiter, args=(runner,), daemon=True)
            t.start()
        elif ch in (ord('h'), ord('H')):
            # show history
            hist = load_history()
            show_history(stdscr, hist)
        elif ch in (ord('o'), ord('O')):
            # show last output full
            show_output_screen(stdscr, output_lines, last_cmd)
        elif ch in (ord('c'), ord('C')):
            # copy command: just display it in a popup
            if last_cmd:
                show_message(stdscr, "Commande:", format_command_for_history(last_cmd))
            else:
                show_message(stdscr, "Aucune commande exécutée encore.", "")
        else:
            # pass key to active field
            if 0 <= active_index < len(fields):
                fields[active_index].handle_key(ch)

def show_message(stdscr, title, text):
    h, w = stdscr.getmaxyx()
    win_h = min(10, h-4)
    win_w = min(int(w*0.8), w-4)
    win = curses.newwin(win_h, win_w, (h-win_h)//2, (w-win_w)//2)
    win.border()
    win.addstr(0, 2, f" {title} ")
    lines = text.splitlines() or [text]
    for i, line in enumerate(lines[:win_h-2]):
        try:
            win.addstr(1+i, 1, line[:win_w-2])
        except:
            pass
    win.addstr(win_h-1, 1, "Appuyez sur une touche pour fermer")
    win.refresh()
    win.getch()
    win.clear()
    stdscr.touchwin()
    stdscr.refresh()

def show_history(stdscr, hist):
    h, w = stdscr.getmaxyx()
    win_h = min(h-2, max(10, len(hist)+4))
    win_w = min(w-4, 120)
    win = curses.newwin(win_h, win_w, 1, (w-win_w)//2)
    win.keypad(True)
    win.border()
    win.addstr(0, 2, " Historique ")
    if not hist:
        win.addstr(2, 2, "Aucun historique enregistré.")
        win.addstr(win_h-2, 2, "Appuyez sur une touche pour revenir")
        win.refresh()
        win.getch()
        return
    # show entries with navigation
    idx = max(0, len(hist)- (win_h-4))
    while True:
        win.erase()
        win.border()
        win.addstr(0, 2, " Historique ")
        display = hist[idx: idx + (win_h-4)]
        for i, e in enumerate(display):
            t = e.get('time', '')[:19]
            cmd = e.get('cmd', '')[:win_w-30]
            code = e.get('exitcode', '')
            win.addstr(1+i, 2, f"{idx+i+1:3d}. {t} ({code}) {cmd}")
        win.addstr(win_h-2, 2, "[Flèche haut/bas] pour naviguer  [Entrée] Voir sortie  [q] Quitter")
        win.refresh()
        c = win.getch()
        if c in (ord('q'), ord('Q')):
            break
        elif c in (curses.KEY_UP,):
            if idx > 0: idx -= 1
        elif c in (curses.KEY_DOWN,):
            if idx + (win_h-4) < len(hist): idx += 1
        elif c in (10, 13):
            # show selected
            sel = idx
            if sel < len(hist):
                e = hist[sel]
                show_message(stdscr, f"Entrée #{sel+1}", f"Time: {e.get('time')}\nCmd: {e.get('cmd')}\nExit: {e.get('exitcode')}\n\nPreview:\n{e.get('output_preview')}")
        else:
            continue

def show_output_screen(stdscr, output_lines, last_cmd):
    h, w = stdscr.getmaxyx()
    win_h = h-2
    win_w = w-2
    win = curses.newwin(win_h, win_w, 1, 1)
    win.keypad(True)
    win.border()
    win.addstr(0, 2, " Sortie complète (q pour quitter) ")
    # display with paging
    idx = 0
    while True:
        win.erase()
        win.border()
        win.addstr(0, 2, " Sortie complète (q pour quitter) ")
        # show last_cmd
        if last_cmd:
            win.addstr(1, 2, "Commande: " + format_command_for_history(last_cmd)[:win_w-4])
        # show chunk of output_lines
        max_lines = win_h - 5
        chunk = output_lines[idx: idx+max_lines]
        for i, (typ, ln) in enumerate(chunk):
            try:
                if typ == "ERR":
                    win.addstr(3+i, 2, ln[:win_w-4], curses.A_BOLD)
                else:
                    win.addstr(3+i, 2, ln[:win_w-4])
            except:
                pass
        win.addstr(win_h-2, 2, f"[PgUp/PgDn] scroll  {idx+1}/{max(1, len(output_lines))}  [q] quitter")
        win.refresh()
        c = win.getch()
        if c in (ord('q'), ord('Q')):
            break
        elif c == curses.KEY_NPAGE:
            idx = min(len(output_lines)-max_lines, idx+max_lines) if len(output_lines) > max_lines else 0
            if idx < 0: idx = 0
        elif c == curses.KEY_PPAGE:
            idx = max(0, idx-max_lines)
        else:
            pass

def main(stdscr):
    try:
        show_splash(stdscr)
        main_ui(stdscr)
    except Exception as e:
        curses.endwin()
        print("Erreur :", e)

if __name__ == '__main__':
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nInterrompu par utilisateur.")