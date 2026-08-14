import hashlib
import os
import time
import requests
import threading
import json
import re
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
import sys
import webbrowser

if sys.platform == "win32":
    import winsound

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

ctk.deactivate_automatic_dpi_awareness()
ctk.set_widget_scaling(1.0)
ctk.set_window_scaling(1.0)

LANG = {
    "ru": {
        "title": "VirusTotal Scanner Pro",
        "select_file": "Выбрать файл",
        "scanning": "Сканирование...",
        "ready": "Готов к работе",
        "no_file": "Файл не выбран",
        "file_info": "Информация о файле",
        "actions": "Действия",
        "status": "Статус",
        "results": "Результаты сканирования",
        "clear": "Очистить",
        "about": "О программе",
        "change_api_key": "Сменить API ключ",
        "settings": "Настройки",
        "copy": "Копировать",
        "copy_hash": "Копировать хеш",
        "open_in_browser": "Открыть на VirusTotal",
        "file_not_selected": "Файл не выбран",
        "size": "Размер",
        "sha256": "SHA-256",
        "api_key_dialog_title": "Настройка API ключа",
        "api_key_dialog_text": "Введите ваш API ключ VirusTotal:\n(можно вставить через Ctrl+V)",
        "api_key_warning": "API ключ не введен. Программа будет работать некорректно!",
        "api_key_updated": "API ключ успешно обновлен!",
        "api_key_update_status": "API ключ обновлен",
        "hash_copied": "Хеш скопирован!",
        "hash_not_found": "Хеш не найден",
        "text_copied": "Текст скопирован!",
        "text_pasted": "Текст вставлен!",
        "no_text_to_copy": "Нет текста для копирования",
        "output_cleared": "Вывод очищен",
        "browser_opened": "Открыто в браузере",
        "hash_calc": "Вычисление SHA-256...",
        "checking_db": "Проверка в базе VirusTotal...",
        "file_not_in_db": "Файл не найден в базе. Загрузка...",
        "uploading": "Загрузка файла на сервер...",
        "file_uploaded": "Файл загружен!",
        "file_found_in_db": "Файл найден в базе!",
        "ready_report_from_db": "Готовый отчет из базы!",
        "waiting_scan": "Ожидание проверки антивирусами...",
        "waiting_scan_text": "Ожидание проверки (до 7 минут)...",
        "scan_complete": "Проверка завершена!",
        "timeout_warning": "Время ожидания истекло",
        "check_later": "Проверьте позже",
        "error_network": "Нет подключения к интернету!",
        "error_timeout": "Превышено время ожидания!",
        "error_fail": "Сбой",
        "no_detections": "ЧИСТО! Ни один антивирус не нашел угроз.",
        "threats_detected": "ОБНАРУЖЕНЫ УГРОЗЫ",
        "total_detections": "Всего обнаружений",
        "full_report": "Полный отчет",
        "comments": "КОММЕНТАРИИ",
        "no_comments": "Комментариев нет",
        "stats": "СТАТИСТИКА",
        "harmless": "Безопасные",
        "undetected": "Не обнаружено",
        "suspicious": "Подозрительные",
        "malicious": "Вредоносные",
        "timeout_stats": "Таймаут",
        "reputation": "РЕЙТИНГ СООБЩЕСТВА",
        "votes_for": "За",
        "votes_against": "Против",
        "settings_window": "Настройки",
        "theme": "Тема",
        "dark": "Тёмная",
        "light": "Светлая",
        "system": "Системная",
        "sound": "Звук при завершении сканирования",
        "api_type": "Тип API ключа",
        "free": "Бесплатный",
        "paid": "Платный",
        "close_to_tray": "Закрывать в трей",
        "autostart": "Запускать вместе с Windows",
        "save": "Сохранить",
        "reset": "Сбросить",
        "thanks_title": "Спасибо!",
        "thanks_text": "Спасибо что скачал\n\nЯ не знаю где ты это использовать будешь \nно используй ¯\\_(ツ)_/¯",
        "thanks_body": "Спасибо что скачал",
        "thanks_subtext": "Я не знаю где ты это использовать будешь \nно используй ¯\\_(ツ)_/¯",
        "dont_show_again": "Не показывать в следующий раз",
        "ok": "ОК",
        "cancel": "Отмена",
        "about_program": "О программе",
        "welcome": "Добро пожаловать в VirusTotal Scanner Pro!",
        "instructions": "Инструкция",
        "instruction_1": "1. Нажмите 'Выбрать файл' для загрузки",
        "instruction_2": "2. Дождитесь завершения сканирования",
        "instruction_3": "3. Просмотрите результаты в этом окне",
        "hint": "Совет: Программа проверит файл по хешу,\nесли он уже есть в базе VirusTotal.",
        "wait_time": "Время проверки зависит от размера файла\nи загрузки сервера (до 5 минут).",
        "language": "Язык",
        "lang_ru": "Русский",
        "lang_en": "English",
        "topmost": "Поверх других окон",
        "requests_used": "Потрачено",
        "behavior": "Поведение",
        "window": "Окно",
        "warning_title": "Предупреждение",
        "kb": "КБ",
        "bytes_unit": "байт",
        "date_label": "Дата",
        "file_label": "Файл",
        "method_label": "Метод",
        "unknown_object": "Подозрительный объект",
        "scan_start_header": "НАЧАЛО СКАНИРОВАНИЯ",
        "scan_start_note1": "Это может занять до 5 минут...",
        "scan_start_note2": "Пожалуйста, подождите.",
        "check_now": "Проверить сейчас",
        "filter_all": "Все файлы",
        "filter_exe": "Исполняемые файлы",
        "filter_docs": "Документы",
        "filter_archives": "Архивы",
        "success": "Успех",
        "scan_results_header": "РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ",
        "anonymous": "Аноним",
        "about_text": """
🔍 VirusTotal Scanner Pro v3.0

📌 Логика работы:
   1️⃣ Проверяет SHA-256 хеш файла
   2️⃣ Если файл есть в базе - показывает готовый отчет
   3️⃣ Если нет - загружает и ждет результат

📌 Возможности:
   • Мгновенный результат для проверенных файлов
   • Загрузка новых файлов на проверку
   • Детальный отчет о результатах
   • Прогресс-бар для отслеживания статуса
   • Современный темный интерфейс
   • Многопоточность (интерфейс не зависает)
   • Копирование (Ctrl+C) и вставка (Ctrl+V)
   • 🔗 Открытие файла на VirusTotal
   • 💾 Автосохранение API ключа

⚙️ Требования:
   • API ключ VirusTotal (бесплатный)
   • Интернет-соединение

📝 Примечание:
   Бесплатный API ключ имеет ограничение:
   • 4 запроса в минуту
   • 500 запросов в день

💡 Совет:
   Для получения API ключа посетите:
   https://www.virustotal.com/gui/join-us
"""
    },
    "en": {
        "title": "VirusTotal Scanner Pro",
        "select_file": "Select file",
        "scanning": "Scanning...",
        "ready": "Ready",
        "no_file": "No file selected",
        "file_info": "File info",
        "actions": "Actions",
        "status": "Status",
        "results": "Scan results",
        "clear": "Clear",
        "about": "About",
        "change_api_key": "Change API key",
        "settings": "Settings",
        "copy": "Copy",
        "copy_hash": "Copy hash",
        "open_in_browser": "Open on VirusTotal",
        "file_not_selected": "No file selected",
        "size": "Size",
        "sha256": "SHA-256",
        "api_key_dialog_title": "Setup API key",
        "api_key_dialog_text": "Enter your VirusTotal API key:\n(you can paste with Ctrl+V)",
        "api_key_warning": "API key not entered. The program will not work correctly!",
        "api_key_updated": "API key updated successfully!",
        "api_key_update_status": "API key updated",
        "hash_copied": "Hash copied!",
        "hash_not_found": "Hash not found",
        "text_copied": "Text copied!",
        "text_pasted": "Text pasted!",
        "no_text_to_copy": "No text to copy",
        "output_cleared": "Output cleared",
        "browser_opened": "Opened in browser",
        "hash_calc": "Calculating SHA-256...",
        "checking_db": "Checking VirusTotal database...",
        "file_not_in_db": "File not found in database. Uploading...",
        "uploading": "Uploading file to server...",
        "file_uploaded": "File uploaded!",
        "file_found_in_db": "File found in database!",
        "ready_report_from_db": "Ready report from database!",
        "waiting_scan": "Waiting for antivirus check...",
        "waiting_scan_text": "Waiting for check (up to 7 minutes)...",
        "scan_complete": "Scan complete!",
        "timeout_warning": "Waiting time expired",
        "check_later": "Check later",
        "error_network": "No internet connection!",
        "error_timeout": "Timeout exceeded!",
        "error_fail": "Fail",
        "no_detections": "CLEAN! No antivirus detected any threats.",
        "threats_detected": "THREATS DETECTED",
        "total_detections": "Total detections",
        "full_report": "Full report",
        "comments": "COMMENTS",
        "no_comments": "No comments",
        "stats": "STATISTICS",
        "harmless": "Harmless",
        "undetected": "Undetected",
        "suspicious": "Suspicious",
        "malicious": "Malicious",
        "timeout_stats": "Timeout",
        "reputation": "COMMUNITY REPUTATION",
        "votes_for": "For",
        "votes_against": "Against",
        "settings_window": "Settings",
        "theme": "Theme",
        "dark": "Dark",
        "light": "Light",
        "system": "System",
        "sound": "Sound on scan complete",
        "api_type": "API key type",
        "free": "Free",
        "paid": "Paid",
        "close_to_tray": "Close to tray",
        "autostart": "Start with Windows",
        "save": "Save",
        "reset": "Reset",
        "thanks_title": "Thank you!",
        "thanks_text": "Thanks for downloading\n\nI don't know where you'll use this \nbut use it ¯\\_(ツ)_/¯",
        "thanks_body": "Thanks for downloading",
        "thanks_subtext": "I don't know where you'll use this \nbut use it ¯\\_(ツ)_/¯",
        "dont_show_again": "Don't show again",
        "ok": "OK",
        "cancel": "Cancel",
        "about_program": "About",
        "welcome": "Welcome to VirusTotal Scanner Pro!",
        "instructions": "Instructions",
        "instruction_1": "1. Click 'Select file' to upload",
        "instruction_2": "2. Wait for the scan to complete",
        "instruction_3": "3. View the results in this window",
        "hint": "Tip: The program will check the file by hash,\nif it's already in VirusTotal database.",
        "wait_time": "Scan time depends on file size\nand server load (up to 5 minutes).",
        "language": "Language",
        "lang_ru": "Русский",
        "lang_en": "English",
        "topmost": "Always on top",
        "requests_used": "Used",
        "behavior": "Behavior",
        "window": "Window",
        "warning_title": "Warning",
        "kb": "KB",
        "bytes_unit": "bytes",
        "date_label": "Date",
        "file_label": "File",
        "method_label": "Method",
        "unknown_object": "Suspicious object",
        "scan_start_header": "SCAN STARTED",
        "scan_start_note1": "This may take up to 5 minutes...",
        "scan_start_note2": "Please wait.",
        "check_now": "Check now",
        "filter_all": "All files",
        "filter_exe": "Executables",
        "filter_docs": "Documents",
        "filter_archives": "Archives",
        "success": "Success",
        "scan_results_header": "SCAN RESULTS",
        "anonymous": "Anonymous",
        "about_text": """
🔍 VirusTotal Scanner Pro v3.0

📌 Logic:
   1️⃣ Checks SHA-256 hash of the file
   2️⃣ If the file is in the database - shows a ready report
   3️⃣ If not - uploads and waits for the result

📌 Features:
   • Instant result for verified files
   • Upload new files for scanning
   • Detailed report of results
   • Progress bar to track status
   • Modern dark interface
   • Multithreading (interface doesn't freeze)
   • Copy (Ctrl+C) and paste (Ctrl+V)
   • 🔗 Open file on VirusTotal
   • 💾 Auto-save API key

⚙️ Requirements:
   • VirusTotal API key (free)
   • Internet connection

📝 Note:
   Free API key has limitations:
   • 4 requests per minute
   • 500 requests per day

💡 Tip:
   To get an API key visit:
   https://www.virustotal.com/gui/join-us
"""
    }
}

CURRENT_LANG = "ru"

def get_config_path():
    if sys.platform == "win32":
        appdata_local = os.getenv("LOCALAPPDATA")
        if not appdata_local:
            username = os.getenv("USERNAME")
            if username:
                appdata_local = f"C:\\Users\\{username}\\AppData\\Local"
            else:
                appdata_local = os.path.join(os.getenv("USERPROFILE", ""), "AppData", "Local")
        config_dir = os.path.join(appdata_local, "VirusTotalScanner")
    else:
        config_dir = os.path.join(os.path.expanduser("~"), ".config", "VirusTotalScanner")
    
    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir)
        except:
            pass
    
    return config_dir

CONFIG_DIR = get_config_path()
CONFIG_FILE = os.path.join(CONFIG_DIR, "vt_config.json")

def load_config():
    default = {"api_key": "", "topmost": False, "thanks_shown": False, "api_type": "free", "requests_used": 0, "requests_reset_date": "", "lang": "ru", "theme": "dark", "sound_on_complete": True, "close_to_tray": False, "autostart": False}
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                default.update(data)
    except:
        pass

    today = datetime.now().strftime("%Y-%m-%d")
    if default.get("requests_reset_date") != today:
        default["requests_used"] = 0
        default["requests_reset_date"] = today
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(default, f)
        except:
            pass
    return default

def save_config(config):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f)
        return True
    except:
        return False

CONFIG = load_config()
VT_API_KEY = CONFIG.get("api_key", "")
TOPMOST = CONFIG.get("topmost", False)
THANKS_SHOWN = CONFIG.get("thanks_shown", False)
CURRENT_LANG = CONFIG.get("lang", "ru")

ctk.set_appearance_mode(CONFIG.get("theme", "dark"))

VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSES_URL = "https://www.virustotal.com/api/v3/analyses/"

class ThanksWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.dont_show = False
        self.text = LANG[CURRENT_LANG]

        self.title(self.text["thanks_title"])
        self.geometry("450x320")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 450) // 2
        y = (self.winfo_screenheight() - 320) // 2
        self.geometry(f"+{x}+{y}")

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=25, pady=25)

        ctk.CTkLabel(
            main_frame,
            text=self.text["thanks_body"],
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=(0, 15))

        ctk.CTkLabel(
            main_frame,
            text=self.text["thanks_subtext"],
            font=ctk.CTkFont(size=16),
            text_color="gray60",
            justify="center"
        ).pack(pady=(0, 20))

        self.check_var = ctk.BooleanVar(value=False)
        check = ctk.CTkCheckBox(
            main_frame,
            text=self.text["dont_show_again"],
            variable=self.check_var,
            font=ctk.CTkFont(size=13)
        )
        check.pack(pady=(0, 15))

        ok_btn = ctk.CTkButton(
            main_frame,
            text=self.text["ok"],
            command=self.ok_click,
            height=38,
            width=150,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            corner_radius=10
        )
        ok_btn.pack()

    def ok_click(self):
        self.dont_show = self.check_var.get()
        self.destroy()

class CustomInputDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, text):
        super().__init__(parent)
        
        self.text = LANG[CURRENT_LANG]
        self.title(title)
        self.geometry("500x200")
        self.resizable(False, False)
        self.grab_set()
        
        self.result = None
        
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 200) // 2
        self.geometry(f"+{x}+{y}")
        
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        label = ctk.CTkLabel(main_frame, text=text, font=ctk.CTkFont(size=14))
        label.pack(pady=(0, 15))
        
        self.entry = ctk.CTkEntry(main_frame, width=400, height=40, font=ctk.CTkFont(size=14))
        self.entry.pack(pady=(0, 15))
        self.entry.focus()
        
        self.entry.bind("<Control-v>", self.paste_from_clipboard)
        self.entry.bind("<Command-v>", self.paste_from_clipboard)
        self.entry.bind("<Control-V>", self.paste_from_clipboard)
        self.entry.bind("<Command-V>", self.paste_from_clipboard)
        
        self.entry.bind("<Button-3>", self.show_context_menu)
        
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(0, 5))
        
        ok_btn = ctk.CTkButton(
            btn_frame,
            text=self.text["ok"],
            command=self.ok_click,
            width=100,
            height=35,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60"
        )
        ok_btn.pack(side="right", padx=(0, 5))
        
        cancel_btn = ctk.CTkButton(
            btn_frame,
            text=self.text["cancel"],
            command=self.cancel_click,
            width=100,
            height=35,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b"
        )
        cancel_btn.pack(side="right", padx=5)
        
        self.context_menu = None
        self.create_context_menu()
        
        self.entry.bind("<Return>", lambda e: self.ok_click())
        
    def create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Вставить", command=self.paste_from_clipboard)
        self.context_menu.add_command(label="Копировать", command=self.copy_from_entry)
        self.context_menu.add_command(label="Вырезать", command=self.cut_from_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Выделить всё", command=self.select_all)
    
    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def paste_from_clipboard(self, event=None):
        try:
            clipboard_text = self.clipboard_get()
            if clipboard_text:
                self.entry.insert("insert", clipboard_text)
                self.entry.focus()
        except:
            pass
        return "break"
    
    def copy_from_entry(self):
        try:
            selected = self.entry.selection_get()
            if selected:
                self.clipboard_clear()
                self.clipboard_append(selected)
        except:
            pass
    
    def cut_from_entry(self):
        try:
            selected = self.entry.selection_get()
            if selected:
                self.clipboard_clear()
                self.clipboard_append(selected)
                self.entry.delete("sel.first", "sel.last")
        except:
            pass
    
    def select_all(self):
        self.entry.select_range(0, "end")
        self.entry.focus()
    
    def ok_click(self):
        self.result = self.entry.get()
        self.destroy()
    
    def cancel_click(self):
        self.result = None
        self.destroy()

class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.text = LANG[CURRENT_LANG]

        self.title(self.text["settings"])
        self.geometry("450x560")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = (self.winfo_screenwidth() - 450) // 2
        y = (self.winfo_screenheight() - 560) // 2
        self.geometry(f"+{x}+{y}")

        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", padx=20, pady=(0, 20))

        save_btn = ctk.CTkButton(
            bottom_frame,
            text=self.text["save"],
            command=self.save_click,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            corner_radius=10
        )
        save_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        reset_btn = ctk.CTkButton(
            bottom_frame,
            text=self.text["reset"],
            command=self.reset_click,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#95a5a6",
            hover_color="#7f8c8d",
            corner_radius=10
        )
        reset_btn.pack(side="right", fill="x", expand=True, padx=(5, 0))

        main_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        main_frame.pack(side="top", fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            main_frame,
            text=self.text["window"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(0, 5))

        self.topmost_var = ctk.BooleanVar(value=CONFIG.get("topmost", False))
        topmost_check = ctk.CTkCheckBox(
            main_frame,
            text=self.text["topmost"],
            variable=self.topmost_var,
            font=ctk.CTkFont(size=13)
        )
        topmost_check.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.text["theme"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        self.theme_var = ctk.StringVar(value=self.theme_display_from_config())
        theme_menu = ctk.CTkOptionMenu(
            main_frame,
            values=[self.text["dark"], self.text["light"], self.text["system"]],
            variable=self.theme_var,
            font=ctk.CTkFont(size=13),
            width=200,
            height=35
        )
        theme_menu.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.text["sound"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        self.sound_var = ctk.BooleanVar(value=CONFIG.get("sound_on_complete", True))
        sound_check = ctk.CTkCheckBox(
            main_frame,
            text=self.text["sound"],
            variable=self.sound_var,
            font=ctk.CTkFont(size=13)
        )
        sound_check.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.text["api_type"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        api_type_value = CONFIG.get("api_type", "free")
        if api_type_value == "free":
            display_value = self.text["free"]
        else:
            display_value = self.text["paid"]

        self.api_type_var = ctk.StringVar(value=display_value)
        api_type_menu = ctk.CTkOptionMenu(
            main_frame,
            values=[self.text["free"], self.text["paid"]],
            variable=self.api_type_var,
            font=ctk.CTkFont(size=13),
            width=200,
            height=35
        )
        api_type_menu.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.text["language"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        self.lang_display_map = {self.text["lang_ru"]: "ru", self.text["lang_en"]: "en"}
        current_lang_display = self.text["lang_ru"] if CONFIG.get("lang", "ru") == "ru" else self.text["lang_en"]
        self.lang_var = ctk.StringVar(value=current_lang_display)
        lang_menu = ctk.CTkOptionMenu(
            main_frame,
            values=[self.text["lang_ru"], self.text["lang_en"]],
            variable=self.lang_var,
            font=ctk.CTkFont(size=13),
            width=200,
            height=35
        )
        lang_menu.pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            main_frame,
            text=self.text["behavior"],
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        self.tray_var = ctk.BooleanVar(value=CONFIG.get("close_to_tray", False))
        tray_check = ctk.CTkCheckBox(
            main_frame,
            text=self.text["close_to_tray"],
            variable=self.tray_var,
            font=ctk.CTkFont(size=13)
        )
        tray_check.pack(anchor="w", pady=(0, 10))

        self.autostart_var = ctk.BooleanVar(value=CONFIG.get("autostart", False))
        autostart_check = ctk.CTkCheckBox(
            main_frame,
            text=self.text["autostart"],
            variable=self.autostart_var,
            font=ctk.CTkFont(size=13)
        )
        autostart_check.pack(anchor="w", pady=(0, 10))

    def theme_display_from_config(self):
        key = CONFIG.get("theme", "dark")
        if key == "light":
            return self.text["light"]
        elif key == "system":
            return self.text["system"]
        return self.text["dark"]

    def save_click(self):
        global CURRENT_LANG
        CONFIG["topmost"] = self.topmost_var.get()
        theme_value = self.theme_var.get()
        if theme_value == self.text["light"]:
            CONFIG["theme"] = "light"
        elif theme_value == self.text["system"]:
            CONFIG["theme"] = "system"
        else:
            CONFIG["theme"] = "dark"

        CONFIG["sound_on_complete"] = self.sound_var.get()
        CONFIG["lang"] = self.lang_display_map.get(self.lang_var.get(), "ru")
        CONFIG["close_to_tray"] = self.tray_var.get()
        CONFIG["autostart"] = self.autostart_var.get()

        api_value = self.api_type_var.get()
        if api_value == self.text["free"]:
            CONFIG["api_type"] = "free"
        else:
            CONFIG["api_type"] = "paid"

        save_config(CONFIG)

        self.parent.attributes("-topmost", CONFIG["topmost"])
        CURRENT_LANG = CONFIG.get("lang", "ru")

        ctk.set_appearance_mode(CONFIG["theme"])

        if CONFIG.get("autostart"):
            self.add_to_startup()
        else:
            self.remove_from_startup()

        self.parent.update_ui_text()
        self.parent.update_requests_display()
        self.destroy()

    def reset_click(self):
        self.topmost_var.set(False)
        self.theme_var.set(self.text["dark"])
        self.sound_var.set(True)
        self.api_type_var.set(self.text["free"])
        self.lang_var.set(self.text["lang_ru"])
        self.tray_var.set(False)
        self.autostart_var.set(False)

    def add_to_startup(self):
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "VirusTotalScanner", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
        except:
            pass

    def remove_from_startup(self):
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            try:
                winreg.DeleteValue(key, "VirusTotalScanner")
            except:
                pass
            winreg.CloseKey(key)
        except:
            pass

class VirusTotalScanner(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.text = LANG[CURRENT_LANG]
        self.title(f"🔍 {self.text['title']}")
        self.geometry("1100x750")
        self.minsize(900, 650)
        self.maxsize(1200, 800)
        self.attributes("-topmost", TOPMOST)
        self.protocol("WM_DELETE_WINDOW", self.on_close_request)
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        if not THANKS_SHOWN:
            self.show_thanks()
        
        if not VT_API_KEY:
            self.show_api_key_dialog()
        
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self.main_container.grid_columnconfigure(0, weight=0)
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)
        
        self.left_panel = ctk.CTkFrame(self.main_container, width=280, corner_radius=15)
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.left_panel.grid_propagate(False)
        
        self.right_panel = ctk.CTkFrame(self.main_container, corner_radius=15)
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(2, weight=1)
        
        self.create_left_panel()
        
        self.requests_used = CONFIG.get("requests_used", 0)
        
        self.create_right_panel()
        
        self.current_file_path = None
        self.current_file_name = None
        self.current_file_hash = None
        self.scanning = False
        self.is_rescan = False
        self.check_now_event = threading.Event()

    def update_console_text(self):
        if not hasattr(self, 'output_text'):
            return
        
        current_content = self.output_text.get("1.0", "end-1c")
        
        if "Добро пожаловать" in current_content or "Welcome" in current_content:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", f"👋 {self.text['welcome']}\n\n")
            self.output_text.insert("end", f"📌 {self.text['instructions']}:\n")
            self.output_text.insert("end", f"{self.text['instruction_1']}\n")
            self.output_text.insert("end", f"{self.text['instruction_2']}\n")
            self.output_text.insert("end", f"{self.text['instruction_3']}\n\n")
            self.output_text.insert("end", f"💡 {self.text['hint']}\n")
            self.output_text.insert("end", f"\n⏱️ {self.text['wait_time']}\n")
            self.output_text.see("1.0")
            return

        for lang_key in LANG:
            other = LANG[lang_key]
            placeholder = f"🔍 {other['scan_start_header']}\n" + "=" * 85 + "\n\n" + f"⏱️ {other['scan_start_note1']}\n" + f"   {other['scan_start_note2']}\n\n"
            if current_content.strip() == placeholder.strip():
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", f"🔍 {self.text['scan_start_header']}\n")
                self.output_text.insert("end", "=" * 85 + "\n\n")
                self.output_text.insert("end", f"⏱️ {self.text['scan_start_note1']}\n")
                self.output_text.insert("end", f"   {self.text['scan_start_note2']}\n\n")
                self.output_text.see("1.0")
                return

    def update_ui_text(self):
        self.text = LANG[CURRENT_LANG]
        self.title(f"🔍 {self.text['title']}")
        
        self.title_label.configure(text=self.text["title"])
        self.select_btn.configure(text=self.text["select_file"])
        self.clear_btn.configure(text=self.text["clear"])
        self.info_btn.configure(text=self.text["about"])
        self.change_key_btn.configure(text=self.text["change_api_key"])
        self.settings_btn.configure(text=self.text["settings"])
        self.copy_btn.configure(text=self.text["copy"])
        self.copy_hash_btn.configure(text=self.text["copy_hash"])
        self.rescan_btn.configure(text=self.text["open_in_browser"])
        self.list_label.configure(text=self.text["results"])
        self.status_label.configure(text=self.text["ready"])
        
        self.file_info_section.configure(text="📊 " + self.text["file_info"])
        self.actions_section.configure(text="⚡ " + self.text["actions"])
        self.status_section.configure(text="📡 " + self.text["status"])
        
        if hasattr(self, 'theme_var'):
            current_theme = CONFIG.get("theme", "dark")
            if current_theme == "light":
                theme_display = self.text["light"]
            elif current_theme == "system":
                theme_display = self.text["system"]
            else:
                theme_display = self.text["dark"]
            self.theme_var.set(theme_display)
        
        if hasattr(self, 'api_type_var'):
            api_type_value = CONFIG.get("api_type", "free")
            if api_type_value == "free":
                api_display = self.text["free"]
            else:
                api_display = self.text["paid"]
            self.api_type_var.set(api_display)
        
        if self.current_file_name:
            self.file_info_label.configure(text=f"📄 {self.current_file_name}")
        else:
            self.file_info_label.configure(text=self.text["no_file"])
        
        if self.current_file_path:
            file_size = os.path.getsize(self.current_file_path)
            self.size_info_label.configure(text=f"{self.text['size']}: {file_size/1024:.2f} {self.text['kb']}")
        else:
            self.size_info_label.configure(text=f"{self.text['size']}: -")
        
        if self.current_file_hash:
            self.hash_info_label.configure(text=f"{self.text['sha256']}: {self.current_file_hash[:20]}...")
        else:
            self.hash_info_label.configure(text=f"{self.text['sha256']}: -")
        
        self.update_requests_display()
        self.update_console_text()

    def update_requests_display(self):
        api_type = CONFIG.get("api_type", "free")
        if api_type == "paid":
            self.requests_label.configure(text=f"{self.text['requests_used']}: {self.requests_used}/∞")
            self.requests_progress.set(0)
        else:
            max_requests = 500
            progress = min(self.requests_used / max_requests, 1.0)
            self.requests_label.configure(text=f"{self.text['requests_used']}: {self.requests_used}/{max_requests}")
            self.requests_progress.set(progress)

    def show_thanks(self):
        dialog = ThanksWindow(self)
        self.wait_window(dialog)
        if dialog.dont_show:
            CONFIG["thanks_shown"] = True
            save_config(CONFIG)

    def ui(self, func):
        self.after(0, func)

    def on_close_request(self):
        if CONFIG.get("close_to_tray", False):
            self.iconify()
        else:
            self.destroy()

    def bump_requests_used(self):
        today = datetime.now().strftime("%Y-%m-%d")
        if CONFIG.get("requests_reset_date") != today:
            self.requests_used = 0
            CONFIG["requests_reset_date"] = today
        self.requests_used += 1
        CONFIG["requests_used"] = self.requests_used
        save_config(CONFIG)
        self.update_requests_display()

    def play_complete_sound(self):
        if not CONFIG.get("sound_on_complete", True):
            return
        if sys.platform == "win32":
            try:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except:
                pass
        else:
            try:
                self.bell()
            except:
                pass

    def trigger_check_now(self):
        self.check_now_event.set()

    def open_settings(self):
        dialog = SettingsDialog(self)
        self.wait_window(dialog)

    def open_in_browser(self):
        if self.current_file_hash:
            url = f"https://www.virustotal.com/gui/file/{self.current_file_hash}"
            webbrowser.open(url)
            self.status_label.configure(text=self.text["browser_opened"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
        else:
            self.status_label.configure(text=self.text["hash_not_found"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))

    def show_api_key_dialog(self):
        dialog = CustomInputDialog(
            self,
            self.text["api_key_dialog_title"],
            self.text["api_key_dialog_text"]
        )
        self.wait_window(dialog)
        api_key = dialog.result
        
        if api_key and api_key.strip():
            global VT_API_KEY
            VT_API_KEY = api_key.strip()
            CONFIG["api_key"] = VT_API_KEY
            save_config(CONFIG)
        else:
            messagebox.showwarning(self.text.get("warning_title", "Warning"), self.text["api_key_warning"])
        
    def create_left_panel(self):
        logo_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        logo_frame.pack(fill="x", pady=(20, 10))
        
        ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=ctk.CTkFont(size=50)
        ).pack()
        
        self.title_label = ctk.CTkLabel(
            logo_frame,
            text=self.text["title"],
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.title_label.pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="Pro Edition v3.0",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        ).pack()
        
        ctk.CTkFrame(self.left_panel, height=2, fg_color="gray30").pack(fill="x", pady=15, padx=20)
        
        info_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        info_frame.pack(fill="x", pady=10, padx=20)
        
        self.file_info_section = ctk.CTkLabel(
            info_frame,
            text="📊 " + self.text["file_info"],
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.file_info_section.pack(anchor="w", pady=(0, 10))
        
        self.file_info_label = ctk.CTkLabel(
            info_frame,
            text=self.text["no_file"],
            font=ctk.CTkFont(size=13),
            anchor="w",
            wraplength=230
        )
        self.file_info_label.pack(anchor="w", pady=2)
        
        self.size_info_label = ctk.CTkLabel(
            info_frame,
            text=self.text["size"] + ": -",
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        self.size_info_label.pack(anchor="w", pady=2)
        
        self.hash_info_label = ctk.CTkLabel(
            info_frame,
            text=self.text["sha256"] + ": -",
            font=ctk.CTkFont(size=11),
            anchor="w",
            wraplength=230
        )
        self.hash_info_label.pack(anchor="w", pady=2)
        
        ctk.CTkFrame(self.left_panel, height=2, fg_color="gray30").pack(fill="x", pady=15, padx=20)
        
        actions_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        actions_frame.pack(fill="x", pady=10, padx=20)
        
        self.actions_section = ctk.CTkLabel(
            actions_frame,
            text="⚡ " + self.text["actions"],
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.actions_section.pack(anchor="w", pady=(0, 10))
        
        self.select_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["select_file"],
            command=self.select_file,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            corner_radius=10
        )
        self.select_btn.pack(fill="x", pady=5)
        
        self.rescan_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["open_in_browser"],
            command=self.open_in_browser,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#9b59b6",
            hover_color="#8e44ad",
            corner_radius=10,
            state="disabled"
        )
        self.rescan_btn.pack(fill="x", pady=5)
        
        self.clear_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["clear"],
            command=self.clear_output,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b",
            corner_radius=10
        )
        self.clear_btn.pack(fill="x", pady=5)
        
        self.info_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["about"],
            command=self.show_info,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#3498db",
            hover_color="#2980b9",
            corner_radius=10
        )
        self.info_btn.pack(fill="x", pady=5)
        
        self.change_key_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["change_api_key"],
            command=self.change_api_key,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#95a5a6",
            hover_color="#7f8c8d",
            corner_radius=8
        )
        self.change_key_btn.pack(fill="x", pady=5)

        self.settings_btn = ctk.CTkButton(
            actions_frame,
            text=self.text["settings"],
            command=self.open_settings,
            height=35,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#95a5a6",
            hover_color="#7f8c8d",
            corner_radius=8
        )
        self.settings_btn.pack(fill="x", pady=5)
        
        ctk.CTkFrame(self.left_panel, height=2, fg_color="gray30").pack(fill="x", pady=15, padx=20)
        
        status_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        status_frame.pack(fill="x", pady=10, padx=20)
        
        self.status_section = ctk.CTkLabel(
            status_frame,
            text="📡 " + self.text["status"],
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.status_section.pack(anchor="w", pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(
            status_frame,
            text=self.text["ready"],
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        self.status_label.pack(anchor="w", pady=2)
        
        self.progress_bar = ctk.CTkProgressBar(
            status_frame,
            height=12,
            corner_radius=6,
            progress_color="#2ecc71"
        )
        self.progress_bar.pack(fill="x", pady=(10, 0))
        self.progress_bar.set(0)
        
        self.check_now_btn = ctk.CTkButton(
            status_frame,
            text=f"🔄 {self.text['check_now']}",
            command=self.trigger_check_now,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=28,
            fg_color="#2d3748",
            hover_color="#4a5568"
        )
        self.check_now_btn.pack(fill="x", pady=(8, 0))
        self.check_now_btn.pack_forget()
        
        self.footer_label = ctk.CTkLabel(
            self.left_panel,
            text="© 2026 VirusTotal Pro",
            font=ctk.CTkFont(size=10),
            text_color="gray50"
        )
        self.footer_label.pack(side="bottom", pady=15)
        
    def create_right_panel(self):
        top_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        top_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 5))
        top_frame.grid_columnconfigure(0, weight=1)
        
        top_frame_left = ctk.CTkFrame(top_frame, fg_color="transparent")
        top_frame_left.pack(side="left", fill="x", expand=True)
        
        self.list_label = ctk.CTkLabel(
            top_frame_left,
            text=self.text["results"],
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.list_label.pack(anchor="w")
        
        top_frame_right = ctk.CTkFrame(top_frame, fg_color="transparent")
        top_frame_right.pack(side="right")
        
        self.requests_frame = ctk.CTkFrame(top_frame_right, fg_color="transparent")
        self.requests_frame.pack(side="left", padx=(0, 10))

        self.requests_label = ctk.CTkLabel(
            self.requests_frame,
            text="Потрачено: 0/500",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        )
        self.requests_label.pack()

        self.requests_progress = ctk.CTkProgressBar(
            self.requests_frame,
            width=150,
            height=6,
            corner_radius=3,
            fg_color="#2d3748",
            progress_color="#2ecc71"
        )
        self.requests_progress.pack(pady=(2, 0))
        self.requests_progress.set(0)

        self.copy_btn = ctk.CTkButton(
            top_frame_right,
            text=self.text["copy"],
            command=self.copy_output,
            height=30,
            width=100,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#3498db",
            hover_color="#2980b9",
            corner_radius=8
        )
        self.copy_btn.pack(side="left", padx=2)
        
        self.copy_hash_btn = ctk.CTkButton(
            top_frame_right,
            text=self.text["copy_hash"],
            command=self.copy_hash,
            height=30,
            width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#9b59b6",
            hover_color="#8e44ad",
            corner_radius=8
        )
        self.copy_hash_btn.pack(side="left", padx=2)
        
        self.output_text = ctk.CTkTextbox(
            self.right_panel,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            border_width=2,
            border_color="#2b2b2b",
            corner_radius=0
        )
        self.output_text.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        self.output_text.insert("1.0", f"👋 {self.text['welcome']}\n\n")
        self.output_text.insert("end", f"📌 {self.text['instructions']}:\n")
        self.output_text.insert("end", f"{self.text['instruction_1']}\n")
        self.output_text.insert("end", f"{self.text['instruction_2']}\n")
        self.output_text.insert("end", f"{self.text['instruction_3']}\n\n")
        self.output_text.insert("end", f"💡 {self.text['hint']}\n")
        self.output_text.insert("end", f"\n⏱️ {self.text['wait_time']}\n")
        self.output_text.see("1.0")
        
        self.output_text.bind("<Control-c>", self.copy_selected)
        self.output_text.bind("<Command-c>", self.copy_selected)
        self.output_text.bind("<Control-v>", self.paste_to_textbox)
        self.output_text.bind("<Command-v>", self.paste_to_textbox)
        
        self.update_requests_display()
        
    def paste_to_textbox(self, event=None):
        try:
            clipboard_text = self.clipboard_get()
            if clipboard_text:
                self.output_text.insert("insert", clipboard_text)
                self.status_label.configure(text=self.text["text_pasted"])
                self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
        except:
            pass
        return "break"
        
    def copy_selected(self, event=None):
        try:
            selected = self.output_text.get("sel.first", "sel.last")
            if selected:
                self.clipboard_clear()
                self.clipboard_append(selected)
                self.status_label.configure(text=self.text["text_copied"])
                self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
        except:
            pass
        return "break"
    
    def copy_output(self):
        text = self.output_text.get("1.0", "end-1c")
        if text.strip():
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_label.configure(text=self.text["text_copied"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
        else:
            self.status_label.configure(text=self.text["no_text_to_copy"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
    
    def copy_hash(self):
        hash_text = self.hash_info_label.cget("text")
        if hash_text and hash_text != self.text["sha256"] + ": -":
            hash_value = hash_text.replace(self.text["sha256"] + ": ", "").replace("...", "")
            self.clipboard_clear()
            self.clipboard_append(hash_value)
            self.status_label.configure(text=self.text["hash_copied"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
        else:
            self.status_label.configure(text=self.text["hash_not_found"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
    
    def change_api_key(self):
        dialog = CustomInputDialog(
            self,
            self.text["change_api_key"],
            self.text["api_key_dialog_text"]
        )
        self.wait_window(dialog)
        api_key = dialog.result
        
        if api_key and api_key.strip():
            global VT_API_KEY
            VT_API_KEY = api_key.strip()
            CONFIG["api_key"] = VT_API_KEY
            save_config(CONFIG)
            messagebox.showinfo("Успех", self.text["api_key_updated"])
            self.status_label.configure(text=self.text["api_key_update_status"])
            self.after(2000, lambda: self.status_label.configure(text=self.text["ready"]))
    
    def get_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_completed_report(self, file_hash, headers):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'attributes' in data['data']:
                    attrs = data['data']['attributes']
                    last_analysis_stats = attrs.get('last_analysis_stats', {})
                    last_analysis_results = attrs.get('last_analysis_results', {})
                    
                    return {
                        'stats': last_analysis_stats,
                        'results': last_analysis_results
                    }
            return None
        except:
            return None
    
    def upload_file(self, file_path, file_name, headers):
        url = "https://www.virustotal.com/api/v3/files"
        with open(file_path, "rb") as f:
            files = {"file": (file_name, f)}
            response = requests.post(url, headers=headers, files=files, timeout=60)
        return response
    
    def extract_analysis_id_from_409(self, response_text):
        try:
            data = json.loads(response_text)
            if 'error' in data:
                error = data['error']
                if 'message' in error:
                    match = re.search(r'analysis[=/]([a-zA-Z0-9-]+)', error['message'])
                    if match:
                        return match.group(1)
                    match = re.search(r'([a-f0-9-]{36})', error['message'])
                    if match:
                        return match.group(1)
            return None
        except:
            return None
    
    def get_comment_author(self, comment_id, headers):
        try:
            url = f"https://www.virustotal.com/api/v3/comments/{comment_id}/author"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                name = data.get('id', self.text["anonymous"])
                reputation = data.get('attributes', {}).get('reputation', 0)
                return name, reputation
        except:
            pass
        return self.text["anonymous"], 0

    def get_file_reputation(self, file_hash, headers):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                attrs = response.json().get('data', {}).get('attributes', {})
                return attrs.get('reputation', 0), attrs.get('total_votes', {})
        except:
            pass
        return 0, {}

    def get_comments(self, file_hash, headers):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}/comments"
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                comments = response.json().get('data', [])
                for c in comments[:10]:
                    name, reputation = self.get_comment_author(c.get('id', ''), headers)
                    c['author_name'] = name
                    c['author_reputation'] = reputation
                return comments
        except:
            pass
        return []

    def display_results(self, stats, results, file_name, file_size, file_hash, comments=None, reputation=0, total_votes=None):
        self.output_text.delete("1.0", "end")
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        timeout = stats.get('timeout', 0)
        total_votes = total_votes or {}
        votes_harmless = total_votes.get('harmless', 0)
        votes_malicious = total_votes.get('malicious', 0)
        rep_icon = "🟢" if reputation > 0 else ("🔴" if reputation < 0 else "⚪")
        
        header = f"""
{'=' * 85}
📊 {self.text["scan_results_header"]}
{'=' * 85}

📁 {self.text["file_label"]}: {file_name}
📏 {self.text["size"]}: {file_size/1024:.2f} {self.text["kb"]} ({file_size} {self.text["bytes_unit"]})
🔑 {self.text["sha256"]}: {file_hash}
🕐 {self.text["date_label"]}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'=' * 85}
📈 {self.text["stats"]}:
   🟢 {self.text["harmless"]}: {harmless}
   ⚪ {self.text["undetected"]}: {undetected}
   🟡 {self.text["suspicious"]}: {suspicious}
   🔴 {self.text["malicious"]}: {malicious}
   ⏱️ {self.text["timeout_stats"]}: {timeout}

{'=' * 85}
{rep_icon} {self.text["reputation"]}: {reputation}
   👍 {self.text["votes_for"]}: {votes_harmless}   👎 {self.text["votes_against"]}: {votes_malicious}
{'=' * 85}
"""
        
        self.output_text.insert("1.0", header)
        
        if malicious > 0 or suspicious > 0:
            self.output_text.insert("end", f"⚠️ {self.text['threats_detected']}:\n")
            self.output_text.insert("end", "-" * 85 + "\n")
            
            detected_count = 0
            for engine, res in results.items():
                category = res.get('category', '')
                if category in ['malicious', 'suspicious']:
                    detected_count += 1
                    result_text = res.get('result', self.text["unknown_object"])
                    method = res.get('method', 'unknown')
                    engine_name = res.get('engine_name', engine)
                    
                    icon = "🔴" if category == 'malicious' else "🟡"
                    self.output_text.insert(
                        "end",
                        f"{icon} [{engine_name}] -> {result_text}\n   📌 {self.text['method_label']}: {method}\n"
                    )
            
            self.output_text.insert("end", "-" * 85 + "\n")
            self.output_text.insert("end", f"📊 {self.text['total_detections']}: {detected_count}\n")
        else:
            self.output_text.insert("end", f"✅ {self.text['no_detections']}\n")
        
        self.output_text.insert("end", f"\n🔗 {self.text['full_report']}: https://www.virustotal.com/gui/file/{file_hash}\n")

        if comments:
            self.output_text.insert("end", "\n" + "=" * 85 + "\n")
            self.output_text.insert("end", f"💬 {self.text['comments']} ({len(comments)}):\n")
            self.output_text.insert("end", "=" * 85 + "\n")

            for c in comments:
                attrs = c.get('attributes', {})
                text = attrs.get('text', '').strip()
                author = c.get('author_name', self.text["anonymous"])
                author_rep = c.get('author_reputation', 0)
                author_label = f"{author} ({author_rep:+d})"

                if re.fullmatch(r'[+-]?\d+\+?', text):
                    self.output_text.insert("end", f"👤 {author_label}: {text}\n")
                else:
                    self.output_text.insert("end", f"👤 {author_label}:\n{text}\n\n")
        else:
            self.output_text.insert("end", f"\n💬 {self.text['no_comments']}\n")

        self.output_text.see("1.0")
        
    def select_file(self):
        if self.scanning:
            return
            
        file_path = filedialog.askopenfilename(
            title=self.text["select_file"],
            filetypes=[
                (self.text["filter_all"], "*.*"),
                (self.text["filter_exe"], "*.exe *.dll *.sys *.msi"),
                (self.text["filter_docs"], "*.pdf *.doc *.docx *.xls *.xlsx *.txt"),
                (self.text["filter_archives"], "*.zip *.rar *.7z *.tar *.gz")
            ]
        )
        
        if not file_path:
            return
        
        self.current_file_path = file_path
        self.current_file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        self.is_rescan = False
        
        self.file_info_label.configure(text=f"📄 {self.current_file_name}")
        self.size_info_label.configure(text=f"{self.text['size']}: {file_size/1024:.2f} {self.text['kb']}")
        self.rescan_btn.configure(state="normal")
        
        self.output_text.delete("1.0", "end")
        self.progress_bar.set(0)
        
        self.output_text.insert("1.0", f"🔍 {self.text['scan_start_header']}\n")
        self.output_text.insert("end", "=" * 85 + "\n\n")
        self.output_text.insert("end", f"⏱️ {self.text['scan_start_note1']}\n")
        self.output_text.insert("end", f"   {self.text['scan_start_note2']}\n\n")
        
        thread = threading.Thread(target=self.start_scan, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def start_scan(self, file_path):
        self.scanning = True
        self.ui(lambda: (
            self.select_btn.configure(state="disabled", text="⏳ " + self.text["scanning"]),
            self.rescan_btn.configure(state="disabled")
        ))

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        headers = {
            "x-apikey": VT_API_KEY,
            "accept": "application/json"
        }

        def reset_buttons():
            self.scanning = False
            self.select_btn.configure(state="normal", text=self.text["select_file"])
            self.rescan_btn.configure(state="normal")
            self.check_now_btn.pack_forget()

        try:
            self.ui(lambda: self.status_label.configure(text=self.text["hash_calc"]))
            file_hash = self.get_file_hash(file_path)
            self.current_file_hash = file_hash
            self.ui(lambda: (
                self.hash_info_label.configure(text=f"{self.text['sha256']}: {file_hash[:20]}..."),
                self.progress_bar.set(0.1)
            ))

            self.ui(lambda: self.status_label.configure(text=self.text["checking_db"]))

            completed_report = self.get_completed_report(file_hash, headers)
            if completed_report:
                comments = self.get_comments(file_hash, headers)
                reputation, total_votes = self.get_file_reputation(file_hash, headers)

                def finish_from_db(stats=completed_report['stats'], results=completed_report['results'], comments=comments, reputation=reputation, total_votes=total_votes):
                    self.bump_requests_used()
                    self.progress_bar.set(1.0)
                    self.output_text.insert("end", self.text["file_found_in_db"] + "\n\n")
                    self.display_results(stats, results, file_name, file_size, file_hash, comments, reputation, total_votes)
                    self.status_label.configure(text=self.text["ready_report_from_db"])
                    self.play_complete_sound()
                    reset_buttons()

                self.ui(finish_from_db)
                return

            self.ui(lambda: self.status_label.configure(text=self.text["file_not_in_db"]))
            self.ui(lambda: (
                self.output_text.insert("end", self.text["uploading"] + "\n"),
                self.output_text.see("end")
            ))

            response = self.upload_file(file_path, file_name, headers)
            self.ui(lambda: self.progress_bar.set(0.3))

            if response.status_code == 409:
                self.ui(lambda: self.status_label.configure(text="⏳ Файл уже загружается, получаем ID..."))

                analysis_id = self.extract_analysis_id_from_409(response.text)

                if not analysis_id:
                    try:
                        data = response.json()
                        if 'error' in data and 'message' in data['error']:
                            match = re.search(r'[a-f0-9-]{36}', data['error']['message'])
                            if match:
                                analysis_id = match.group(0)
                    except:
                        pass

                if not analysis_id:
                    self.ui(lambda: self.status_label.configure(text="❌ Не удалось получить ID анализа"))
                    self.ui(lambda: self.progress_bar.set(0))
                    self.ui(reset_buttons)
                    return

            elif response.status_code == 200:
                response_data = response.json()
                if 'data' in response_data and 'id' in response_data['data']:
                    analysis_id = response_data['data']['id']
                    self.ui(lambda: self.output_text.insert("end", self.text["file_uploaded"] + "\n"))
                else:
                    self.ui(lambda: self.status_label.configure(text="❌ Неверный ответ сервера"))
                    self.ui(lambda: self.progress_bar.set(0))
                    self.ui(reset_buttons)
                    return
            else:
                error_msg = f"Ошибка (Код: {response.status_code})"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg += f": {error_data['error'].get('message', '')}"
                except:
                    pass

                self.ui(lambda: self.output_text.insert("end", f"❌ {error_msg}\n"))
                self.ui(lambda: messagebox.showerror("Ошибка", error_msg))
                self.ui(lambda: self.status_label.configure(text="❌ Ошибка"))
                self.ui(lambda: self.progress_bar.set(0))
                self.ui(reset_buttons)
                return

            analysis_url = f"{VT_ANALYSES_URL}{analysis_id}"
            self.ui(lambda: self.progress_bar.set(0.4))
            self.ui(lambda: self.status_label.configure(text=self.text["waiting_scan"]))
            self.ui(lambda: (
                self.output_text.insert("end", self.text["waiting_scan_text"] + "\n"),
                self.output_text.see("end")
            ))
            self.ui(lambda: self.check_now_btn.pack(fill="x", pady=(8, 0)))

            max_attempts = 15
            attempts = 0
            self.check_now_event.clear()

            while attempts < max_attempts:
                self.check_now_event.wait(timeout=30)
                self.check_now_event.clear()
                attempts += 1

                progress_value = 0.4 + (attempts * 0.037)
                if progress_value > 0.95:
                    progress_value = 0.95
                self.ui(lambda v=progress_value: self.progress_bar.set(v))

                try:
                    analysis_response = requests.get(analysis_url, headers=headers, timeout=30)

                    if analysis_response.status_code != 200:
                        continue

                    analysis_data = analysis_response.json()

                    if 'data' not in analysis_data or 'attributes' not in analysis_data['data']:
                        continue

                    analysis_attrs = analysis_data['data']['attributes']
                    status = analysis_attrs.get('status', 'unknown')

                    if status == 'completed':
                        stats = analysis_attrs.get('stats', {})
                        results = analysis_attrs.get('results', {})
                        comments = self.get_comments(file_hash, headers)
                        reputation, total_votes = self.get_file_reputation(file_hash, headers)

                        def finish(stats=stats, results=results, comments=comments, reputation=reputation, total_votes=total_votes):
                            self.bump_requests_used()
                            self.output_text.insert("end", "\n" + "=" * 85 + "\n")
                            self.output_text.insert("end", f"📊 {self.text['scan_results_header']}\n")
                            self.output_text.insert("end", "=" * 85 + "\n\n")
                            self.display_results(stats, results, file_name, file_size, file_hash, comments, reputation, total_votes)
                            self.status_label.configure(text=self.text["scan_complete"])
                            self.progress_bar.set(1.0)
                            self.check_now_btn.pack_forget()
                            self.play_complete_sound()
                            reset_buttons()

                        self.ui(finish)
                        return
                    else:
                        attempts_snapshot, max_snapshot = attempts, max_attempts
                        show_line = (attempts_snapshot % 3 == 0)

                        def status_update(s=status, a=attempts_snapshot, m=max_snapshot, show=show_line):
                            self.status_label.configure(text=f"⏳ Статус: [{s}] ({a}/{m})")
                            if show:
                                self.output_text.insert("end", f"⏳ Статус: [{s}]...\n")
                                self.output_text.see("end")

                        self.ui(status_update)
                except:
                    continue

            self.ui(lambda: self.status_label.configure(text=self.text["timeout_warning"]))
            self.ui(lambda: (
                self.output_text.insert("end", "\n⚠️ " + self.text["timeout_warning"] + ".\n"),
                self.output_text.insert("end", f"🔗 " + self.text["check_later"] + f": {analysis_url}\n")
            ))

        except requests.exceptions.ConnectionError:
            self.ui(lambda: messagebox.showerror("Ошибка сети", self.text["error_network"]))
            self.ui(lambda: self.status_label.configure(text="❌ " + self.text["error_network"]))
            self.ui(lambda: self.progress_bar.set(0))
        except requests.exceptions.Timeout:
            self.ui(lambda: messagebox.showerror("Ошибка", self.text["error_timeout"]))
            self.ui(lambda: self.status_label.configure(text="❌ " + self.text["error_timeout"]))
            self.ui(lambda: self.progress_bar.set(0))
        except Exception as e:
            self.ui(lambda e=e: messagebox.showerror("Ошибка", f"{self.text['error_fail']}: {str(e)}"))
            self.ui(lambda: self.status_label.configure(text="❌ " + self.text["error_fail"]))
            self.ui(lambda: self.progress_bar.set(0))
        finally:
            self.ui(reset_buttons)
    
    def clear_output(self):
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", "🧹 " + self.text["output_cleared"] + "\n")
        self.status_label.configure(text=self.text["ready"])
        self.progress_bar.set(0)
        self.file_info_label.configure(text=self.text["no_file"])
        self.size_info_label.configure(text=self.text["size"] + ": -")
        self.hash_info_label.configure(text=self.text["sha256"] + ": -")
        self.current_file_path = None
        self.current_file_name = None
        self.current_file_hash = None
        self.rescan_btn.configure(state="disabled")
    
    def show_info(self):
        messagebox.showinfo("ℹ️ " + self.text["about_program"], self.text["about_text"])

if __name__ == "__main__":
    app = VirusTotalScanner()
    app.mainloop()
