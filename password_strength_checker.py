#!/usr/bin/env python3
"""
Password Strength Checker (Tkinter)
- Entropy estimate (bits)
- Length & character variety checks
- Regex-based validations
- Live feedback with a strength meter

Run: python main.py
"""

import math
import re
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox


# ---- Core password analysis ----

COMMON_PASSWORDS = {
    # deliberately short list; you can expand later from public datasets
    "123456", "123456789", "qwerty", "password", "12345", "12345678",
    "111111", "123123", "abc123", "1234", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "letmein", "password1"
}

REPEAT_RUN_RE = re.compile(r"(.)\1{2,}")  # any char repeated 3+ times


def pool_size(password: str) -> int:
    """Estimate the character pool size based on the types present."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^\w\s]", password):  # punctuation/symbols
        # string.punctuation has 32 printable ASCII symbols
        pool += len(string.punctuation)
    # Minimal safeguard: if nothing matched but password not empty,
    # use unique character count as pool approximation.
    if pool == 0 and password:
        pool = len(set(password))
    return pool


def entropy_bits(password: str) -> float:
    """Idealized entropy: length * log2(pool_size)."""
    if not password:
        return 0.0
    p = pool_size(password)
    return round(len(password) * math.log2(max(1, p)), 2)


def has_sequential_run(pw: str, run_len: int = 3) -> bool:
    """Detect simple ascending/descending sequences like abc, 123."""
    if len(pw) < run_len:
        return False
    # normalize to lower for letter checks
    low = pw.lower()
    for i in range(len(low) - run_len + 1):
        chunk = low[i : i + run_len]
        ords = [ord(c) for c in chunk]
        inc = all(ords[j] + 1 == ords[j + 1] for j in range(run_len - 1))
        dec = all(ords[j] - 1 == ords[j + 1] for j in range(run_len - 1))
        if inc or dec:
            return True
    return False


def classify_by_entropy(bits: float) -> tuple[str, int]:
    """
    Map entropy bits to (rating, score 0..100).
    Thresholds adapted from common guidance.
    """
    if bits < 28:
        return "Very Weak", 10
    if bits < 36:
        return "Weak", 25
    if bits < 60:
        return "Fair", 45
    if bits < 90:
        return "Good", 70
    if bits < 128:
        return "Strong", 90
    return "Excellent", 100


def evaluate_password(
    password: str,
    min_length: int = 12,
    require_lower: bool = True,
    require_upper: bool = True,
    require_digit: bool = True,
    require_symbol: bool = True,
) -> dict:
    """Return a complete analysis dictionary for the password."""
    bits = entropy_bits(password)
    rating, score_from_bits = classify_by_entropy(bits)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^\w\s]", password))

    meets_length = len(password) >= min_length
    meets_variety = True
    requirements = []

    if require_lower and not has_lower:
        meets_variety = False
        requirements.append("add a lowercase letter")
    if require_upper and not has_upper:
        meets_variety = False
        requirements.append("add an uppercase letter")
    if require_digit and not has_digit:
        meets_variety = False
        requirements.append("add a digit")
    if require_symbol and not has_symbol:
        meets_variety = False
        requirements.append("add a symbol (e.g., !@#$)")

    is_common = password.lower() in COMMON_PASSWORDS
    has_repeats = bool(REPEAT_RUN_RE.search(password))
    has_sequence = has_sequential_run(password)

    # Start from entropy-derived score then penalize bad patterns
    score = score_from_bits
    if not meets_length:
        score = max(0, score - 25)
    if not meets_variety:
        score = max(0, score - 20)
    if is_common:
        score = max(0, score - 50)
    if has_repeats:
        score = max(0, score - 10)
    if has_sequence:
        score = max(0, score - 10)
    score = max(0, min(100, score))

    # Up-level rating if score and entropy are both strong and no flags
    if score >= 90 and meets_length and meets_variety and not (is_common or has_repeats or has_sequence):
        rating = "Strong" if bits < 128 else "Excellent"

    feedback = []
    if not password:
        feedback.append("Start typing to evaluate your password.")
    if not meets_length:
        feedback.append(f"Use at least {min_length} characters.")
    if requirements:
        feedback.append("Try to " + ", ".join(requirements) + ".")
    if is_common:
        feedback.append("Avoid extremely common passwords.")
    if has_repeats:
        feedback.append("Avoid repeating the same character 3+ times in a row.")
    if has_sequence:
        feedback.append("Avoid simple sequences (e.g., abc, 123, qwerty).")
    if meets_length and meets_variety and not (is_common or has_repeats or has_sequence) and bits < 90:
        feedback.append("Increase length for more entropy (aim for 16+).")

    return {
        "length": len(password),
        "entropy_bits": bits,
        "pool_size": pool_size(password),
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "meets_length": meets_length,
        "meets_variety": meets_variety,
        "is_common": is_common,
        "has_repeats": has_repeats,
        "has_sequence": has_sequence,
        "rating": rating,
        "score": score,
        "feedback": feedback,
    }


# ---- Tkinter UI ----

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("560x380")
        self.minsize(520, 360)

        self.password_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)

        self._build_widgets()
        self._wire_events()

    def _build_widgets(self):
        pad = {"padx": 14, "pady": 10}

        header = ttk.Label(self, text="Password Strength Checker", font=("Segoe UI", 16, "bold"))
        header.pack(anchor="w", **pad)

        frame = ttk.Frame(self)
        frame.pack(fill="x", **pad)

        ttk.Label(frame, text="Enter Password:").grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(frame, textvariable=self.password_var, width=42, show="•")
        self.entry.grid(row=0, column=1, sticky="we", padx=(8, 8))
        frame.columnconfigure(1, weight=1)

        self.toggle = ttk.Checkbutton(frame, text="Show", variable=self.show_var, command=self._toggle_show)
        self.toggle.grid(row=0, column=2, sticky="e")

        # Meter + rating
        self.style = ttk.Style(self)
        self.style.theme_use(self.style.theme_use())  # ensure style exists
        self.meter = ttk.Progressbar(self, orient="horizontal", length=100, mode="determinate", maximum=100)
        self.meter.pack(fill="x", **pad)

        self.rating_label = ttk.Label(self, text="Rating: —", font=("Segoe UI", 12, "bold"))
        self.rating_label.pack(anchor="w", padx=14)

        # Details grid
        details = ttk.LabelFrame(self, text="Details")
        details.pack(fill="x", padx=14, pady=8)

        self.length_var = tk.StringVar(value="Length: 0")
        self.entropy_var = tk.StringVar(value="Entropy: 0.00 bits")
        self.variety_var = tk.StringVar(value="Variety: —")

        ttk.Label(details, textvariable=self.length_var).grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Label(details, textvariable=self.entropy_var).grid(row=0, column=1, sticky="w", padx=8, pady=6)
        ttk.Label(details, textvariable=self.variety_var).grid(row=0, column=2, sticky="w", padx=8, pady=6)

        # Feedback
        self.feedback = tk.Text(self, height=6, wrap="word")
        self.feedback.configure(state="disabled")
        self.feedback.pack(fill="both", expand=True, padx=14, pady=10)

        # Footer hint
        ttk.Label(self, text="Tip: aim for 16+ chars with upper/lower/digit/symbol for strong entropy.",
                  foreground="#666").pack(anchor="w", padx=14, pady=(0, 10))

    def _wire_events(self):
        self.entry.bind("<KeyRelease>", lambda _e: self._refresh())
        self._refresh()

    def _toggle_show(self):
        self.entry.configure(show="" if self.show_var.get() else "•")

    def _set_meter_color(self, score: int):
        """Change progress bar color by score bracket."""
        # ttk Progressbar coloring is theme-specific; background usually works.
        if score < 30:
            color = "#d9534f"  # red
        elif score < 60:
            color = "#f0ad4e"  # orange
        elif score < 85:
            color = "#5bc0de"  # blue
        else:
            color = "#5cb85c"  # green
        style_name = "Strength.Horizontal.TProgressbar"
        self.style.configure(style_name, troughcolor="#eee", background=color)
        self.meter.configure(style=style_name)

    def _write_feedback(self, lines: list[str]):
        self.feedback.configure(state="normal")
        self.feedback.delete("1.0", "end")
        if not lines:
            self.feedback.insert("end", "Looks great! 🎉")
        else:
            for line in lines:
                self.feedback.insert("end", f"• {line}\n")
        self.feedback.configure(state="disabled")

    def _refresh(self):
        pw = self.password_var.get()
        result = evaluate_password(pw)

        self.meter["value"] = result["score"]
        self._set_meter_color(result["score"])

        self.rating_label.configure(text=f"Rating: {result['rating']}  ({result['score']}/100)")
        self.length_var.set(f"Length: {result['length']}")
        self.entropy_var.set(f"Entropy: {result['entropy_bits']} bits")
        kinds = []
        if result["has_lower"]: kinds.append("lower")
        if result["has_upper"]: kinds.append("upper")
        if result["has_digit"]: kinds.append("digit")
        if result["has_symbol"]: kinds.append("symbol")
        self.variety_var.set("Variety: " + (", ".join(kinds) if kinds else "—"))

        self._write_feedback(result["feedback"])


if __name__ == "__main__":
    try:
        App().mainloop()
    except tk.TclError as e:
        messagebox.showerror("Tk Error", f"Tkinter could not start:\n{e}\n"
                             "On Linux, install Tk: sudo apt-get install python3-tk")
