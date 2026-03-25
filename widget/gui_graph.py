from __future__ import annotations

import multiprocessing
import time
from collections import deque
from typing import TYPE_CHECKING

import tkinter as tk

if TYPE_CHECKING:
    from widget.gui_main import MainWidget

# ── constants ────────────────────────────────────────────────────────────────
WINDOW_SECONDS  = 180   # rolling display width (s)
GRAPH_UPDATE_MS = 1000  # canvas redraw interval (ms)

N_X_GRID = 6
N_Y_GRID = 5

PAD_TOP    = 15
PAD_RIGHT  = 20
PAD_BOTTOM = 30
PAD_LEFT   = 58

C_BG    = '#1c1c2e'
C_PLOT  = '#12122a'
C_GRID  = '#2a2a45'
C_LABEL = '#8888aa'
C_LINE  = '#00e5ff'
C_FILL  = '#003d4d'
C_VALUE = '#ffffff'
C_PEAK  = '#ff9944'   # peak marker colour (orange)

_CLEAR = 'CLEAR'   # sentinel value sent through the queue

# ── Y-axis fixed scale tiers: (y_max KB/s, display divisor, unit label) ──────
# All values in KB/s (kilobits/s, SI): 1 byte/s = 1/125 KB/s
_TIERS: list[tuple[float, float, str]] = [
    (10,            1,         "KB/s"),   #   10 KB/s
    (100,           1,         "KB/s"),   #  100 KB/s
    (1_000,         1,         "KB/s"),   # 1000 KB/s

    (10_000,        1_000,     "MB/s"),   #   10 MB/s
    (100_000,       1_000,     "MB/s"),   #  100 MB/s
    (1_000_000,     1_000,     "MB/s"),   # 1000 MB/s

    (10_000_000,    1_000_000, "GB/s"),   #    1 GB/s
    (100_000_000,   1_000_000, "GB/s"),   #   10 GB/s
    (1_000_000_000, 1_000_000, "GB/s"),   #  100 GB/s
]

def _pick_tier(peak_kbps: float) -> tuple[float, float, str]:
    for tier in _TIERS:
        if peak_kbps <= tier[0]:
            return tier
    return _TIERS[-1]

def _fmt(v: float) -> str:
    return "0" if v == 0 else (f"{v:.1f}" if v < 10 else f"{int(v)}")

# ── moving average configs: (window_s, color, label, line_width) ─────────────
_AVGS: list[tuple[int, str, str, float]] = [
    (60, '#ff6688', 'T/60s', 1.0),   # 60-pt   – pink
    (10, '#ffcc00', 'T/10s', 1.0),   # 10-pt   – gold
    (5,  '#44ff88', 'T/5s ', 1.0),   # 5-pt    – green
    (1,  '#00e5ff', 'T/1s ', 1.5),   # raw     – cyan
]

def _moving_avg(values: list[float], window: int) -> list[float]:
    """Trailing moving average, O(n)."""
    if not values:
        return []
    result, s = [], 0.0
    for i, v in enumerate(values):
        s += v
        if i >= window:
            s -= values[i - window]
        result.append(s / min(i + 1, window))
    return result


# ── subprocess drawing logic (module-level — required for Windows spawn) ─────

def _redraw(cv: tk.Canvas, speed_history: deque, peak_kbps: float) -> None:
    cv.delete('all')

    W = cv.winfo_width()
    H = cv.winfo_height()
    if W < 50 or H < 50:
        return

    px1, px2 = PAD_LEFT,   W - PAD_RIGHT
    py1, py2 = PAD_TOP,    H - PAD_BOTTOM
    pw,  ph  = px2 - px1,  py2 - py1

    cv.create_rectangle(px1, py1, px2, py2, fill=C_PLOT, outline=C_GRID)

    now    = time.time()
    cutoff = now - WINDOW_SECONDS
    xs_raw = [t - now for t, _ in speed_history if t >= cutoff]   # [-180…0]
    ys_raw = [s       for t, s in speed_history if t >= cutoff]   # kb/s

    y_max, divisor, y_unit = _pick_tier(peak_kbps)

    def cx(t_rel: float) -> float:
        return px1 + (t_rel + WINDOW_SECONDS) / WINDOW_SECONDS * pw

    def cy(v_kbps: float) -> float:
        return py2 - (v_kbps / y_max) * ph

    # ── grid & tick labels ───────────────────────────────────────────────────
    for i in range(N_X_GRID + 1):
        x      = px1 + i * pw / N_X_GRID
        t_tick = -WINDOW_SECONDS + i * WINDOW_SECONDS / N_X_GRID
        cv.create_line(x, py1, x, py2, fill=C_GRID, dash=(3, 5))
        cv.create_text(x, py2 + 12, text=f"{int(t_tick)}s",
                       fill=C_LABEL, font=('Consolas', 8))

    for i in range(N_Y_GRID + 1):
        y           = py1 + i * ph / N_Y_GRID
        v_tick_kbps = y_max * (1 - i / N_Y_GRID)
        cv.create_line(px1, y, px2, y, fill=C_GRID, dash=(3, 5))
        cv.create_text(px1 - 6, y, text=_fmt(v_tick_kbps / divisor),
                       fill=C_LABEL, font=('Consolas', 8), anchor='e')

    cv.create_text(px1 - 30, py1 + ph // 2, text=y_unit,
                   fill=C_LABEL, font=('Consolas', 10, 'bold'))
    cv.create_text(px1 + pw // 2, H - 6, text="seconds ago",
                   fill=C_LABEL, font=('Consolas', 8))

    # ── moving average lines ─────────────────────────────────────────────────
    avg_last: list[float] = [0.0] * len(_AVGS)
    if len(xs_raw) >= 2:
        pts_cx = [cx(x) for x in xs_raw]
        all_ma = [_moving_avg(ys_raw, w) for w, *_ in _AVGS]

        for (_, color, _, lw), ma_vals in zip(_AVGS, all_ma):
            pts: list[float] = []
            for pcx, pcy in zip(pts_cx, [cy(v) for v in ma_vals]):
                pts += [pcx, pcy]
            cv.create_line(pts, fill=color, width=lw)

        avg_last = [ma[-1] if ma else 0.0 for ma in all_ma]

        # Peak dashed line + marker
        peak_y = cy(peak_kbps)
        cv.create_line(px1+2, peak_y, px2, peak_y, fill=C_PEAK, dash=(6, 4), width=1)
        cv.create_text(px1, peak_y, text="◀",
                       fill=C_PEAK, font=('Consolas', 8, 'bold'), anchor='w')
        cv.create_text(px1 + 10, peak_y - 10, text=f"{peak_kbps / divisor:.3f} {y_unit}",
                       fill=C_PEAK, font=('Consolas', 8, 'bold'), anchor='w')

    # ── legend: top-right ────────────────────────────────────────────────────
    for i, (_, color, label, lw) in enumerate(_AVGS):
        ly = py1 + 8 + i * 15
        val_str = _fmt(avg_last[i] / divisor)
        cv.create_text(px2 - 75, ly, text=f"{label}: {val_str}",
                       fill=color, font=('Consolas', 8, 'bold'), anchor='w')
        cv.create_line(px2 - 100, ly, px2 - 80, ly, fill=color, width=lw + 0.5)


def _graph_process(data_queue: multiprocessing.Queue,
                   running_event: multiprocessing.Event) -> None:
    """Subprocess entry point — owns its own Tk root and mainloop."""
    root = tk.Tk()
    root.title("TX Speed  –  I/O Graph")
    root.geometry("760x360")
    root.minsize(400, 220)
    root.resizable(True, True)
    root.configure(bg=C_BG)
    root.protocol("WM_DELETE_WINDOW", root.destroy)

    canvas = tk.Canvas(root, bg=C_BG, highlightthickness=0)
    canvas.pack(fill=tk.BOTH, expand=True)

    speed_history: deque = deque(maxlen=WINDOW_SECONDS)
    peak_kbps: float = 0.0

    def update() -> None:
        nonlocal peak_kbps

        # Drain all queued samples — update peak incrementally
        try:
            while True:
                item = data_queue.get_nowait()
                if item == _CLEAR:
                    speed_history.clear()
                    peak_kbps = 0.0
                else:
                    ts, spd = item
                    # If the deque is full, check whether the value about to be
                    # evicted (index 0) is the current peak.  Only then do we
                    # need a full O(n) rescan; every other append is O(1).
                    if len(speed_history) == speed_history.maxlen:
                        evicted_spd = speed_history[0][1]
                        speed_history.append(item)
                        if evicted_spd == peak_kbps:
                            peak_kbps = max((s for _, s in speed_history), default=0.0)
                        else:
                            peak_kbps = max(peak_kbps, spd)
                    else:
                        speed_history.append(item)
                        peak_kbps = max(peak_kbps, spd)
        except Exception:
            pass

        # Only redraw while sniffing is active
        if running_event.is_set():
            _redraw(canvas, speed_history, peak_kbps)

        root.after(GRAPH_UPDATE_MS, update)

    root.after(GRAPH_UPDATE_MS, update)
    root.mainloop()


# ── main-process controller ───────────────────────────────────────────────────

class SpeedGraph:
    """Spawns and manages the graph subprocess; feeds it data via a Queue."""

    def __init__(self, parent: MainWidget) -> None:
        self._queue:   multiprocessing.Queue  = multiprocessing.Queue(maxsize=500)
        self._running: multiprocessing.Event  = multiprocessing.Event()
        self._process: multiprocessing.Process | None = None

        # Graph starts in 'running' state so opening before sniffing shows live axes
        self._running.set()

    # ── public API ────────────────────────────────────────────────────────────
    def toggle(self) -> None:
        if self._process and self._process.is_alive():
            self._close()
        else:
            self._open()

    def push(self, timestamp: float, speed_kbps: float) -> None:
        """Feed one data point; silently discarded if graph is not open."""
        if self._process and self._process.is_alive():
            try:
                self._queue.put_nowait((timestamp, speed_kbps))
            except Exception:
                pass

    def on_start(self) -> None:
        """Call when sniffing starts — clears history and resumes updates."""
        # Drain leftover data from previous session
        while True:
            try:
                self._queue.get_nowait()
            except Exception:
                break
        try:
            self._queue.put_nowait(_CLEAR)
        except Exception:
            pass
        self._running.set()

    def on_stop(self) -> None:
        """Call when sniffing stops — freezes the graph display."""
        self._running.clear()

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def _open(self) -> None:
        self._process = multiprocessing.Process(
            target=_graph_process,
            args=(self._queue, self._running),
            daemon=True
        )
        self._process.start()

    def _close(self) -> None:
        if self._process and self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=1)
        self._process = None
