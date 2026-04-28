from PyQt5.QtWidgets import QWidget, QVBoxLayout
from PyQt5.QtCore import QTimer, QMutex
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from collections import deque
import time


class LiveGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.mutex         = QMutex()
        self.timestamps    = deque(maxlen=200)
        self.normal_counts = deque(maxlen=200)
        self.attack_counts = deque(maxlen=200)

        # ── Figure setup ───────────────────────────────
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.fig.patch.set_facecolor("#f0f0f0")
        self.ax.set_facecolor("#f8f8f8")
        self.ax.set_xlabel("Elapsed Time (s)", fontsize=10)
        self.ax.set_ylabel("Cumulative Packet Count", fontsize=10)
        self.ax.set_title("Live Traffic Monitor", fontsize=11, fontweight="bold")
        self.ax.grid(True, alpha=0.4, linestyle="--")

        self.line_normal, = self.ax.plot([], [], label="Normal",  color="#1a8fff", lw=2)
        self.line_attack, = self.ax.plot([], [], label="Attack",  color="#e63946", lw=2)
        self.ax.legend(loc="upper left", fontsize=9)

        self.canvas = FigureCanvas(self.fig)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)
        self.setLayout(layout)

        # Refresh graph every 2 s from main thread only
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._refresh_graph)
        self.update_timer.start(2000)

    def update_graph(self, normal_count, attack_count):
        """Thread-safe data update — called via queued signal from controller."""
        self.mutex.lock()
        self.timestamps.append(time.time())
        self.normal_counts.append(normal_count)
        self.attack_counts.append(attack_count)
        self.mutex.unlock()

    def _refresh_graph(self):
        """Render — always runs in main UI thread via QTimer."""
        self.mutex.lock()
        if not self.timestamps:
            self.mutex.unlock()
            return

        base_time      = self.timestamps[0]
        x_vals         = [t - base_time for t in self.timestamps]
        normal_counts  = list(self.normal_counts)
        attack_counts  = list(self.attack_counts)
        self.mutex.unlock()

        self.line_normal.set_data(x_vals, normal_counts)
        self.line_attack.set_data(x_vals, attack_counts)

        # X-axis: always show from 0 to latest second (min 60 s window)
        x_max = max(x_vals[-1], 60) if x_vals else 60
        self.ax.set_xlim(0, x_max)

        # Y-axis: 0 to max value with a small top margin
        y_max = max(10, max(normal_counts + attack_counts, default=10))
        self.ax.set_ylim(0, y_max * 1.1)

        self.canvas.draw_idle()   # draw_idle is safer than draw() in timer callbacks