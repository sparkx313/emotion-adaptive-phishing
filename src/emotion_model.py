"""
LSTM Emotion Classifier from Keystroke Timing Sequences.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import List, Tuple

# 7-dimensional keystroke timing features per keypress
# [inter_key_ms, hold_ms, backspace_flag, shift_flag, bigram_gap, speed_trend, burst_ratio]
FEATURE_DIM = 7
SEQ_LEN = 64  # max sequence length (keypresses)

EMOTIONS = ["calm", "happy", "anxious", "angry", "sad"]
EMOTION_TO_IDX = {e: i for i, e in enumerate(EMOTIONS)}
NUM_EMOTIONS = len(EMOTIONS)


class KeystrokeAttention(nn.Module):
    """Single-head attention over keystroke sequence positions."""

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attn = nn.Linear(hidden_dim, 1)

    def forward(self, lstm_out: torch.Tensor) -> torch.Tensor:
        # lstm_out: (B, T, H)
        weights = torch.softmax(self.attn(lstm_out), dim=1)  # (B, T, 1)
        context = (lstm_out * weights).sum(dim=1)             # (B, H)
        return context


class EmotionLSTM(nn.Module):
    """
    LSTM + Attention classifier for 5-emotion typing rhythm recognition.
    Input:  (B, T, FEATURE_DIM) keystroke timing feature sequences
    Output: (B, NUM_EMOTIONS) emotion logits
    """

    def __init__(
        self,
        input_dim: int = FEATURE_DIM,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0,
        )
        self.attention = KeystrokeAttention(hidden_dim * 2)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, NUM_EMOTIONS),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (B, T, FEATURE_DIM)"""
        lstm_out, _ = self.lstm(x)   # (B, T, H*2)
        context = self.attention(lstm_out)  # (B, H*2)
        return self.classifier(context)

    @torch.no_grad()
    def predict_emotion(self, x: torch.Tensor) -> Tuple[str, float]:
        self.eval()
        logits = self.forward(x)
        probs = F.softmax(logits, dim=-1)
        conf, idx = probs.max(dim=-1)
        return EMOTIONS[idx.item()], float(conf.item())


def extract_keystroke_features(events: List[dict], max_seq: int = SEQ_LEN) -> np.ndarray:
    """
    Convert raw keystroke events to feature matrix.

    events: list of {"key": str, "press_time": float, "release_time": float}
    Returns: (max_seq, FEATURE_DIM) float32 array.
    """
    features = np.zeros((max_seq, FEATURE_DIM), dtype=np.float32)

    if not events:
        return features

    times = np.array([e["press_time"] for e in events])
    holds = np.array([e["release_time"] - e["press_time"] for e in events])
    keys = [e["key"] for e in events]

    n = min(len(times), max_seq)

    # Inter-key interval (ms)
    intervals = np.diff(times) * 1000
    features[:n - 1, 0] = intervals[: n - 1]
    features[n - 1, 0] = intervals[-1] if len(intervals) > 0 else 0

    # Hold duration (ms)
    features[:n, 1] = holds[:n] * 1000

    # Backspace flag
    for i, k in enumerate(keys[:n]):
        if k == "Backspace":
            features[i, 2] = 1.0

    # Shift/caps flag
    for i, k in enumerate(keys[:n]):
        if k in ("Shift", "CapsLock"):
            features[i, 3] = 1.0

    # Bigram gap (time since same key pair last occurred)
    seen = {}
    for i in range(n):
        key = keys[i] if i < len(keys) else ""
        if key in seen:
            features[i, 4] = (times[i] - times[seen[key]]) * 1000
        seen[key] = i

    # Speed trend (rolling window)
    if len(intervals) > 5:
        window = np.convolve(intervals, np.ones(5) / 5, mode="valid")
        speed_trend = np.diff(window)
        features[: min(len(speed_trend), n), 5] = speed_trend[:n]

    # Burst ratio (consecutive fast keys)
    fast = (intervals < 150).astype(np.float32)
    burst = np.convolve(fast, np.ones(10) / 10, mode="valid")
    features[: min(len(burst), n), 6] = burst[:n]

    # Normalize
    features[:n] = (features[:n] - features[:n].mean(axis=0)) / (features[:n].std(axis=0) + 1e-9)

    return features
