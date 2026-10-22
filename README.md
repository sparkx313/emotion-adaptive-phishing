# Emotion-Adaptive Phishing Engine (Typing Rhythm ML)

> Detects user emotional state from typing cadence patterns, then generates context-aware social engineering lures — and the countermeasure detector that catches them.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Concept

Human typing rhythm changes measurably under emotional stress:
- **Anxious**: faster keystrokes, more backspaces, higher inter-key variance
- **Angry**: harder key impacts (force if measured), shorter bursts, more all-caps
- **Sad**: slower rhythm, longer pauses, more deletions
- **Calm**: steady rhythm, low variance, consistent speed

This system:
1. **🔴 Red Module**: Builds a typing-emotion classifier + adaptive phishing email generator that tailors urgency, tone, and timing based on detected emotional state
2. **🔵 Blue Module**: A phishing email detector trained specifically on emotionally-adaptive lure patterns (harder to spot than generic phishing)

---

## Emotion Classification Model

| Feature | Source |
|---------|--------|
| Mean inter-key interval (ms) | Typing rhythm |
| Std dev of key intervals | Variability |
| Backspace frequency | Error rate |
| Burst-pause ratio | Stress indicator |
| Typing speed trend | Acceleration/deceleration |
| Key overlap rate | Simultaneous presses |
| Session duration | Engagement level |

**Classifier:** LSTM + Attention over keystroke timing sequence → 5-class emotion output

---

## Usage

### Train Emotion Classifier

```bash
python -m src.emotion_classifier.train \
    --data data/typing-sessions/ \
    --epochs 80 \
    --output checkpoints/emotion_lstm.pt
```

### Generate Adaptive Phishing Email (Red Team)

```python
from src.phishing_generator import EmotionAdaptivePhisher

phisher = EmotionAdaptivePhisher(
    emotion_model="checkpoints/emotion_lstm.pt",
    llm_api_key="your-api-key",  # optional: use local model
)

email = phisher.generate(
    target_name="alice@company.com",
    detected_emotion="anxious",
    context="recent_missed_deadline",
)
print(email.subject)  # "URGENT: Action Required on Your Account (Time-Sensitive)"
```

### Train Phishing Detector (Blue Team)

```bash
python -m src.phishing_detector.train \
    --corpus data/phishing-emails/ \
    --emotion-augmented \
    --output checkpoints/phish_detector.pt
```

---

## Dataset: EmotionTaggedTyping

The repo includes a synthetic typing rhythm dataset generator:

```bash
python src/generate_typing_data.py \
    --num-users 100 \
    --sessions-per-user 20 \
    --emotion-distribution balanced \
    --output data/typing-sessions/
```

Based on research parameters from:
- Chen et al. (2022): "Emotion Recognition from Keystroke Dynamics"
- Khan & Hamdy (2023): "Typing Pattern Analysis for Affective Computing"

---

## Project Structure

```
emotion-adaptive-phishing/
├── src/
│   ├── emotion_classifier/
│   │   ├── model.py         # LSTM emotion classifier
│   │   ├── features.py      # Keystroke feature extraction
│   │   └── train.py         # Training script
│   ├── phishing_generator/
│   │   ├── generator.py     # Emotion-adaptive email composer
│   │   ├── templates.py     # Emotion-specific lure templates
│   │   └── timing.py        # Optimal send-time predictor
│   ├── phishing_detector/
│   │   ├── detector.py      # Feature-rich phishing classifier
│   │   └── train.py         # Training pipeline
│   └── generate_typing_data.py
├── data/
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Ethical Framework

This project is a **security research contribution** in two ways:
1. Exposes how emotional state makes users more vulnerable to targeted phishing
2. Builds a detector that specifically defends against this class of attacks

All generated phishing samples are **fictional** and not deployed. Use only in controlled research settings with IRB approval if studying real users.

---

## License

MIT © [sparkx313](https://github.com/sparkx313)
