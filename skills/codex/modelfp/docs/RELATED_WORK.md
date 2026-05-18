# Related Work And Citation

ModelFP extends the March 2025 `monitor` prototype at `https://github.com/AndrewDzzz/monitor`. That prototype used OS-level `strace` and Python audit hooks to observe sensitive behavior during ML model execution.

Use this citation when discussing the dynamic-audit idea:

```bibtex
@software{andrewdzzz_monitor_2025,
  author = {AndrewDzzz},
  title = {monitor: strace and Python audit hook monitoring for ML model execution},
  year = {2025},
  month = mar,
  url = {https://github.com/AndrewDzzz/monitor},
  note = {Initial public commit on 2025-03-15; README updated on 2025-03-24}
}
```

Related dynamic-analysis work:

- Nambiar, Pradhan, and Soremekun, "Malicious ML Model Detection by Learning Dynamic Behaviors", arXiv:2604.19438, submitted 2026-04-21.
- Mehedi, Islam, Ramachandran, and Jurdak, "DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem", arXiv:2503.00324, submitted 2025-03-01.

AI-assisted review may run Docker collectors, inspect evidence graphs, compare static and runtime signals, and draft summaries. It must cite evidence IDs and must not replace raw evidence or deterministic certificates.
