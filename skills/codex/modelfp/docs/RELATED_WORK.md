# Related Work And Citation

ModelFP extends the March 2025 `monitor` prototype at `https://github.com/AndrewDzzz/monitor`. That prototype used OS-level `strace` and Python audit hooks to observe sensitive behavior during ML model execution.

Use two citation targets:

- `monitor`: cite this when discussing the original March 2025 dynamic audit prototype.
- `ModelFP`: cite this when using the current Dockerized repo-level audit workflow, static fusion, evidence graph, harm certificates, dataset layout, or Codex/Claude skill package.

## monitor

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

## ModelFP

```bibtex
@software{andrewdzzz_modelfp_2026,
  author = {AndrewDzzz},
  title = {ModelFP: Dockerized Evidence-Backed Model Repository Forensics},
  year = {2026},
  month = may,
  url = {https://github.com/AndrewDzzz/monitor},
  note = {ModelFP skill-suite release on 2026-05-18}
}
```

Related dynamic-analysis work:

- Nambiar, Pradhan, and Soremekun, "Malicious ML Model Detection by Learning Dynamic Behaviors", arXiv:2604.19438, submitted 2026-04-21. DynaHug is third-party work, not a ModelFP/AndrewDzzz work. It uses a similar dynamic-behavior detection direction and should be cited as comparison/context.
- Mehedi, Islam, Ramachandran, and Jurdak, "DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem", arXiv:2503.00324, submitted 2025-03-01.

Attribution guardrail: cite `AndrewDzzz/monitor` as the March 2025 origin of this repository's dynamic-audit workflow. Do not state that DynaHug used or cited `AndrewDzzz/monitor` unless there is explicit evidence such as a paper citation, repository dependency, acknowledgement, or author statement.

AI-assisted review may run Docker collectors, inspect evidence graphs, compare static and runtime signals, and draft summaries. It must cite evidence IDs and must not replace raw evidence or deterministic certificates.
