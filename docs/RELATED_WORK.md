# Related Work And Citation

## Project Lineage

ModelFP extends the March 2025 `monitor` prototype in this repository. That prototype used OS-level tracing and Python audit hooks to observe sensitive behavior during ML model execution.

Please cite the original public project when using the dynamic-audit idea:

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

Useful commit anchors:

- Initial public commit: `518e9d82721f10d908f0f54512790f69ec55f947`, 2025-03-15.
- Pre-ModelFP README update: `ec0f77ebf710c9f3e9c587a20a3a0dfe4ba7ba21`, 2025-03-24.
- ModelFP skill-suite release: `ef42f9cd5451f8f8100ee6492ce524453ee00155`, 2026-05-18.

## Dynamic Analysis Context

Dynamic analysis is valuable because static model scanners can miss behavior that only appears at model load or execution time. ModelFP keeps this idea repo-level and evidence-based: static risk, runtime behavior, and deterministic certificates are separate layers that can be linked but should not be conflated.

Related dynamic-analysis work includes:

- Nambiar, Pradhan, and Soremekun, "Malicious ML Model Detection by Learning Dynamic Behaviors", arXiv:2604.19438, submitted 2026-04-21. DynaHug learns benign PTM runtime behavior and compares dynamic model behavior against static, dynamic, and LLM-based baselines.
- Mehedi, Islam, Ramachandran, and Jurdak, "DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem", arXiv:2503.00324, submitted 2025-03-01. DySec shows the broader supply-chain value of controlled runtime behavior monitoring with kernel/user-level probes.

## AI-Assisted Audit Position

The March 2025 prototype assumed that a human auditor would inspect logs and rule hits. By 2026, code-capable AI agents can assist that workflow:

- run the Dockerized collectors consistently;
- normalize logs into evidence graphs;
- check whether claims cite evidence IDs;
- compare static and runtime signals;
- draft review summaries, rules, and follow-up experiments.

The AI remains an audit assistant, not the source of truth. ModelFP keeps raw evidence, deterministic rules, and certificates as the primary artifacts.
