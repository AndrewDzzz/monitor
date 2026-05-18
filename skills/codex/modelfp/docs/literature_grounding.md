# Literature Grounding

ModelFP uses literature-grounding nodes (`LIT*`) to explain why a finding belongs in the evidence chain. These nodes are not primary facts about the target model. They map observed evidence IDs and verified certificates to published detection methods and supply-chain provenance patterns.

## Source Map

| ID | Source | ModelFP use |
|---|---|---|
| `zhao_2024_malhug` | Zhao et al., "Models Are Codes", arXiv:2409.09368 | Ground custom-code loading, model deserialization, taint-style chains, and heuristic pattern matching. |
| `casey_2024_hf_exploit` | Casey et al., "A Large-Scale Exploit Instrumentation Study", arXiv:2410.04490 | Ground unsafe serialization and Hugging Face exploit instrumentation. |
| `siddiq_2026_rce` | Siddiq et al., "An Empirical Study on Remote Code Execution in ML Model Hosting Ecosystems", arXiv:2601.14163 | Ground `trust_remote_code` / custom loader RCE risk and static-analysis/YARA-style taxonomy. |
| `nambiar_2026_dynahug` | Nambiar et al., "Malicious ML Model Detection by Learning Dynamic Behaviors", arXiv:2604.19438 | Ground runtime-behavior evidence from syscall/audit traces. |
| `safepickle_2026` | "SafePickle", arXiv:2602.19818 | Ground pickle bytecode feature extraction and scanner limitations. |
| `torres_arias_2019_intoto` | Torres-Arias et al., "in-toto", USENIX Security 2019 | Ground verifiable certificate chains and supply-chain provenance metadata. |
| `huggingface_pickle_scanning` | Hugging Face Hub pickle-scanning docs | Ground non-executing pickle import/opcode inspection and signed-origin caution. |

## Evidence Mapping

`code/literature_mapper.py` currently emits:

- `unsafe_serialization_methodology_match` for risky serialized model formats or ModelScan evidence.
- `custom_code_loading_methodology_match` for `auto_map`, `trust_remote_code`, custom Hugging Face Python files, Python/Lambda AST risk calls, and suspicious loader/setup scripts.
- `repo_hygiene_methodology_match` for non-model payload files, README script/app instructions, abnormal or repeated commits, model-card/task mismatch, and malware-hosting-like file trees.
- `malware_static_methodology_match` for malware-style static triage such as executable magic, shell download cradles, PowerShell stagers, reverse shells, persistence hooks, credential-harvesting strings, miner indicators, and obfuscation patterns.
- `static_fusion_methodology_match` for repo-level fusion of malware triage, config risk, unsafe serialization, ModelScan, AST, all-file payload, and repo hygiene evidence.
- `dynamic_behavior_methodology_match` for runtime events such as shell execution, external connects, secret path opens, Docker socket access, or other risk-hinted syscall/audit events.
- `verified_chain_provenance_methodology_match` when deterministic rulecheck produces verified certificates.
- `static_runtime_correlation_methodology_match` when both static model-artifact risk and runtime behavior appear in the same run.

## Review Guidance

When Codex reviews `llm_payload.json`, treat `LIT*` nodes as methodology support:

- Cite primary `R*`, `C*`, `S*`, `ENV*`, and `E*` evidence for what happened.
- Cite `LIT*` nodes for why that evidence-chain pattern is meaningful.
- Do not upgrade a verdict solely because a paper is cited.
- Do not claim that the cited paper proves the target model is malicious.
