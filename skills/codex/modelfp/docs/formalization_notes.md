# ModelFP Formalization Notes

## 1. Objects

Let:

```text
R = Hugging Face repository
rev = repository revision
C = configuration files
A = model artifacts
E = execution environment
T = normalized runtime trace
G = evidence graph
P = policy/rule set
Cert = harm certificate
```

ModelFP does not prove universal model safety. It verifies evidence-backed harm verdicts for observed executions.

## 2. Trace

A trace is a finite sequence:

```text
T = [e1, e2, ..., en]
```

Each event has:

```text
id, time, pid, phase, source, op, args, result, labels
```

## 3. Evidence Graph

The evidence graph is:

```text
G = (V, E)
```

V contains static findings, config findings, environment findings, runtime events, harm chains, and candidate rules.

E contains relations such as:

```text
belongs_to, derived_from, precedes, same_process, uses_fd, reads_from, writes_to, supports, correlates_with
```

## 4. Rule Semantics

Each rule R defines a predicate over G and a witness mapping W:

```text
[[R]](G, W) ∈ {true, false}
```

Example:

```text
SecretExfiltration(G, W) :=
  open_secret(W.a)
  ∧ read_from_fd(W.b, W.a.fd)
  ∧ external_connect(W.c)
  ∧ write_to_fd(W.d, W.c.fd)
  ∧ same_process(W.a, W.b, W.c, W.d)
  ∧ before(W.a, W.b)
  ∧ before(W.b, W.c)
  ∧ before(W.c, W.d)
  ∧ within(W.a, W.d, 30s)
```

## 5. Certificate Validity

```text
valid(Cert, G, P) :=
  rule(Cert.rule_id) ∈ P
  ∧ ∀ evidence_id ∈ Cert.evidence, evidence_id ∈ G
  ∧ [[rule(Cert.rule_id)]](G, Cert.witness) = true
  ∧ Cert.verdict = rule(Cert.rule_id).verdict
  ∧ Cert.severity = rule(Cert.rule_id).severity
```

## 6. Soundness Theorem

```text
Theorem: Harm Certificate Soundness

If valid(Cert, G, P) = true,
then G contains a witness subgraph satisfying the formal semantics of Cert.rule_id.
```

Interpretation:

```text
A verified ModelFP harm certificate cannot be evidence-free.
```

## 7. Bounded No-Observed-Harm

```text
Theorem: Bounded No-Observed-Harm

Given policy P, evidence graph G, and collector coverage K.
If rulecheck(P, G) reports no harm H,
and all event types required by H are covered by K,
then G contains no witness subgraph satisfying H.
```

This theorem does not prove that the model is safe. It proves only that the current evidence graph lacks a witness for H under the covered event types.

## 8. GPT Exclusion from Trusted Core

GPT is not part of the trusted proof core.

Trusted core:

```text
evidence graph builder
rule DSL parser
rulecheck engine
certificate generator
certificate verifier
rule evolution gate
```

Untrusted/helper layer:

```text
GPT summary
GPT candidate rules
GPT explanations
```

GPT outputs must be validated before use.
