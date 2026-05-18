"""ModelFP Hugging Face local-model target.

Run this inside the Docker sandbox with a pre-downloaded HF snapshot mounted at
/workspace/models/model. This target intentionally uses local_files_only=True so
runtime can be executed with --network none.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", default="/workspace/models/model")
    parser.add_argument("--prompt", default="hello")
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--load-only", action="store_true")
    parser.add_argument("--max-new-tokens", type=int, default=8)
    args = parser.parse_args()

    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    os.environ.setdefault("HF_HUB_OFFLINE", "1")

    print(f"[ModelFP HF target] loading from {args.model_dir}")
    print(f"[ModelFP HF target] trust_remote_code={args.trust_remote_code}")

    from transformers import AutoConfig, AutoModel, AutoModelForCausalLM, AutoModelForSeq2SeqLM, AutoTokenizer
    import torch

    model_dir = Path(args.model_dir)
    cfg = AutoConfig.from_pretrained(model_dir, local_files_only=True, trust_remote_code=args.trust_remote_code)
    print(f"[ModelFP HF target] model_type={getattr(cfg, 'model_type', None)}")

    tokenizer = None
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True, trust_remote_code=args.trust_remote_code)
    except Exception as exc:
        print(f"[ModelFP HF target] tokenizer unavailable: {type(exc).__name__}: {exc}")

    try:
        model = AutoModelForSeq2SeqLM.from_pretrained(model_dir, local_files_only=True, trust_remote_code=args.trust_remote_code)
        model_kind = "AutoModelForSeq2SeqLM"
    except Exception as exc:
        print(f"[ModelFP HF target] Seq2SeqLM load failed: {type(exc).__name__}: {exc}")
        try:
            model = AutoModelForCausalLM.from_pretrained(model_dir, local_files_only=True, trust_remote_code=args.trust_remote_code)
            model_kind = "AutoModelForCausalLM"
        except Exception as exc:
            print(f"[ModelFP HF target] CausalLM load failed: {type(exc).__name__}: {exc}")
            model = AutoModel.from_pretrained(model_dir, local_files_only=True, trust_remote_code=args.trust_remote_code)
            model_kind = "AutoModel"

    model.eval()
    print(f"[ModelFP HF target] loaded {model_kind} class={type(model).__name__}")

    if args.load_only or tokenizer is None:
        print("[ModelFP HF target] load-only or tokenizer unavailable; stopping after load")
        return

    with torch.no_grad():
        inputs = tokenizer(args.prompt, return_tensors="pt")
        if hasattr(model, "generate"):
            outputs = model.generate(**inputs, max_new_tokens=args.max_new_tokens)
            decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
            print("[ModelFP HF target output]", decoded[:500])
        else:
            outputs = model(**inputs)
            print("[ModelFP HF target output type]", type(outputs).__name__)


if __name__ == "__main__":
    main()
