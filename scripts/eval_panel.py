"""Mide el panel contra el corpus etiquetado usando los proveedores REALES
configurados en el entorno (.env). Uso manual:

    uv run python scripts/eval_panel.py

Criterios de aceptacion (exit code 1 si no se cumplen):
  - 0 hallazgos REALES descartados (`dismissed`).           -> sin falsos negativos
  - <= 20 % de los FALSOS POSITIVOS quedan `confirmed`.     -> el panel filtra ruido
No imprime claves ni contenido de .env.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents"))

from dotenv import load_dotenv  # noqa: E402
from findings import make_finding  # noqa: E402
from llm_router import CredentialRouter  # noqa: E402
from panel import run_panel  # noqa: E402

MAX_FP_CONFIRMED_RATE = 0.20


def main() -> int:
    load_dotenv(ROOT / ".env")
    cases = json.loads((ROOT / "eval" / "corpus.json").read_text())
    findings, truth = [], {}
    for index, case in enumerate(cases, start=1):
        finding = make_finding(
            source=case["source"], rule=case["rule"], severity=case["severity"],
            tier=case["tier"], file=case["file"], line=case["line"],
            message=case["message"], evidence=case["evidence"],
        )
        finding["id"] = f"F{index:03d}"
        findings.append(finding)
        truth[finding["id"]] = case["label"]

    router = CredentialRouter()
    result = run_panel(router, findings, "eval-corpus")
    consolidated = result["consolidated"]

    print(f"Panel: min_size={result['min_size']} diverse={result['diverse']} error={result['error']}")
    per_provider: dict[str, dict[str, int]] = {}
    for finding_id, entry in consolidated.items():
        for vote in entry["votes"]:
            stats = per_provider.setdefault(
                vote["provider"], {"correct": 0, "wrong": 0, "abstain": 0}
            )
            if vote["verdict"] == "uncertain":
                stats["abstain"] += 1
            elif vote["verdict"] == truth[finding_id]:
                stats["correct"] += 1
            else:
                stats["wrong"] += 1
    for provider, stats in sorted(per_provider.items()):
        print(f"  {provider:12s} correctos={stats['correct']} errados={stats['wrong']} abstenciones={stats['abstain']}")

    real_dismissed = [i for i, t in truth.items() if t == "real" and consolidated[i]["status"] == "dismissed"]
    fp_ids = [i for i, t in truth.items() if t == "false_positive"]
    fp_confirmed = [i for i in fp_ids if consolidated[i]["status"] == "confirmed"]
    fp_dismissed = [i for i in fp_ids if consolidated[i]["status"] == "dismissed"]
    rate = len(fp_confirmed) / len(fp_ids)

    print(f"Reales descartados (debe ser 0): {len(real_dismissed)} {real_dismissed}")
    print(f"FP descartados: {len(fp_dismissed)}/{len(fp_ids)} | FP confirmados: {len(fp_confirmed)}/{len(fp_ids)} ({rate:.0%}, max {MAX_FP_CONFIRMED_RATE:.0%})")
    return 0 if not real_dismissed and rate <= MAX_FP_CONFIRMED_RATE else 1


if __name__ == "__main__":
    sys.exit(main())
