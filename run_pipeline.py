import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Run stages in order. Intake is optional but included by default.
STEPS = [
    "Intake.py",
    "ClusterIncidents.py",
    "GenerateRiskCandidates.py",
    "EnrichRiskCandidates.py",
    "GenerateReports.py",
    "GenerateDashboards.py",
]


def run_step(script_name: str) -> None:
    script_path = BASE_DIR / script_name
    if not script_path.exists():
        raise FileNotFoundError(f"Required script not found: {script_path}")

    print(f"\n{'=' * 70}")
    print(f"Running: {script_name}")
    print(f"{'=' * 70}")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Step failed: {script_name} (exit code {result.returncode})")



def main() -> None:
    print("AI Risk Intelligence Pipeline Runner")
    print(f"Working directory: {BASE_DIR}")
    print("Close all CSV files in Excel before running this pipeline.\n")

    try:
        for step in STEPS:
            run_step(step)
    except Exception as exc:
        print(f"\nPipeline stopped: {exc}")
        sys.exit(1)

    print("\nPipeline completed successfully.")
    print("Generated outputs include:")
    print("- EvidenceCache.csv")
    print("- IncidentClusters.csv")
    print("- RiskCandidates.csv")
    print("- RiskCandidates_Enriched.csv")
    print("- RiskReport.csv / RiskReport.md / RiskTrends.csv")
    print("- Dashboard_Risks.csv / Dashboard_RiskEvidence.csv")


if __name__ == "__main__":
    main()
