import pandas as pd

SCENARIOS_CSV = "IncidentScenarios.csv"
ENV_CSV = "EnvironmentProfile.csv"
OUTPUT_CSV = "IncidentScenarios_Scored.csv"
REPORT_MD = "DRScenarioReport.md"


def calculate_similarity(row, env):
    score = 0

    event_type = str(row["event_type"]).upper()
    business_function = str(row["business_function"]).lower()

    primary_cloud = str(env.get("primary_cloud", "")).lower()
    identity_platform = str(env.get("identity_platform", "")).lower()
    on_prem_count = int(env.get("on_premise_datacenters", 0) or 0)
    critical_functions = str(env.get("primary_business_functions", "")).lower().split(";")

    # --- Failure pattern ---
    if "RANSOMWARE" in event_type:
        score += 2
    elif "BREACH" in event_type:
        score += 1
    elif "IDENTITY" in event_type:
        score += 2
    elif "CLOUD" in event_type:
        score += 2
    elif "NETWORK" in event_type:
        score += 1
    elif "APPLICATION" in event_type:
        score += 1

    # --- Technology / infrastructure match ---
    if "CLOUD" in event_type and primary_cloud == "azure":
        score += 1

    if "IDENTITY" in event_type and "active" in identity_platform:
        score += 1

    if "RANSOMWARE" in event_type and on_prem_count > 0:
        score += 1

    # --- Business function match ---
    for f in critical_functions:
        f = f.strip()
        if f and f in business_function:
            score += 1
            break

    # --- Normalize to 1-5 ---
    if score <= 0:
        return 1
    return min(score, 5)


def calculate_impact(event_type):
    if "RANSOMWARE" in event_type:
        return 5
    if "IDENTITY" in event_type:
        return 5
    if "CLOUD" in event_type:
        return 4
    if "NETWORK" in event_type:
        return 4
    if "BREACH" in event_type:
        return 3   # <-- reduce generic breaches
    return 3


def calculate_likelihood(evidence_count):

    if evidence_count >= 5:
        return 5
    elif evidence_count >= 3:
        return 4
    elif evidence_count >= 2:
        return 3
    else:
        return 1   # <-- change from 2 to 1


def main():

    df = pd.read_csv(SCENARIOS_CSV)
    env = pd.read_csv(ENV_CSV).iloc[0]

    scores = []

    for _, row in df.iterrows():

        likelihood = calculate_likelihood(row["evidence_count"])
        impact = calculate_impact(row["event_type"])
        similarity = calculate_similarity(row, env)

        final_score = likelihood * impact * similarity

        print(
    row["scenario_title"],
    row["evidence_count"],
    likelihood,
    impact,
    similarity,
    final_score
)

        scores.append({
            **row,
            "likelihood": likelihood,
            "impact": impact,
            "similarity": similarity,
            "final_score": final_score
        })

    df_out = pd.DataFrame(scores)
    df_out = df_out.sort_values(by="final_score", ascending=False)

    df_out.to_csv(OUTPUT_CSV, index=False)

    # --- Create simple report ---
    with open(REPORT_MD, "w") as f:

        f.write("# DR Scenario Risk Assessment\n\n")
        f.write("Top Scenarios Based on Environment\n\n")

        top = df_out.head(10)

        for i, r in top.iterrows():
            f.write(f"## {r['scenario_title']}\n")
            f.write(f"Score: {r['final_score']} (L={r['likelihood']} I={r['impact']} S={r['similarity']})\n")
            f.write(f"Incident: {r['incident_title']}\n")
            f.write(f"Impact: {r['operational_impact']}\n")
            f.write(f"Recovery Focus: {r['recovery_focus']}\n\n")

    print("Scored scenarios and report created.")


if __name__ == "__main__":
    main()