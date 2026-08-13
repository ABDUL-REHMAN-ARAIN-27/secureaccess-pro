"""
Deterministic generator for ~55 synthetic patient records.

All data is fake but realistic, covering a range of serious medical cases so
the Patient Records module looks substantial in a demo. Deterministic (fixed
random seed) so re-seeding produces the same set.
"""

import random

FIRST_NAMES = [
    "Imran", "Nadia", "Kamran", "Sara", "Bilal", "Hina", "Ali", "Ayesha", "Usman",
    "Fatima", "Hamza", "Zainab", "Ahmed", "Maryam", "Bilquis", "Tariq", "Rabia",
    "Junaid", "Saima", "Noman", "Kiran", "Faisal", "Amna", "Rizwan", "Sadia",
    "Adnan", "Mehwish", "Yasir", "Nimra", "Salman", "Iqra", "Waqas", "Hooria",
    "Kashif", "Rida", "Owais", "Sana", "Danish", "Areeba", "Shahzad",
]
LAST_NAMES = [
    "Khan", "Ahmed", "Malik", "Hussain", "Shah", "Iqbal", "Raza", "Anwar",
    "Butt", "Chaudhry", "Baig", "Qureshi", "Siddiqui", "Farooqi", "Memon",
    "Abbasi", "Rehman", "Mughal", "Sheikh", "Bhatti",
]

# (diagnosis, department, typical severity pool)
CASES = [
    ("Acute Myocardial Infarction", "Cardiology", ["Critical", "Serious"]),
    ("Congestive Heart Failure",    "Cardiology", ["Serious", "Moderate"]),
    ("Cardiac Arrhythmia",          "Cardiology", ["Serious", "Moderate"]),
    ("Ischemic Stroke",             "Neurology",  ["Critical", "Serious"]),
    ("Traumatic Brain Injury",      "Neurology",  ["Critical", "Serious"]),
    ("Epilepsy - Status Epilepticus", "Neurology", ["Serious", "Moderate"]),
    ("Sepsis",                      "ICU",        ["Critical"]),
    ("Acute Respiratory Distress",  "ICU",        ["Critical"]),
    ("Multi-Organ Failure",         "ICU",        ["Critical"]),
    ("Severe Pneumonia",            "Pulmonology",["Serious", "Moderate"]),
    ("COPD Exacerbation",           "Pulmonology",["Serious", "Moderate"]),
    ("Acute Kidney Injury",         "Nephrology", ["Serious", "Moderate"]),
    ("Chronic Kidney Disease St. 4","Nephrology", ["Moderate", "Stable"]),
    ("Acute Pancreatitis",          "Gastroenterology", ["Serious", "Moderate"]),
    ("GI Bleeding",                 "Gastroenterology", ["Serious", "Moderate"]),
    ("Diabetic Ketoacidosis",       "Endocrinology", ["Serious", "Moderate"]),
    ("Type 2 Diabetes - Complicated","Endocrinology",["Moderate", "Stable"]),
    ("Leukemia",                    "Oncology",   ["Critical", "Serious"]),
    ("Lung Carcinoma",              "Oncology",   ["Serious", "Moderate"]),
    ("Breast Carcinoma",            "Oncology",   ["Serious", "Moderate"]),
    ("Polytrauma - RTA",            "Emergency",  ["Critical", "Serious"]),
    ("Severe Burns",                "Emergency",  ["Critical", "Serious"]),
    ("Hypertensive Emergency",      "Emergency",  ["Serious", "Moderate"]),
    ("Post-Operative Recovery",     "Surgery",    ["Moderate", "Stable"]),
    ("Appendectomy - Recovery",     "Surgery",    ["Stable"]),
]
DOCTORS = [
    "Dr. Zafar", "Dr. Meher", "Dr. Rehman", "Dr. Aslam", "Dr. Naveed",
    "Dr. Shabana", "Dr. Kamal", "Dr. Farah", "Dr. Junaid", "Dr. Nasreen",
]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]


def _status_for(severity):
    if severity == "Critical":
        return "ICU"
    if severity == "Serious":
        return "Admitted"
    if severity == "Moderate":
        return random.choice(["Admitted", "Outpatient"])
    return random.choice(["Outpatient", "Discharged"])


def generate_patients(count=55, seed=27):
    """Return `count` deterministic patient dicts."""
    rng = random.Random(seed)
    # keep module-level random.choice deterministic too
    random.seed(seed)
    patients = []
    for i in range(count):
        diagnosis, department, sev_pool = rng.choice(CASES)
        severity = rng.choice(sev_pool)
        gender = rng.choice(["M", "F"])
        name = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"
        month = rng.randint(1, 8)
        day = rng.randint(1, 28)
        patients.append({
            "patient_id": f"PT-{2001 + i}",
            "name": name,
            "age": rng.randint(3, 88),
            "gender": gender,
            "blood_group": rng.choice(BLOOD),
            "diagnosis": diagnosis,
            "severity": severity,
            "department": department,
            "attending": rng.choice(DOCTORS),
            "status": _status_for(severity) if severity != "Moderate" else random.choice(["Admitted", "Outpatient"]),
            "admitted_on": f"2025-{month:02d}-{day:02d}",
            "contact": f"03{rng.randint(0,9)}{rng.randint(0,9)}-{rng.randint(1000000, 9999999)}",
        })
    return patients
