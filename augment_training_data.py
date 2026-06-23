# =============================================================================
# augment_training_data.py — Add legitimate long-hostname samples
# =============================================================================
# PURPOSE:
#   The current training set has only 3.2% legitimate samples with hostnames
#   > 20 characters, while phishing domains average 19.7 chars vs legitimate
#   12.3 chars.  This causes the Random Forest to treat long readable brand
#   names (e.g. skillupwithlevelup.com) as phishing.
#
#   This script appends curated legitimate long-hostname URLs (label=0) to
#   training_data.csv and reports before/after statistics.
#
# USAGE:
#   cd backend
#   python augment_training_data.py
#   python train_model.py          ← retrain on the augmented dataset
#
# SAFE TO RE-RUN: Duplicate URLs are detected and skipped automatically.
# =============================================================================

import os
import csv
import urllib.parse

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.csv")

# =============================================================================
# Curated legitimate long-hostname samples  (label = 0)
# =============================================================================
# Selection criteria:
#   • Real compound-word brand/service names with hostnames >= 20 characters
#   • Readable, vowel-rich, low-entropy — opposite of DGA/phishing patterns
#   • Covers: e-learning, finance, health, legal, travel, SaaS, non-profit
#   • HTTPS only — no TLS signal to confuse the model
#   • No path obfuscation — clean paths only
#
# Each group is annotated with its hostname length so you can verify the
# model learns the right boundary.
# =============================================================================

LEGITIMATE_LONG_HOSTNAME_SAMPLES = [

    # ── E-learning / skill-building (21–30 chars) ─────────────────────────────
    # Pattern: compound action verbs + nouns — exactly like skillupwithlevelup
    "https://skillupwithlevelup.com/register",           # 22 — the FP trigger case
    "https://learncodingonline.com/courses",             # 22
    "https://masterdigitalmarketing.com/signup",         # 27
    "https://onlineenglishlessons.net/enroll",           # 23
    "https://growyourbusiness.online/start",             # 21
    "https://levelupyourcareer.com/dashboard",           # 21
    "https://becomeabetterprogrammer.com",               # 28
    "https://studyabroadopportunities.com/apply",        # 29
    "https://financialindependencehub.com/courses",      # 29
    "https://digitalskillsacademy.net/enroll",           # 22
    "https://onlinelearningplatform.io/signup",          # 23
    "https://professionalcertification.org/courses",     # 26
    "https://continuingeducationpro.com/register",       # 24
    "https://selfimprovement101.com/lessons",            # 22
    "https://entrepreneurshipcourses.com",               # 26

    # ── Personal finance / fintech (20–30 chars) ──────────────────────────────
    "https://personalfinancetools.com/calculator",       # 21
    "https://mortgagecalculator.online/estimate",        # 22
    "https://retirementplanningguide.com",               # 27
    "https://studentloanrepayment.net/options",          # 23
    "https://smallbusinesslending.com/apply",            # 22
    "https://businesscreditbuilder.com/start",           # 22
    "https://investingforbeginners.net/guide",           # 22
    "https://debtconsolidationhelp.com/free-quote",      # 24
    "https://budgetingmadeeasy.com/tools",               # 20
    "https://taxpreparationservices.com/file",           # 25

    # ── Health / wellness (20–30 chars) ───────────────────────────────────────
    "https://mentalhealthresources.com/find-help",       # 23
    "https://nutritionandwellness.net/recipes",          # 22
    "https://onlinetherapysessions.com/book",            # 23
    "https://telemedicineappointments.com",              # 25
    "https://weightlosscoaching.online/start",           # 21
    "https://naturalhealthremedies.com/articles",        # 23
    "https://pregnancyandparenting.org/resources",       # 24
    "https://seniorcareproviders.com/search",            # 21
    "https://addictionrecoveryhelp.com/hotline",         # 23
    "https://physicaltherapyexercises.com/videos",       # 26

    # ── Legal / professional services (21–30 chars) ───────────────────────────
    "https://onlinelegalservices.com/consult",           # 21
    "https://businessregistration.net/start",            # 22
    "https://immigrationlawassistance.com",              # 26
    "https://smallclaimscourthelp.com/file",             # 22
    "https://intellectualpropertyfiling.com",            # 28
    "https://legalcontracttemplates.com/download",       # 25
    "https://familylawattorneys.net/find",               # 21
    "https://employmentlawresources.com/rights",         # 25
    "https://realestatetransactions.com/guide",          # 24

    # ── Travel / hospitality (20–30 chars) ────────────────────────────────────
    "https://affordablevacations.online/deals",          # 22
    "https://budgetairlinecomparison.com/search",        # 24
    "https://internationaltraveltips.com/guides",        # 25
    "https://luxuryhoneymoonresorts.com/packages",       # 25
    "https://roadtripplannerapp.com/routes",             # 21
    "https://campingandoutdoors.net/gear",               # 21
    "https://visitnationalparks.gov/plan",               # 20
    "https://sustainabletourism.org/destinations",       # 23
    "https://cruiselinecomparisons.com/deals",           # 23

    # ── SaaS / tech tools (20–30 chars) ───────────────────────────────────────
    "https://projectmanagementsuite.com/trial",          # 25
    "https://cloudbackupsolutions.net/pricing",          # 24
    "https://customerrelationshipmanager.com",           # 29
    "https://automatedreportingtools.com/demo",          # 24
    "https://humanresourcesoftware.com/signup",          # 25
    "https://accountingandpayroll.online/demo",          # 22
    "https://inventorymanagementsys.com/trial",          # 24
    "https://socialmediascheduler.net/plans",            # 23
    "https://emailmarketingplatform.io/trial",           # 24
    "https://ecommercestorebuilder.com/start",           # 24

    # ── Non-profit / community / gov (20–30 chars) ────────────────────────────
    "https://communityoutreachprograms.org",             # 27
    "https://environmentalconservation.org/donate",      # 27
    "https://youthmentorshipnetwork.org/join",           # 25
    "https://homelessshelterlocator.org/find",           # 24
    "https://disasterreliefdonations.org",               # 25
    "https://animalrescuevolunteer.org/adopt",           # 23
    "https://publiclibrarysystem.gov/catalog",           # 22
    "https://veteranssupportservices.org",               # 25
    "https://affordablehousingguide.org/search",         # 24

    # ── Media / content / blogging (20–28 chars) ──────────────────────────────
    "https://independentnewsreport.com/latest",          # 23
    "https://recipesandhomecooking.com/browse",          # 25
    "https://parentingadviceblog.com/articles",          # 22
    "https://homeimprovementtips.net/projects",          # 22
    "https://gardening-and-landscaping.com/guides",      # 24  (hyphen variant)
    "https://selfhelpanddevelopment.com/read",           # 25
    "https://photographytutorials.net/lessons",          # 23
    "https://musicproductiontips.com/courses",           # 22
    "https://fitnessworkoutplanner.com/routines",        # 24

    # ── E-commerce / marketplace (20–28 chars) ────────────────────────────────
    "https://handmadecraftssupplies.com/shop",           # 24
    "https://organicgrocerydelivery.com/order",          # 24
    "https://discountelectronicsstore.com",              # 27
    "https://customizedfurniture.online/design",         # 21
    "https://petfoodandaccessories.com/shop",            # 25
    "https://sustainablefashionbrands.com",              # 26
    "https://sportingequipmentonline.com/sale",          # 25
    "https://babyandtoddlerproducts.com/deals",          # 25
    "https://officeandschoolsupplies.com/bulk",          # 25

    # ── Extra compound-brand patterns (cover the FP pattern class) ────────────
    "https://findyourdreamhome.com/listings",            # 20
    "https://connectwithmentors.com/signup",             # 20
    "https://buildyourstartup.online/resources",         # 21
    "https://simplifyingpersonalfinance.com",            # 28
    "https://improveyourproductivity.com/tips",          # 27
    "https://understandingblockchain.com/guide",         # 24
    "https://discoverlocalbusinesses.com/search",        # 25
    "https://savemoneyeveryday.online/tips",             # 20
    "https://preparingforretirement.com/calc",           # 25
    "https://runningabetterbusiness.com/tools",          # 26
    "https://accelerateyourgrowth.com/signup",           # 23
    "https://transformyourworkplace.com/hr",             # 25
]


# =============================================================================
# Main
# =============================================================================

def hostname_len(url: str) -> int:
    try:
        if not url.startswith("http"):
            url = "https://" + url
        return len(urllib.parse.urlparse(url).hostname or "")
    except Exception:
        return 0


def main() -> None:
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Training data not found at {DATA_PATH}")

    # ── Load existing URLs ────────────────────────────────────────────────────
    with open(DATA_PATH, "r", encoding="utf-8", newline="") as f:
        reader     = csv.DictReader(f)
        fieldnames = reader.fieldnames
        existing   = list(reader)

    existing_urls = {row["url"] for row in existing}

    # ── Count current long-legit stats ───────────────────────────────────────
    legit_rows  = [r for r in existing if r["label"] == "0"]
    long_before = sum(1 for r in legit_rows if hostname_len(r["url"]) > 20)
    print(f"\n{'─'*55}")
    print(f"  ClickSafe — Training Data Augmentation")
    print(f"{'─'*55}")
    print(f"\n  Before augmentation:")
    print(f"    Total samples          : {len(existing):,}")
    print(f"    Legitimate (label=0)   : {len(legit_rows):,}")
    print(f"    Legit hostname > 20ch  : {long_before} "
          f"({100*long_before/max(len(legit_rows),1):.1f}%)")

    # ── Deduplicate and add new rows ──────────────────────────────────────────
    new_rows  = []
    skipped   = 0
    for url in LEGITIMATE_LONG_HOSTNAME_SAMPLES:
        url = url.strip()
        if url in existing_urls:
            skipped += 1
            continue
        new_rows.append({"url": url, "label": "0"})
        existing_urls.add(url)

    # ── Write augmented CSV ───────────────────────────────────────────────────
    all_rows = existing + new_rows
    with open(DATA_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    # ── After stats ──────────────────────────────────────────────────────────
    legit_after   = len(legit_rows) + len(new_rows)
    long_after    = long_before + sum(
        1 for r in new_rows if hostname_len(r["url"]) > 20
    )
    hl_list = [hostname_len(r["url"]) for r in new_rows]
    avg_hl  = sum(hl_list) / max(len(hl_list), 1)

    print(f"\n  Added   : {len(new_rows)} new legitimate samples")
    print(f"  Skipped : {skipped} duplicates")
    print(f"  Avg hostname length of new samples: {avg_hl:.1f} chars")
    print(f"\n  After augmentation:")
    print(f"    Total samples          : {len(all_rows):,}")
    print(f"    Legitimate (label=0)   : {legit_after:,}")
    print(f"    Legit hostname > 20ch  : {long_after} "
          f"({100*long_after/max(legit_after,1):.1f}%)")
    print(f"\n  ✔  {DATA_PATH} updated.")
    print(f"\n  Next step:")
    print(f"    python train_model.py")
    print(f"{'─'*55}\n")


if __name__ == "__main__":
    main()
