from __future__ import annotations

import csv
import random
import re
from pathlib import Path
from typing import Dict, List


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

# Dataset will be saved beside this Python file.
OUTPUT_PATH = Path(__file__).resolve().parent / "phishing_email_dataset.csv"

# Fixed seed makes the dataset reproducible.
SEED = 42

# The project prompt requires 500+ records.
TOTAL_RECORDS = 600

# Keep the dataset balanced for the initial project version.
PHISHING_RATIO = 0.50


# ============================================================
# SAFE SYNTHETIC / RESERVED DOMAINS
# ============================================================

# These are documentation/example domains intended for safe use.
LEGITIMATE_DOMAINS = [
    "example.org",
    "example.com",
    "example.net",
    "invalid.test",
]

# Synthetic phishing-style subdomains under safe example domains.
# They are fictional and do not represent real organizations.
PHISHING_DOMAINS = [
    "account-check.example.com",
    "secure-verify.example.org",
    "billing-alert.example.net",
    "hr-confirm.invalid.test",
    "delivery-notice.example.com",
    "executive-request.example.org",
]


# ============================================================
# SYNTHETIC NAMES
# ============================================================

FIRST_NAMES = [
    "Aarav",
    "Riya",
    "Ananya",
    "Kabir",
    "Meera",
    "Rahul",
    "Neha",
    "Vikram",
    "Priya",
    "Arjun",
]


# ============================================================
# LEGITIMATE EMAIL TEMPLATES
# ============================================================

LEGITIMATE_TEMPLATES: List[Dict[str, str]] = [
    {
        "category": "university_notice",
        "sender_local": "notices",
        "subject": "University Notice: Updated Seminar Schedule",
        "body": (
            "Hello {name},\n\n"
            "This is a routine notice about the updated seminar schedule. "
            "The revised timetable is available through the university's "
            "normal portal. No action is required by email.\n\n"
            "Regards,\n"
            "Academic Coordination Team"
        ),
        "url": "https://portal.example.org/seminars",
        "attachment": "",
    },
    {
        "category": "hr_update",
        "sender_local": "hr",
        "subject": "HR Update: Monthly Policy Reminder",
        "body": (
            "Hello {name},\n\n"
            "This monthly message contains a reminder about workplace policies "
            "and upcoming internal activities. Please review the information "
            "during your normal working schedule.\n\n"
            "Regards,\n"
            "Human Resources Team"
        ),
        "url": "https://hr.example.com/policies",
        "attachment": "monthly-policy.pdf",
    },
    {
        "category": "project_update",
        "sender_local": "project-team",
        "subject": "Project Update: Sprint Review Notes",
        "body": (
            "Hi {name},\n\n"
            "The sprint review notes have been posted to the shared project "
            "workspace. Please review the action items before the next team meeting.\n\n"
            "Thanks,\n"
            "Project Team"
        ),
        "url": "https://projects.example.net/workspace/sprint-review",
        "attachment": "",
    },
    {
        "category": "meeting_reminder",
        "sender_local": "calendar",
        "subject": "Meeting Reminder: Team Sync Tomorrow",
        "body": (
            "Hello {name},\n\n"
            "This is a reminder for the scheduled team sync tomorrow. "
            "Please join through the meeting details already provided in "
            "the calendar invitation.\n\n"
            "Regards,\n"
            "Coordination Desk"
        ),
        "url": "https://calendar.example.org/meeting/team-sync",
        "attachment": "",
    },
    {
        "category": "shopping_confirmation",
        "sender_local": "orders",
        "subject": "Shopping Confirmation: Order Summary",
        "body": (
            "Hello {name},\n\n"
            "Your sample order confirmation is available in your normal account "
            "area. The message is informational and does not request your "
            "password or payment credentials.\n\n"
            "Regards,\n"
            "Order Support"
        ),
        "url": "https://shop.example.com/orders/history",
        "attachment": "order-summary.pdf",
    },
    {
        "category": "newsletter",
        "sender_local": "newsletter",
        "subject": "Monthly Newsletter: Security and Technology",
        "body": (
            "Hello {name},\n\n"
            "Here is the monthly newsletter with articles and educational updates. "
            "You can read it when convenient. No immediate action is required.\n\n"
            "Regards,\n"
            "Newsletter Team"
        ),
        "url": "https://news.example.net/monthly",
        "attachment": "",
    },
    {
        "category": "password_change_confirmation",
        "sender_local": "account",
        "subject": "Password Change Confirmation",
        "body": (
            "Hello {name},\n\n"
            "This message confirms that a password change was recorded in your "
            "account. If you made this change, no further action is required. "
            "Use the normal account support channel if you do not recognize "
            "the activity.\n\n"
            "Regards,\n"
            "Account Services"
        ),
        "url": "https://account.example.org/security",
        "attachment": "",
    },
    {
        "category": "fictional_bank_notification",
        "sender_local": "notifications",
        "subject": "DemoBank Notification: Statement Ready",
        "body": (
            "Hello {name},\n\n"
            "Your monthly statement is available through the regular DemoBank "
            "portal. This notification does not request your password, one-time "
            "code, or card number.\n\n"
            "Regards,\n"
            "DemoBank Notifications"
        ),
        "url": "https://bank.example.com/statements",
        "attachment": "statement.pdf",
    },
]


# ============================================================
# SYNTHETIC PHISHING EMAIL TEMPLATES
# ============================================================

PHISHING_TEMPLATES: List[Dict[str, str]] = [
    {
        "category": "fake_account_verification",
        "sender_local": "security-alert",
        "subject": "URGENT: Verify Your Account Immediately",
        "body": (
            "Dear {name},\n\n"
            "Your account will be suspended unless you verify your password "
            "immediately. Confirm your login details now to prevent interruption. "
            "Failure to respond today may result in account restrictions.\n\n"
            "Security Notification"
        ),
        "url": "http://198.51.100.10/verify-account",
        "attachment": "",
    },
    {
        "category": "fake_invoice",
        "sender_local": "billing-review",
        "subject": "URGENT: Invoice Payment Required Today",
        "body": (
            "Hello {name},\n\n"
            "An outstanding invoice requires immediate payment. Review the invoice "
            "now and confirm your billing information to avoid a service penalty. "
            "Please act today.\n\n"
            "Billing Desk"
        ),
        "url": "http://billing-alert.example.net/invoice/confirm-payment",
        "attachment": "invoice.pdf.exe",
    },
    {
        "category": "fake_prize",
        "sender_local": "reward-center",
        "subject": "Congratulations! You Have Won a Reward",
        "body": (
            "Dear Customer,\n\n"
            "You have won a special reward in our promotional program. Confirm "
            "your personal details and payment information to claim the prize. "
            "The claim window closes soon.\n\n"
            "Reward Center"
        ),
        "url": "https://secure-verify.example.org/prize/claim",
        "attachment": "",
    },
    {
        "category": "fake_password_expiration",
        "sender_local": "password-alert",
        "subject": "Action Required: Password Expires Today",
        "body": (
            "Hello {name},\n\n"
            "Your password expires today. Act now and verify your current password "
            "to keep your account active. Failure to respond may suspend access.\n\n"
            "Account Security Team"
        ),
        "url": "http://account-check.example.com/password/reset-now",
        "attachment": "",
    },
    {
        "category": "fake_delivery",
        "sender_local": "delivery-update",
        "subject": "Delivery Notice: Confirm Details to Receive Package",
        "body": (
            "Dear Customer,\n\n"
            "Your package is waiting for confirmation. Confirm your address and "
            "personal information immediately to prevent return of the shipment. "
            "A small payment may be required.\n\n"
            "Delivery Services"
        ),
        "url": "https://delivery-notice.example.com/package/confirm",
        "attachment": "delivery-details.zip",
    },
    {
        "category": "fake_hr_request",
        "sender_local": "hr-confirm",
        "subject": "Urgent HR Verification Required",
        "body": (
            "Hello {name},\n\n"
            "Human Resources needs your identity and payroll information today. "
            "Reply with your personal details and account information so your "
            "records are not delayed. This request is time-sensitive.\n\n"
            "HR Administration"
        ),
        "url": "https://hr-confirm.invalid.test/employee/verify",
        "attachment": "employee-form.js",
    },
    {
        "category": "fake_executive_request",
        "sender_local": "executive-request",
        "subject": "Private Request: Immediate Action Needed",
        "body": (
            "Hello {name},\n\n"
            "I need you to complete an urgent financial request today. Please "
            "confirm payment details and personal information as soon as possible. "
            "Keep this request confidential until the task is completed.\n\n"
            "Executive Office"
        ),
        "url": "https://account-check.example.com/request/payment",
        "attachment": "",
    },
]


# ============================================================
# HARMLESS TEXT VARIATIONS
# ============================================================

LEGITIMATE_VARIANTS = [
    " Please review this information during normal business hours.",
    " No immediate response is required.",
    " This is an informational message for your records.",
    " Please use the organization's normal portal for any account activity.",
]

PHISHING_VARIANTS = [
    " Act immediately to avoid interruption.",
    " Do not delay this request.",
    " Your access may be restricted if you do not respond.",
    " Confirm the requested information before the deadline.",
]


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def extract_domain(sender: str) -> str:
    """
    Extract the domain portion from an email sender string.

    Example:
        notices1@example.org
        -> example.org
    """

    match = re.search(
        r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9.-]+)",
        sender,
    )

    if match:
        return match.group(1).lower()

    return ""


def build_sender(
    template: Dict[str, str],
    label: str,
    index: int,
) -> str:
    """
    Build a synthetic sender address.
    """

    if label == "LEGITIMATE":
        domain = LEGITIMATE_DOMAINS[index % len(LEGITIMATE_DOMAINS)]
    else:
        domain = PHISHING_DOMAINS[index % len(PHISHING_DOMAINS)]

    return f"{template['sender_local']}{index + 1}@{domain}"


def generate_record(
    email_id: str,
    label: str,
    template: Dict[str, str],
    index: int,
    rng: random.Random,
) -> Dict[str, str]:
    """
    Create one synthetic email record.
    """

    name = rng.choice(FIRST_NAMES)

    # Personalize the message with a synthetic first name.
    body = template["body"].format(name=name)

    # Add harmless variation.
    if label == "LEGITIMATE":
        body += rng.choice(LEGITIMATE_VARIANTS)
    else:
        body += rng.choice(PHISHING_VARIANTS)

    sender = build_sender(
        template=template,
        label=label,
        index=index,
    )

    subject = template["subject"]

    # Small synthetic variation in some subjects.
    if index % 9 == 0:
        subject += "!"

    # Add a harmless synthetic reference ID to some messages.
    if index % 11 == 0:
        body += "\n\nReference ID: DEMO-" + f"{index + 1:04d}"

    url = template["url"]

    # Some legitimate samples contain two URLs.
    if index % 17 == 0 and label == "LEGITIMATE":
        urls = (
            f"{url};"
            "https://help.example.org/security"
        )

    # Some phishing samples contain an additional fictional short-style path.
    elif index % 13 == 0 and label == "PHISHING":
        urls = (
            f"{url};"
            f"http://short.example.net/x{index + 1:04d}"
        )

    else:
        urls = url

    attachment = template["attachment"]

    return {
        "email_id": email_id,
        "sender": sender,
        "sender_domain": extract_domain(sender),
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachment_name": attachment,
        "label": label,
    }


# ============================================================
# DATASET GENERATION
# ============================================================

def generate_dataset(
    total_records: int = TOTAL_RECORDS,
    seed: int = SEED,
) -> List[Dict[str, str]]:
    """
    Generate the complete synthetic dataset.
    """

    if total_records < 500:
        raise ValueError(
            "The project requires at least 500 synthetic records."
        )

    rng = random.Random(seed)

    # 50% phishing and 50% legitimate.
    phishing_count = int(
        total_records * PHISHING_RATIO
    )

    legitimate_count = (
        total_records - phishing_count
    )

    records: List[Dict[str, str]] = []

    # --------------------------------------------------------
    # Generate legitimate records
    # --------------------------------------------------------

    for i in range(legitimate_count):
        template = LEGITIMATE_TEMPLATES[
            i % len(LEGITIMATE_TEMPLATES)
        ]

        records.append(
            generate_record(
                email_id=f"LEG-{i + 1:04d}",
                label="LEGITIMATE",
                template=template,
                index=i,
                rng=rng,
            )
        )

    # --------------------------------------------------------
    # Generate phishing records
    # --------------------------------------------------------

    for i in range(phishing_count):
        template = PHISHING_TEMPLATES[
            i % len(PHISHING_TEMPLATES)
        ]

        records.append(
            generate_record(
                email_id=f"PHI-{i + 1:04d}",
                label="PHISHING",
                template=template,
                index=i,
                rng=rng,
            )
        )

    # Shuffle so legitimate and phishing rows are mixed.
    rng.shuffle(records)

    return records


# ============================================================
# SAVE CSV
# ============================================================

def save_dataset(
    records: List[Dict[str, str]],
    output_path: Path = OUTPUT_PATH,
) -> None:
    """
    Save generated records to CSV.
    """

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "email_id",
        "sender",
        "sender_domain",
        "subject",
        "body",
        "urls",
        "attachment_name",
        "label",
    ]

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)


# ============================================================
# DATASET VALIDATION / SUMMARY
# ============================================================

def validate_dataset(
    records: List[Dict[str, str]],
) -> None:
    """
    Validate important dataset requirements.
    """

    required_columns = {
        "email_id",
        "sender",
        "sender_domain",
        "subject",
        "body",
        "urls",
        "attachment_name",
        "label",
    }

    if not records:
        raise ValueError(
            "Dataset generation returned zero records."
        )

    # Check required columns.
    actual_columns = set(records[0].keys())

    missing_columns = (
        required_columns - actual_columns
    )

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    # Check record count.
    if len(records) < 500:
        raise ValueError(
            f"Dataset contains only {len(records)} records."
        )

    # Check labels.
    labels = {
        record["label"]
        for record in records
    }

    expected_labels = {
        "LEGITIMATE",
        "PHISHING",
    }

    if labels != expected_labels:
        raise ValueError(
            f"Unexpected labels found: {sorted(labels)}"
        )

    # Check that every sender has a domain.
    invalid_domains = [
        record["email_id"]
        for record in records
        if not record["sender_domain"]
    ]

    if invalid_domains:
        raise ValueError(
            "Some records have invalid sender domains: "
            f"{invalid_domains[:5]}"
        )


def print_dataset_summary(
    records: List[Dict[str, str]],
    output_path: Path,
) -> None:
    """
    Print useful dataset statistics.
    """

    legitimate = sum(
        1
        for record in records
        if record["label"] == "LEGITIMATE"
    )

    phishing = sum(
        1
        for record in records
        if record["label"] == "PHISHING"
    )

    with_attachments = sum(
        bool(record["attachment_name"])
        for record in records
    )

    with_urls = sum(
        bool(record["urls"])
        for record in records
    )

    print()
    print("=" * 65)
    print("SYNTHETIC PHISHING EMAIL DATASET GENERATED")
    print("=" * 65)

    print(f"Output file       : {output_path}")
    print(f"Total records     : {len(records)}")
    print(f"LEGITIMATE        : {legitimate}")
    print(f"PHISHING          : {phishing}")
    print(f"Records with URLs : {with_urls}")
    print(f"With attachments  : {with_attachments}")

    print()
    print("Columns:")
    print("  email_id")
    print("  sender")
    print("  sender_domain")
    print("  subject")
    print("  body")
    print("  urls")
    print("  attachment_name")
    print("  label")

    print("=" * 65)

    print()
    print("FIRST 3 GENERATED RECORDS")
    print("=" * 65)

    for record in records[:3]:
        print()
        print(
            f"{record['email_id']} | {record['label']}"
        )
        print(
            f"Sender : {record['sender']}"
        )
        print(
            f"Subject: {record['subject']}"
        )
        print(
            f"URLs   : {record['urls']}"
        )
        print(
            f"Attach : {record['attachment_name']}"
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main() -> None:
    """
    Main execution function.
    """

    print(
        "Generating synthetic phishing email dataset..."
    )

    records = generate_dataset()

    validate_dataset(records)

    save_dataset(records)

    print_dataset_summary(
        records,
        OUTPUT_PATH,
    )

    print()
    print(
        "Dataset generation completed successfully."
    )


if __name__ == "__main__":
    main()