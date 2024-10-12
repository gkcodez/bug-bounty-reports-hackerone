import re
from pathlib import Path

from log import logger
from utils import get_project_root_dir

PROJECT_ROOT_DIR = get_project_root_dir()


def classify_top_100_reports_with_highest_upvotes(reports: list):
    relative_path = Path("results", "top", "top_upvotes.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_reports = list(reversed(sorted(reports, key=lambda k: k['upvotes'])))
    top100_sorted_reports = sorted_reports[:100]
    report_entries = []
    for i, report in enumerate(top100_sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        upvotes = report.get("upvotes")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty | ${upvotes} upvotes"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write("## Top 100 reports with highest upvotes from HackerOne:\n")
        file.write("\n".join(report_entries))
    logger.info("Top 100 reports with highest upvotes updated")
    return relative_path


def classify_top_100_reports_with_highest_bounty(reports: list):
    relative_path = Path("results", "top", "top_bounties.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_reports = list(reversed(sorted(reports, key=lambda k: k['bounty'])))
    top100_sorted_reports = sorted_reports[:100]
    report_entries = []
    for i, report in enumerate(top100_sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write("## Top 100 reports with highest bounty from HackerOne:\n")
        file.write("\n".join(report_entries))
    logger.info("Top 100 reports with highest bounties updated")
    return relative_path


def classify_reports_by_vulnerability_type(reports: list, vulnerability_type: str):
    formatted_vulnerability_type = _format_text(vulnerability_type)
    formatted_file_name = formatted_vulnerability_type.replace(" ", "_")
    relative_path = Path("results", "based_on_vulnerability_type", f"{formatted_file_name}.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_vulnerability_type(
        formatted_vulnerability_type, _format_text(report.get("vulnerability_type")))]
    sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
    report_entries = []
    for i, report in enumerate(sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_vulnerability_type} category from HackerOne:\n")
        file.write("\n".join(report_entries))
    logger.info(f"Reports in '{vulnerability_type}' vulnerability type updated")
    return relative_path


def classify_reports_by_severity(reports: list, severity: str):
    formatted_severity = _format_text(severity)
    formatted_file_name = formatted_severity.replace(" ", "_")
    relative_path = Path("results", "based_on_severity", f"{formatted_file_name}.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_severity(
        formatted_severity, _format_text(report.get("severity")))]
    sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
    report_entries = []
    for i, report in enumerate(sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_severity} severity from HackerOne:\n")
        file.write("\n".join(report_entries))
    logger.info(f"Reports in '{severity}' severity updated")
    return relative_path


def classify_reports_by_asset_type(reports: list, asset_type: str):
    formatted_asset_type = _format_text(asset_type)
    formatted_file_name = formatted_asset_type.replace(" ", "_")
    relative_path = Path("results", "based_on_asset_type", f"{formatted_file_name}.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_asset_type(
        formatted_asset_type, _format_text(report.get("asset_type")))]
    sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
    report_entries = []
    for i, report in enumerate(sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write(f"\n## Reports in {formatted_asset_type} asset type from HackerOne:")
        file.write("\n".join(report_entries))
    logger.info(f"Reports in '{asset_type}' asset type updated")
    return relative_path


def classify_reports_by_program(reports: list, program: str):
    formatted_program = _format_text(program)
    formatted_file_name = formatted_program.replace(" ", "_")
    relative_path = Path("results", "based_on_program", f"{formatted_file_name}.md")
    absolute_path = Path(PROJECT_ROOT_DIR, relative_path)
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_program(
        formatted_program, _format_text(report.get("program")))]
    sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
    report_entries = []
    for i, report in enumerate(sorted_reports):
        title = report.get("title")
        url = report.get("url")
        bounty = report.get("bounty")
        report_entry = f"{i + 1}. [{title}]({url}) | ${bounty} bounty"
        report_entries.append(report_entry)
    with open(absolute_path, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_program} program from HackerOne:\n")
        file.write("\n".join(report_entries))
    logger.info(f"Reports in '{program}' program updated")
    return relative_path


def _format_text(text: str):
    if not text:
        return None
    # Match text with letters, numbers, whitespaces, hyphen and parentheses
    pattern = r"[a-zA-Z0-9\s\-\(\)]+"
    match = re.match(pattern, text)
    if match:
        formatted_text = match.group(0).strip().lower()
        # Allow letters and numbers only for filename.
        formatted_text = re.sub(r"[^a-zA-Z0-9]", " ", formatted_text)
        # Removing multiple spaces
        formatted_text = re.sub(r"\s+", " ", formatted_text).strip()
        return formatted_text
    return None


def _compare_vulnerability_type(expected_vulnerability_type, actual_vulnerability_type: str):
    if not expected_vulnerability_type or not actual_vulnerability_type:
        return False
    return expected_vulnerability_type.lower() == actual_vulnerability_type.lower()


def _compare_severity(expected_severity, actual_severity: str):
    if not expected_severity or not actual_severity:
        return False
    return expected_severity.lower() == actual_severity.lower()


def _compare_asset_type(expected_asset_type, actual_asset_type: str):
    if not expected_asset_type or not actual_asset_type:
        return False
    return expected_asset_type.lower() == actual_asset_type.lower()


def _compare_program(expected_program, actual_program: str):
    if not expected_program or not actual_program:
        return False
    return expected_program.lower() == actual_program.lower()