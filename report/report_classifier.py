import re
from pathlib import Path

from log import logger


def classify_top_100_reports_with_highest_upvotes(reports: list):
    filepath = Path("../results", "top", "top_upvotes.md")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write("## Top 100 reports with highest upvotes from HackerOne:\n\n")
        sorted_reports = list(reversed(sorted(reports, key=lambda k: k['upvotes'])))
        for i, report in enumerate(sorted_reports):
            report_entry = (f"{i + 1}. [{report.get("title")}]({report.get("url")}) | "
                            f"{report.get("upvotes")} upvotes | ${report.get("bounty")} bounty\n\n")
            file.write(report_entry)
    logger.info("Top 100 reports with highest upvotes updated")


def classify_top_100_reports_with_highest_bounty(reports: list):
    filepath = Path("../results", "top", "top_bounties.md")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write("## Top 100 reports with highest bounty from HackerOne:\n\n")
        sorted_reports = list(reversed(sorted(reports, key=lambda k: k['bounty'])))
        top100_sorted_reports = sorted_reports[:100]
        for i, report in enumerate(top100_sorted_reports):
            report_entry = (f"{i + 1}. [{report.get("title")}]({report.get("url")}) | "
                            f"${report.get("bounty")} bounty\n\n")
            file.write(report_entry)
    logger.info("Top 100 reports with highest bounties updated")


def classify_reports_by_vulnerability_type(reports: list, vulnerability_type: str):
    if not vulnerability_type:
        return None
    formatted_vulnerability_type = _format_text(vulnerability_type)
    formatted_file_name = formatted_vulnerability_type.replace(" ", "_")
    filepath = Path("../results", "based_on_vulnerability_type", f"{formatted_file_name}.md")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_vulnerability_type(
        formatted_vulnerability_type, _format_text(report.get("vulnerability_type")))]
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_vulnerability_type} category from HackerOne:\n\n")
        sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
        for i, report in enumerate(sorted_reports):
            report_entry = (f"{i + 1}. [{report.get("title")}]({report.get("url")}) | "
                            f"${report.get("bounty")} bounty\n\n")
            file.write(report_entry)
    logger.info(f"Reports in '{vulnerability_type}' vulnerability type updated")


def classify_reports_by_severity(reports: list, severity: str):
    if not severity:
        return None
    formatted_severity = _format_text(severity)
    formatted_file_name = formatted_severity.replace(" ", "_")
    filepath = Path("../results", "based_on_severity", f"{formatted_file_name}.md")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_severity(
        formatted_severity, _format_text(report.get("severity")))]
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_severity} severity from HackerOne:\n\n")
        sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
        for i, report in enumerate(sorted_reports):
            report_entry = (f"{i + 1}. [{report.get("title")}]({report.get("url")}) | "
                            f"${report.get("bounty")} bounty\n\n")
            file.write(report_entry)
    logger.info(f"Reports in '{severity}' severity updated")


def classify_reports_by_asset_type(reports: list, asset_type: str):
    if not asset_type:
        return None
    formatted_asset_type = _format_text(asset_type)
    formatted_file_name = formatted_asset_type.replace(" ", "_")
    filepath = Path("../results", "based_on_asset_type", f"{formatted_file_name}.md")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filtered_reports = [report for report in reports if _compare_asset_type(
        formatted_asset_type, _format_text(report.get("asset_type")))]
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"## Reports in {formatted_asset_type} asset type from HackerOne:\n\n")
        sorted_reports = list(reversed(sorted(filtered_reports, key=lambda k: k['bounty'])))
        for i, report in enumerate(sorted_reports):
            report_entry = (f"{i + 1}. [{report.get("title")}]({report.get("url")}) | "
                            f"${report.get("bounty")} bounty\n\n")
            file.write(report_entry)
    logger.info(f"Reports in '{asset_type}' asset type updated")


def _format_text(text: str):
    if not text:
        return None
    pattern = r"[a-zA-Z0-9\s-]+"
    match = re.match(pattern, text)
    if match:
        return match.group(0).strip().lower().replace("-", " ")
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
