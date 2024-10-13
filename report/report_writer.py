from report import report_classifier
from utils import get_filename_from_filepath

read_me_entries = []


def add_recent_reports(reports):
    read_me_entries.append("\n## Recent reports:")
    read_me_entries.append("| S.No | Title |")
    read_me_entries.append("| ---- | ----- |")
    filepath = report_classifier.classify_recently_disclosed_reports(reports, 90)
    filename = _get_formatted_filename(filepath)
    report_entry = f"| 1 | [{filename}]({str(filepath).replace("\\", "/")}) |"
    read_me_entries.append(report_entry)


def add_top_reports(reports):
    read_me_entries.append("\n## Top reports:")
    read_me_entries.append("| S.No | Title |")
    read_me_entries.append("| ---- | ----- |")
    filepath = report_classifier.classify_top_100_reports_with_highest_upvotes(reports)
    filename = _get_formatted_filename(filepath)
    report_entry = f"| 1 | [{filename}]({str(filepath).replace("\\", "/")}) |"
    read_me_entries.append(report_entry)
    filepath = report_classifier.classify_top_100_reports_with_highest_bounty(reports)
    filename = _get_formatted_filename(filepath)
    report_entry = f"| 2 | [{filename}]({str(filepath).replace("\\", "/")}) |"
    read_me_entries.append(report_entry)


def add_reports_by_vulnerability(reports):
    vulnerability_types = sorted({report.get("vulnerability_type") for report in reports
                                  if report.get("vulnerability_type")}, key=lambda s: s.lower())
    if len(vulnerability_types):
        read_me_entries.append("\n## Reports based on vulnerability:")
        read_me_entries.append("| S.No | Title |")
        read_me_entries.append("| ---- | ----- |")
    for i, vulnerability_type in enumerate(vulnerability_types):
        filepath = report_classifier.classify_reports_by_vulnerability_type(reports, vulnerability_type)
        filename = _get_formatted_filename(filepath)
        report_entry = f"| {i + 1} | [{filename}]({str(filepath).replace("\\", "/")}) |"
        read_me_entries.append(report_entry)


def add_reports_by_severity(reports):
    severities = sorted({report.get("severity") for report in reports if report.get("severity")},
                        key=lambda s: s.lower())
    if len(severities):
        read_me_entries.append("\n## Reports based on severity:")
        read_me_entries.append("| S.No | Title |")
        read_me_entries.append("| ---- | ----- |")
    for i, severity in enumerate(severities):
        filepath = report_classifier.classify_reports_by_severity(reports, severity)
        filename = _get_formatted_filename(filepath)
        report_entry = f"| {i + 1} | [{filename}]({str(filepath).replace("\\", "/")}) |"
        read_me_entries.append(report_entry)


def add_reports_by_asset_type(reports):
    asset_types = sorted({report.get("asset_type") for report in reports if report.get("asset_type")},
                         key=lambda s: s.lower())
    if len(asset_types):
        read_me_entries.append("\n## Reports based on asset type:")
        read_me_entries.append("| S.No | Title |")
        read_me_entries.append("| ---- | ----- |")
    for i, asset_type in enumerate(asset_types):
        filepath = report_classifier.classify_reports_by_asset_type(reports, asset_type)
        filename = _get_formatted_filename(filepath)
        report_entry = f"| {i + 1} | [{filename}]({str(filepath).replace("\\", "/")}) |"
        read_me_entries.append(report_entry)


def add_reports_by_program(reports):
    programs = sorted({report.get("program") for report in reports if report.get("program")},
                      key=lambda s: s.lower())
    if len(programs):
        read_me_entries.append("\n## Reports based on program:")
        read_me_entries.append("| S.No | Title |")
        read_me_entries.append("| ---- | ----- |")
    for i, program in enumerate(programs):
        filepath = report_classifier.classify_reports_by_program(reports, program)
        filename = _get_formatted_filename(filepath)
        report_entry = f"| {i + 1} | [{filename}]({str(filepath).replace("\\", "/")}) |"
        read_me_entries.append(report_entry)


def get_results():
    return read_me_entries


def write_results_to_file():
    with open("README.md", 'w', encoding='utf-8') as file:
        file.write("\n".join(read_me_entries))


def _get_formatted_filename(path):
    raw_filename = get_filename_from_filepath(path)
    raw_filename_without_extension = raw_filename.split(".")[0]
    formatted_filename = raw_filename_without_extension.replace("_", " ").capitalize()
    return formatted_filename

