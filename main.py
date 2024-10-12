from report import report_fetcher, report_classifier

if __name__ == '__main__':
    # report_fetcher.fetch_report_links()
    # report_fetcher.fetch_additional_report_details()
    reports = report_fetcher.get_reports()

    report_classifier.classify_top_100_reports_with_highest_upvotes(reports)
    report_classifier.classify_top_100_reports_with_highest_bounty(reports)

    vulnerability_types = {report.get("vulnerability_type") for report in reports}
    for vulnerability_type in vulnerability_types:
        report_classifier.classify_reports_by_vulnerability_type(reports, vulnerability_type)

    severities = {report.get("severity") for report in reports}
    for severity in severities:
        report_classifier.classify_reports_by_severity(reports, severity)

    asset_types = {report.get("asset_type") for report in reports}
    for asset_type in asset_types:
        report_classifier.classify_reports_by_asset_type(reports, asset_type)
