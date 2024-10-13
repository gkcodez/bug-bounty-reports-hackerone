from log import logger
from report import report_fetcher,  report_writer


if __name__ == '__main__':
    report_fetcher.fetch_report_links()
    report_fetcher.fetch_additional_report_details()
    reports = report_fetcher.read_reports()
    logger.info(f"Number of reports: {len(reports)}")
    valid_reports = [report for report in reports if report.get("title")]
    logger.info(f"Number of valid reports: {len(valid_reports)}")
    logger.info(f"Number of invalid reports: {len(reports) - len(valid_reports)}")
    if len(valid_reports):
        report_writer.add_recent_reports(valid_reports)
        report_writer.add_top_reports(valid_reports)
        report_writer.add_reports_by_vulnerability(valid_reports)
        report_writer.add_reports_by_severity(valid_reports)
        report_writer.add_reports_by_asset_type(valid_reports)
        report_writer.add_reports_by_program(valid_reports)
        report_writer.write_results()
    else:
        logger.info("No reports found")
