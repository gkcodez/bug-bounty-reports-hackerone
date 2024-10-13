from log import logger
from report import report_fetcher,  report_writer


if __name__ == '__main__':
    report_fetcher.fetch_report_links()
    report_fetcher.fetch_additional_report_details()
    reports = report_fetcher.read_reports()
    if len(reports):
        report_writer.add_recent_reports(reports)
        report_writer.add_top_reports(reports)
        report_writer.add_reports_by_vulnerability(reports)
        report_writer.add_reports_by_severity(reports)
        report_writer.add_reports_by_asset_type(reports)
        report_writer.add_reports_by_program(reports)
    else:
        logger.info("No reports found")
