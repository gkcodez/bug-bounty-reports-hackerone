import time
import requests
from selenium.webdriver import Edge, EdgeOptions
from selenium.webdriver.common.by import By
from urllib.parse import urljoin

from log import logger

from utils import read_from_json, write_to_json
from models.report import Report

hackerone_base_url = "https://hackerone.com"


def get_current_url(page_index):
    query_string = f"disclosed=true&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageIndex={page_index}"
    hacktivity_path = f"hacktivity/overview?queryString={query_string}"
    hacktivity_url = urljoin(hackerone_base_url, hacktivity_path)
    return hacktivity_url


def fetch_report_links():
    driver = None
    try:
        logger.info("Fetching report links started")
        fetch_report_start_time = time.time()
        options = EdgeOptions()
        options.add_argument('no-sandbox')
        options.add_argument('headless')
        driver = Edge(options=options)
        # Wait with timeout of 10 seconds.
        driver.implicitly_wait(10)
        new_report_list = []
        page_size = 25
        report_data = read_from_json("reports.json")
        existing_report_list = report_data.get("reports") if report_data.get("reports") else []
        latest_report = existing_report_list[0] if len(existing_report_list) > 0 else None
        current_page_count = 1
        while current_page_count == 1:
            current_page_index = current_page_count - 1
            hacktivity_url = get_current_url(current_page_index)
            driver.get(hacktivity_url)
            current_page_reports = driver.find_elements(
                By.XPATH,
                "//div[@data-testid='report-title']//parent::a"
            )
            report_list_updated = None
            for current_page_report in current_page_reports:
                current_report_object = Report()
                current_report_path = current_page_report.get_attribute("href")
                current_report_url = urljoin(hackerone_base_url, current_report_path)
                current_report_object.url = current_report_url
                report_list_updated = latest_report and current_report_url == latest_report.get("url")
                if report_list_updated:
                    break
                new_report_list.append(vars(current_report_object))
            if report_list_updated:
                logger.info("Reports updated to latest")
                break
            page_element = driver.find_element(
                By.XPATH,
                "//button[@data-testid='hacktivity-previous-button']//parent::div//preceding-sibling::p"
            )
            page_element_text = page_element.text
            page_counts = page_element_text.split("of")
            # current_range = page_counts[0]
            # report_number = current_range.split("-")
            # start_count = int(report_number[0])
            # end_count = int(report_number[1])
            total_report_count = int(page_counts[1])
            total_page_count = total_report_count // page_size
            logger.info(f"Fetching page {current_page_count} of {total_page_count}")
            if current_page_count != total_page_count:
                current_page_count += 1
            else:
                logger.info("Fetching completed.")
                break
        logger.info(f"Existing reports count: {len(existing_report_list)}")
        logger.info(f"New reports count: {len(new_report_list)}")
        report_list = new_report_list + existing_report_list
        logger.info(f"Total reports count: {len(report_list)}")
        # Remove duplicates.
        unique_report_list = []
        for report in report_list:
            if report not in unique_report_list:
                unique_report_list.append(report)
        unique_reports_count = len(unique_report_list)
        logger.info(f"Unique reports count: {unique_reports_count}")
        report_data = {"reports": unique_report_list}
        write_to_json("reports.json", report_data)
        logger.info("Fetch report links successful")
        fetch_report_end_time = time.time()
        duration = fetch_report_end_time - fetch_report_start_time
        logger.info(f"Time taken to fetch report links: {duration} seconds")
    except Exception as e:
        raise Exception(e)
    finally:
        driver.quit()


def fetch_additional_report_details():
    try:
        logger.info("Fetching additional report details started")
        fetch_report_start_time = time.time()
        report_data = read_from_json("reports.json")
        reports = report_data.get("reports") if report_data.get("reports") else []
        reports_count = len(reports)
        # Fetch additional details.
        for i, report in enumerate(reports):
            logger.info(f"Fetching additional report details: {i + 1} out of {reports_count}")
            request_url = f"{report.get("url")}.json"
            report_metadata = requests.get(request_url).json()
            title = report_metadata.get('title')
            team = report_metadata.get('team') if report_metadata.get('team') else {}
            profile = team.get('profile') if team else {}
            program = profile.get('name') if profile else ""
            severity = report_metadata.get('severity_rating')
            state = report_metadata.get('state')
            upvotes = int(report_metadata.get('vote_count')) if report_metadata.get('vote_count') else 0
            scope = report_metadata.get('structured_scope') if report_metadata.get('structured_scope') else {}
            asset_type = scope.get('asset_type') if scope else ""
            vulnerability = report_metadata.get('weakness') if report_metadata.get('weakness') else None
            vulnerability_type = vulnerability.get('name') if vulnerability else ""
            bounty_amount = float(report_metadata.get('bounty_amount')) if report_metadata.get(
                'bounty_amount') else 0.0
            submitted_at = report_metadata.get('submitted_at')
            disclosed_at = report_metadata.get('disclosed_at')
            report['title'] = title
            report['program'] = program
            report['severity'] = severity
            report['state'] = state
            report['upvotes'] = upvotes
            report['asset_type'] = asset_type
            report['bounty'] = bounty_amount
            report['vulnerability_type'] = vulnerability_type
            report['submitted_at'] = submitted_at
            report['disclosed_at'] = disclosed_at
            time.sleep(0.1)
        report_data = {"reports": reports}
        write_to_json("reports.json", report_data)
        logger.info("Fetch additional report details successful")
        fetch_report_end_time = time.time()
        duration = fetch_report_end_time - fetch_report_start_time
        logger.info(f"Time taken to fetch additional report details: {duration} seconds")
    except Exception as e:
        raise Exception(e)


def get_reports():
    reports_json = read_from_json("data\\reports.json")
    reports = reports_json.get("reports")
    return reports
