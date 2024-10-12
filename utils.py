import json
import os

from log import logger


def read_from_json(filename) -> dict:
    if not os.path.exists(filename):
        with open(filename, 'w') as outfile:
            json.dump({}, outfile)
    with open(filename, "r") as outfile:
        report_data = json.load(outfile)
    logger.info("Read json successful")
    return report_data


def write_to_json(filename, report_data):
    with open(filename, "w") as outfile:
        json.dump(report_data, outfile)
    logger.info("Write to json successful")


def get_project_root_dir():
    return os.path.dirname(os.path.abspath(__file__))
