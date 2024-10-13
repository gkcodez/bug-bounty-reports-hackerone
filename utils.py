import json
import os
from pathlib import Path

from log import logger


def create_empty_json_file(filepath):
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as outfile:
        json.dump({}, outfile)


def read_from_json_file(filepath) -> dict:
    if not os.path.exists(filepath):
        create_empty_json_file(filepath)
    with open(filepath, "r") as outfile:
        report_data = json.load(outfile)
    logger.info("Read json successful")
    return report_data


def write_to_json_file(filename, report_data):
    with open(filename, "w") as outfile:
        json.dump(report_data, outfile)
    logger.info("Write to json successful")


def get_project_root_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_filename_from_filepath(filepath: Path):
    directory_name, filename = os.path.split(filepath)
    return filename
