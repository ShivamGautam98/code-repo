import os
import subprocess
import json
import argparse
import logging
from git import Repo, InvalidGitRepositoryError, NoSuchPathError
import sys
import time
from jsonschema import validate, exceptions as jsonschema_exceptions
from typing import List, Dict, Union, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class SnykScanner:

    def __init__(self, repo_name: str, event: str = 'push'):
        self.scan_time = 0
        snyk_conf_repo = 'scripts'
        self.repo_name = repo_name
        self.config_file_path = os.path.join(snyk_conf_repo, "properties.json")
        self.policy_path = os.path.join(snyk_conf_repo, repo_name, ".snyk")
        self.event = event

        logger.info(f"Initialized SnykScanner with repo: {repo_name}, event: {event}")

        self.validate_configuration_files()

        config = self.load_json(self.config_file_path)
        self.org_id = config.get('org_id')
        self.project_name = config.get('project_name', "")
        self.severity_threshold = config.get("severity_threshold", "medium")  # Available options - low|medium|high|critical

        self.ensure_output_directory()
        self.initialize_scan_file_paths()

    def validate_configuration_files(self) -> None:
        """Validate existence and schema of required configuration files."""
        if not os.path.exists(self.config_file_path):
            logger.warning(f"Repository: {self.repo_name} not configured for Snyk Scan. Skipping Scan!!")
            sys.exit(1)
        
        try:
            with open(self.config_file_path, 'r') as f:
                config = json.load(f)
            self.validate_config_schema(config)
        except jsonschema_exceptions.ValidationError as e:
            logger.error(f"Invalid configuration file: {e}")
            sys.exit(1)
        except FileNotFoundError as e:
            logger.error(f"Configuration file not found at: {self.config_file_path}")
            logger.exception(e)  # Log detailed exception traceback
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}")
            logger.exception(e)  # Log detailed exception traceback
            sys.exit(1)


    def validate_config_schema(self, config: dict) -> None:
        """Validate configuration schema against defined JSON schema."""
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
            "org_id": {"type": "string", "format": "uuid"},
            "project_id": {"type": "string"},
            "project_name": {"type": "string"},
            "severity_threshold": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
            },
            "required": ["org_id", "project_name", "severity_threshold"]
        }
        validate(instance=config, schema=schema)
        logger.info("Configuration file validated successfully.")

    def ensure_output_directory(self) -> None:
        """Ensure the outputs directory exists."""
        if not os.path.exists("outputs"):
            os.mkdir("outputs")

    def initialize_scan_file_paths(self) -> None:
        """Initialize paths for scan result files."""
        self.scan_json_file_path = os.path.join("../outputs", "scan_results.json")
        self.scan_sarif_file_path = os.path.join("../outputs", "scan_results.sarif")
        self.scan_summary_file_path = os.path.join("../outputs", "severity_summary.json")
        self.scan_html_file_path = os.path.join("../outputs", "scan_results.html")

    @staticmethod
    def check_snyk_installed() -> None:
        """Check if Snyk CLI is installed."""
        try:
            result = subprocess.run(['snyk', '--version'], capture_output=True, text=True)
            result.check_returncode()
            logger.info(f"Snyk CLI is installed: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            logger.error("Snyk CLI is not installed. Please install it from https://snyk.io/docs/snyk-cli-installation/")
            raise

    @staticmethod
    def check_snyk_token() -> None:
        """Check if SNYK_TOKEN environment variable is set."""
        if 'SNYK_TOKEN' not in os.environ:
            logger.error("SNYK_TOKEN environment variable not set.")
            raise ValueError("SNYK_TOKEN environment variable not set.")

    def get_current_branch(self) -> Optional[str]:
        """Get the current branch of the repository."""
        try:
            repo = Repo(self.repo_name)
            current_branch = repo.active_branch
            return current_branch.name
        except (InvalidGitRepositoryError, NoSuchPathError, TypeError) as e:
            logger.error(f"Error getting current branch: {e}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return None

    def scan_and_generate_report(self, report: bool) -> None:
        """
        Perform SAST scan and generate reports in JSON and HTML formats.
        :param report: Boolean to indicate if the results should be reported to Snyk Web UI.
        """
        logger.debug("Changing Working directory to: ")
        os.chdir(self.repo_name)
        logger.debug(os.getcwd())

        target = "."
        if self.event == "pr":
            changed_files = self.get_changed_files(self.base_branch, self.pr_branch)
            logger.debug(f"Changed Files: {changed_files}")
            if not changed_files:
                logger.info(f"No changed files, Scan will be skipped")
                return
            target = changed_files

        scan_returncode = 1  # default
        try:
            command = self.construct_sast_scan_command(target, report)
            logger.debug(f"Running Command - {command}")

            start_time = time.time()
            result = subprocess.run(command, capture_output=True, text=True)
            end_time = time.time()
            self.scan_time = end_time - start_time
            scan_returncode = result.returncode

            self.handle_scan_result(result, scan_returncode)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running Snyk CLI: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON output: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during the scan: {e}")
        finally:
            os.chdir('..')
            logger.debug(f'Switched to parent directory: {os.getcwd()}')

    def construct_sast_scan_command(self, target: Union[str, List[str]], report: bool) -> List[str]:
        """
        Construct the Snyk CLI command for SAST scan.
        :param target: Path to the project or list of changed files to be scanned.
        :param report: Boolean to indicate if the results should be reported to Snyk Web UI.
        :return: Command as a list of strings.
        """
        
        command = ['snyk', 'code', 'test', f'--severity-threshold={self.severity_threshold}',
                       f'--json-file-output={self.scan_json_file_path}', f'--sarif-file-output={self.scan_sarif_file_path}']
        if self.event == 'pr':
            if isinstance(target, list):
                changed_files_list = [f"--file={file}" for file in target]
                command += changed_files_list
            else:
                raise ValueError("Invalid target for scan. Must be a string (project path) or list (changed files).")

        if self.policy_path is not None:
            command.append(f"--policy-path={self.policy_path}")
        if report:
            command.append('--report')
            command.append(f"--project-name={self.project_name}")
            current_branch = self.get_current_branch()
            if current_branch:
                command.append(f"--target-reference={current_branch}")

        return command

    def handle_scan_result(self, result: subprocess.CompletedProcess, returncode: int) -> None:
        """
        Handle the result of the SAST scan.
        :param result: Result of the subprocess.run() call.
        :param returncode: Return code of the Snyk CLI command.
        """
        if returncode == 0:
            logger.info("CLI scan completed successfully. No vulnerabilities found.")
            logger.info("No Reports will be generated.")
            logger.debug(result.stdout)
        elif returncode == 1:
            logger.warning("CLI scan completed. Vulnerabilities found.")
            logger.info(result.stdout)
            severity_summary = self.summarize_severities()
            scan_summary = {"scan_time": self.scan_time, "summary": severity_summary}
            self.convert_json_to_html(self.scan_json_file_path, self.scan_html_file_path)
            self.save_results_to_json(scan_summary, self.scan_summary_file_path)
            if not self.evaluate_severity_summary(severity_summary):
                sys.exit(1)  # Fail pipeline
        elif returncode == 2:
            logger.error("CLI scan failed. Failure, try to re-run the command.")
            logger.error(result.stderr)
            sys.exit(1)
        elif returncode == 3:
            logger.error("CLI scan failed. No supported projects detected.")
            logger.info("No Reports will be generated.")
            logger.error(result.stderr)
            sys.exit(1)
        else:
            logger.error(f"CLI scan failed with unexpected error code: {returncode}")
            logger.error(result.stderr)
            sys.exit(1)

    def get_changed_files(self, base_branch: str, pr_branch: str) -> List[str]:
        """
        Get the list of changed files between the base branch and PR branch using GitPython.
        :param base_branch: The base branch of the PR.
        :param pr_branch: The PR branch.
        :return: List of changed files.
        """
        try:
            repo = Repo()
            base_commit = repo.commit(base_branch)
            pr_commit = repo.commit(pr_branch)
            changed_files = [os.path.join(self.repo_name, item.a_path) for item in base_commit.diff(pr_commit)]
            logger.info(f"Found {len(changed_files)} changed files between {base_branch} and {pr_branch}.")
            logger.debug(changed_files)
            return changed_files
        except Exception as e:
            logger.error(f"Error getting changed files: {e}")
            return []

    def summarize_severities(self) -> Dict[str, Union[int, float]]:
        """
        Summarize the severities of issues found in the scan results.
        :return: Dictionary summarizing severities.
        """
        scan_results = self.load_json(self.scan_json_file_path)
        severity_counts = {'low': 0, 'medium': 0, 'high': 0}
        try:
            for run in scan_results.get('runs', []):
                for result in run.get('results', []):
                    level = result.get("level", "")
                    if level in ['note', 'info']:
                        severity_counts['low'] += 1
                    elif level == 'warning':
                        severity_counts['medium'] += 1
                    else:
                        severity_counts['high'] += 1
            logger.info(f"Severity summary: {severity_counts}")
            return severity_counts
        except Exception as e:
            logger.error(f"Error summarizing severities: {e}")
            return severity_counts

    @staticmethod
    def save_results_to_json(results: Dict, file_path: str) -> None:
        """
        Save scan results to a JSON file.
        :param results: Scan results in JSON format.
        :param file_path: Path to save the JSON file.
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=4)
            logger.info(f"Scan results saved to {file_path}.")
        except Exception as e:
            logger.error(f"Error saving scan results to {file_path}: {e}")

    @staticmethod
    def convert_json_to_html(json_file: str, html_file: str) -> None:
        """
        Convert JSON scan results to HTML using snyk-to-html.
        :param json_file: Path to the JSON file.
        :param html_file: Path to save the HTML file.
        """
        try:
            result = subprocess.run(['snyk-to-html', '-i', json_file, '-o', html_file], capture_output=True, text=True)
            result.check_returncode()
            logger.info(f"Converted JSON results to HTML file at {html_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error converting JSON to HTML: {e}")
            raise

    @staticmethod
    def evaluate_severity_summary(severity_summary: Dict[str, Union[int, float]]) -> bool:
        """
        Evaluate severity summary and determine pipeline result.
        :param severity_summary: Severity summary dictionary.
        :return: Boolean indicating whether pipeline should pass or fail.
        """
        if severity_summary.get('high', 0) > 0:
            logger.error("High severity issues found. Pipeline will fail.")
            return False
        else:
            logger.info("No high severity issues found. Pipeline will pass.")
            return True

    @staticmethod
    def load_json(file_path: str) -> Dict[str, Union[str, None]]:
        """
        Load configuration from a JSON file.
        :param file_path: Path to the JSON file.
        :return: Configuration dictionary.
        """
        try:
            with open(file_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded file: {file_path}.")
            return config
        except Exception as e:
            logger.error(f"Error loading file: {file_path}: {e}")
            raise

def main() -> None:
    parser = argparse.ArgumentParser(description="Snyk SAST Scanner")
    parser.add_argument('--event', choices=["push", "pr"], default="push", help="Trigger SAST scan using Snyk CLI")
    parser.add_argument('--report', action='store_true', help="Upload results to Snyk Web UI")
    parser.add_argument('--base-branch', help="Base branch of the PR")
    parser.add_argument('--pr-branch', help="PR branch")
    parser.add_argument('--repo-name', required=True, help="Git repository name")

    args = parser.parse_args()

    SnykScanner.check_snyk_installed()
    SnykScanner.check_snyk_token()

    scanner = SnykScanner(event=args.event, repo_name=args.repo_name)

    if args.event == "pr":
        if not args.base_branch or not args.pr_branch:
            logger.error("Base branch and PR branch are required for scanning a Pull Request.")
            sys.exit(1)
        else:
            scanner.base_branch = args.base_branch
            scanner.pr_branch = args.pr_branch
    scanner.scan_and_generate_report(report=args.report)

if __name__ == "__main__":
    main()
