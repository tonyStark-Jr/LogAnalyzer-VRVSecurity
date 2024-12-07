import re
from collections import Counter
import csv
import argparse
import sys
from utils import *

def main():
    # Setup argparse for CLI
    parser = argparse.ArgumentParser(
        description="Analyze web server log files for various metrics.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--logfile',
        type=str,
        default='sample.log',
        help='Path to the log file to be analyzed (default: sample.log)'
    )
    parser.add_argument(
        '--csvfile',
        type=str,
        default='log_analysis_results.csv',
        help='Path to the output CSV file (default: log_analysis_results.csv)'
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=10,
        help='Threshold for failed login attempts to flag suspicious activity (default: 10)'
    )

    args = parser.parse_args()

    # Instantiate LogAnalyzer with provided arguments
    analyzer = LogAnalyzer(
        log_file=args.logfile,
        csv_file=args.csvfile,
        failed_login_threshold=args.threshold
    )

    # Run all analyses
    results = analyzer.run_all_analyses()

    # Display all results
    analyzer.display_all_results(results)

    # Save all results to CSV
    analyzer.save_to_csv(results)

if __name__ == "__main__":
    main()
