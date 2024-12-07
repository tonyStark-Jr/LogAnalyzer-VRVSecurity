# LogAnalyzer-VRVSecurity

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-orange.svg)

### 🔗 App Deployed link: 🔗 [LogAnalyzer-VRVSecurity](https://log-analyzer-vrv.streamlit.app)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Demo](#demo)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Using the Streamlit GUI (`main_gui.py`)](#1-using-the-streamlit-gui-mainguipy)
  - [2. Using the Command-Line Interface (`main_cli.py`)](#2-using-the-command-line-interface-main_clipy)
  - [3. Accessing the Deployed App](#3-accessing-the-deployed-app)
- [Sample Log File](#sample-log-file)
- [Customization](#customization)

## Introduction

Welcome to **LogAnalyzer-VRVSecurity**! This powerful tool is designed to help you efficiently analyze web server log files, providing valuable insights into traffic patterns, popular resources, and potential security threats. Whether you're a system administrator, developer, or cybersecurity professional, LogAnalyzer-VRVSecurity simplifies the process of understanding and managing your server logs.

## Features

- **Count Requests per IP Address**: Identify how many requests each IP address has made to your server.
- **Identify the Most Frequently Accessed Endpoint**: Discover which endpoints (e.g., URLs or resource paths) are most popular among users.
- **Detect Suspicious Activity**: Spot potential brute force login attempts by monitoring failed login attempts from various IP addresses.
- **Streamlit GUI**: An intuitive web-based interface to interact with the analyzer, upload log files, configure settings, and view results.
- **Command-Line Interface (CLI)**: Perform analyses directly from the terminal for quick and automated log processing.
- **Export Results**: Save analysis outcomes to a CSV file for further review or record-keeping.
- **Deployed Application**: Access the analyzer through a live Streamlit app at [LogAnalyzer-VRVSecurity](https://log-analyzer-vrv.streamlit.app).

## Demo

<img width="1440" alt="image" src="https://github.com/user-attachments/assets/d82c3f61-318d-443f-90eb-3115187094f5">


*Figure: Screenshot of the Streamlit GUI displaying analysis results.*

## Project Structure

```
LogAnalyzer-VRVSecurity/
├── main_gui.py
├── main_cli.py
├── utils.py
├── sample_log.txt
├── log_analysis_results.csv
├── README.md
```

- **main_gui.py**: Streamlit application file that provides the GUI for interacting with the `LogAnalyzer` class.
- **main_cli.py**: Command-Line Interface (CLI) application for performing log analyses directly from the terminal.
- **utils.py**: Contains the `LogAnalyzer` class with methods for analyzing log files.
- **sample_log.txt**: A sample web server log file for testing and demonstration purposes.
- **log_analysis_results.csv**: CSV file where analysis results are saved.
- **README.md**: Documentation for the project.

## Installation

### Prerequisites

- **Python 3.8 or higher**: Ensure you have Python installed. You can download it from [Python's official website](https://www.python.org/downloads/).

### Clone the Repository

```bash
git clone https://github.com/yourusername/LogAnalyzer-VRVSecurity.git
cd LogAnalyzer-VRVSecurity
```

### Create a Virtual Environment (Optional but Recommended)

```bash
python -m venv venv
```

Activate the virtual environment:

- **Windows**:

  ```bash
  venv\Scripts\activate
  ```

- **macOS/Linux**:

  ```bash
  source venv/bin/activate
  ```

### Install Dependencies

```bash
pip install streamlit pandas
```

## Usage

You can interact with **LogAnalyzer-VRVSecurity** using either the Streamlit GUI or the Command-Line Interface (CLI). Additionally, the application is deployed and accessible via a live Streamlit app.

### 1. Using the Streamlit GUI (`main_gui.py`)

The Streamlit GUI provides an intuitive web-based interface for uploading log files, setting analysis thresholds, and viewing results.

#### Steps:

1. **Navigate to the Project Directory**:

   ```bash
   cd path/to/LogAnalyzer-VRVSecurity
   ```

2. **Run the Streamlit App**:

   ```bash
   streamlit run main_gui.py
   ```

   This command will launch the Streamlit server and automatically open the application in your default web browser. If it doesn't open automatically, follow the URL provided in the terminal (typically `http://localhost:8501`).

3. **Interact with the GUI**:
   
   - **Upload a Log File**: Use the file uploader in the sidebar to upload your `.log` or `.txt` file.
   - **Set the Threshold**: Adjust the "Failed Login Attempts Threshold" as needed.
   - **Analyze**: Click the "Analyze" button to perform the analysis.
   - **View Results**: The main panel will display the analysis results.
   - **Download Results**: Use the "Download Analysis Results as CSV" button to save the results.

### 2. Using the Command-Line Interface (`main_cli.py`)

The CLI allows you to perform log analyses directly from the terminal, which is ideal for quick analyses or integrating into automated scripts.

#### Steps:

1. **Navigate to the Project Directory**:

   ```bash
   cd path/to/LogAnalyzer-VRVSecurity
   ```

2. **Run the CLI Application**:

   ```bash
   python main_cli.py [OPTIONS]
   ```

   #### **Available Options**:

   - `--logfile`: Path to the log file to be analyzed (default: `sample.log`).
   - `--csvfile`: Path to the output CSV file (default: `log_analysis_results.csv`).
   - `--threshold`: Threshold for failed login attempts to flag suspicious activity (default: `10`).

   #### **Examples**:

   - **Basic Execution**:

     ```bash
     python main_cli.py
     ```

     *Analyzes `sample.log` with a threshold of `10` and saves results to `log_analysis_results.csv`.*

   - **Specify a Different Log File**:

     ```bash
     python main_cli.py --logfile your_log_file.log
     ```

   - **Set a Custom Threshold**:

     ```bash
     python main_cli.py --threshold 5
     ```

   - **Specify a Different Output CSV File**:

     ```bash
     python main_cli.py --csvfile your_output_file.csv
     ```

### 3. Accessing the Deployed App

For convenience, the application is deployed and accessible via the following URL:

🔗 [LogAnalyzer-VRVSecurity](https://log-analyzer-vrv.streamlit.app)

#### Features of the Deployed App:

- **No Installation Required**: Access the analyzer directly through your web browser.
- **Interactive Interface**: Upload log files, set thresholds, and view results without any setup.
- **Download Results**: Easily download analysis results as a CSV file.

*Note: Ensure that your log files are properly formatted to include IP addresses, timestamps, HTTP methods, endpoints, status codes, and any relevant messages for accurate analysis.*

## Sample Log File

A sample log file named `sample.log` is included in the repository to demonstrate the tool's capabilities. Ensure that your log files follow a similar format for accurate analysis. Here's a snippet of the sample log:

```
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
...
```

*Ensure that your log files are properly formatted to include IP addresses, timestamps, HTTP methods, endpoints, status codes, and any relevant messages.*

## Customization

### 1. Changing the Failed Login Threshold

You can adjust the threshold for flagging suspicious IP addresses using either the Streamlit GUI or the CLI.

- **Streamlit GUI**: Use the number input in the sidebar to set a different threshold.
- **CLI**: Use the `--threshold` option.

  ```bash
  python main_cli.py --threshold 5
  ```

### 2. Analyzing Different Log Files

- **Streamlit GUI**: Upload any log file using the file uploader.
- **CLI**: Specify a different log file using the `--logfile` option.

  ```bash
  python main_cli.py --logfile your_log_file.log
  ```

### 3. Modifying the Output CSV File

- **Streamlit GUI**: The CSV file is saved as `log_analysis_results.csv` by default. To change this, modify the `csv_file` parameter when instantiating the `LogAnalyzer` class in `main_gui.py`.
  
  ```python
  analyzer = LogAnalyzer(
      log_file=temp_file_path,
      csv_file='your_custom_filename.csv',
      failed_login_threshold=threshold
  )
  ```

- **CLI**: Use the `--csvfile` option to specify a different output file.

  ```bash
  python main_cli.py --csvfile your_output_file.csv
  ```
