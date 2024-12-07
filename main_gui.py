import streamlit as st
from utils import LogAnalyzer
import tempfile
import os
import pandas as pd

def main():
    st.title("Web Server Log Analyzer")
    st.write("""
    This application analyzes web server log files to:
    1. Count requests per IP address.
    2. Identify the most frequently accessed endpoint.
    3. Detect suspicious activity based on failed login attempts.
    """)

    # Sidebar for configuration
    st.sidebar.header("Configuration")

    # File uploader
    uploaded_file = st.sidebar.file_uploader("Upload Log File", type=["log", "txt"])
    
    # Threshold input
    threshold = st.sidebar.number_input(
        "Failed Login Attempts Threshold",
        min_value=1,
        max_value=1000,
        value=10,
        step=1
    )

    # Button to trigger analysis
    if st.sidebar.button("Analyze"):
        if uploaded_file is not None:
            # Save uploaded file to a temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.log') as tmp_file:
                tmp_file.write(uploaded_file.getbuffer())
                temp_file_path = tmp_file.name

            # Instantiate LogAnalyzer with the temporary file
            analyzer = LogAnalyzer(
                log_file=temp_file_path,
                csv_file='log_analysis_results.csv',
                failed_login_threshold=threshold
            )

            # Run all analyses
            with st.spinner('Analyzing...'):
                results = analyzer.run_all_analyses()
            
            # Display Results
            st.header("Analysis Results")

            # 1. Requests per IP Address
            st.subheader("1. Requests per IP Address")
            df_ip = pd.DataFrame(results['requests_per_ip'], columns=['IP Address', 'Request Count'])
            st.dataframe(df_ip)

            # 2. Most Frequently Accessed Endpoint
            st.subheader("2. Most Frequently Accessed Endpoint")
            endpoint, count = results['most_accessed_endpoint']
            st.write(f"**Endpoint:** {endpoint}")
            st.write(f"**Access Count:** {count}")

            # 3. Suspicious Activity Detected
            st.subheader("3. Suspicious Activity Detected")
            if results['suspicious_activity']:
                df_suspicious = pd.DataFrame(results['suspicious_activity'], columns=['IP Address', 'Failed Login Attempts'])
                st.dataframe(df_suspicious)
            else:
                st.write("No suspicious activity detected based on the current threshold.")

            # Save results to CSV
            analyzer.save_to_csv(results)

            # Offer CSV download
            if os.path.exists(analyzer.csv_file):
                with open(analyzer.csv_file, 'rb') as f:
                    st.download_button(
                        label="Download Analysis Results as CSV",
                        data=f,
                        file_name=analyzer.csv_file,
                        mime='text/csv'
                    )
            else:
                st.warning("CSV file not found.")

            # Clean up temporary file
            os.remove(temp_file_path)

        else:
            st.warning("Please upload a log file to analyze.")

if __name__ == "__main__":
    main()
