import streamlit as st
import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

st.set_page_config(page_title="URL Scanner", page_icon="🛡️")
st.title("🛡️ Phishing URL Analyzer")
st.write("Enter a URL below to check if it's malicious.")

target_url = st.text_input("Paste URL here ")

if st.button("Analyze"):
    if target_url:

        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": API_KEY}
        
        with st.spinner("Checking with VirusTotal..."):
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                stats = result['data']['attributes']['last_analysis_stats']
                
                st.subheader("Results:")
                col1, col2, col3 = st.columns(3)
                col1.metric("Malicious", stats['malicious'])
                col2.metric("Suspicious", stats['suspicious'])
                col3.metric("Safe", stats['harmless'])
                
                if stats['malicious'] > 0:
                    st.error("🚨 WARNING: This URL is flagged as MALICIOUS!")
                else:
                    st.success("✅ This URL appears to be safe.")
            else:
                st.info("URL not found in database. It might be a brand new site!")
    else:
        st.warning("Please enter a URL first.")
