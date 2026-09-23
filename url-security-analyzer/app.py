import streamlit as st
import requests
import base64
import time

# إعدادات واجهة الصفحة
st.set_page_config(
    page_title="URL & File Security Analyzer",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ URL & File Security Analyzer")
st.write("Scan URLs or files for potential security threats using VirusTotal API.")

# خانة إدخال مفتاح الـ API من الشريط الجانبي
st.sidebar.header("Configuration")
api_key = st.sidebar.text_input("Enter VirusTotal API Key:", type="password")

# اختيار نوع الفحص
scan_type = st.radio("Choose scan type:", ["Scan URL", "Scan File"])

# ----------------- فحص الروابط (URL Scan) -----------------
if scan_type == "Scan URL":
    url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com")
    
    if st.button("Analyze URL"):
        if not api_key:
            st.error("Please enter your VirusTotal API Key in the sidebar!")
        elif not url_input:
            st.warning("Please enter a valid URL.")
        else:
            with st.spinner("Analyzing URL with VirusTotal..."):
                headers = {"x-apikey": api_key}
                
                # ترميز الرابط بصيغة Base64 حسب متطلبات VirusTotal API v3
                url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
                endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                
                response = requests.get(endpoint, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    
                    st.subheader("Analysis Results")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Malicious 🚨", malicious)
                    col2.metric("Suspicious ⚠️", suspicious)
                    col3.metric("Harmless ✅", harmless)
                    
                    if malicious > 0 or suspicious > 0:
                        st.error(f"⚠️ Warning! This URL is flagged as unsafe by {malicious + suspicious} security engines.")
                    else:
                        st.success("✅ This URL appears to be clean and safe!")
                elif response.status_code == 404:
                    st.info("URL not found in database. Submitting URL for fresh analysis...")
                    # إرسال الرابط للفحص الجديد
                    scan_url = "https://www.virustotal.com/api/v3/urls"
                    payload = {"url": url_input}
                    post_res = requests.post(scan_url, headers=headers, data=payload)
                    if post_res.status_code == 200:
                        st.success("Successfully submitted for analysis! Try checking again in a few seconds.")
                    else:
                        st.error("Failed to submit URL for analysis.")
                else:
                    st.error(f"Error fetching data. (Status Code: {response.status_code})")

# ----------------- فحص الملفات (File Scan) -----------------
else:
    uploaded_file = st.file_uploader("Upload a file to scan:", type=["pdf", "exe", "docx", "zip", "txt", "png", "jpg"])
    
    if st.button("Analyze File"):
        if not api_key:
            st.error("Please enter your VirusTotal API Key in the sidebar!")
        elif uploaded_file is None:
            st.warning("Please upload a file first.")
        else:
            with st.spinner("Uploading and analyzing file..."):
                headers = {"x-apikey": api_key}
                files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
                
                upload_url = "https://www.virustotal.com/api/v3/files"
                response = requests.post(upload_url, headers=headers, files=files)
                
                if response.status_code == 200:
                    analysis_id = response.json()["data"]["id"]
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    
                    # الانتظار لبضع ثوانٍ لحين اكتمال التحليل
                    time.sleep(3)
                    res_analysis = requests.get(analysis_url, headers=headers)
                    
                    if res_analysis.status_code == 200:
                        stats = res_analysis.json()["data"]["attributes"]["stats"]
                        
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        harmless = stats.get("harmless", 0)
                        
                        st.subheader("Analysis Results")
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Malicious 🚨", malicious)
                        col2.metric("Suspicious ⚠️", suspicious)
                        col3.metric("Harmless ✅", harmless)
                        
                        if malicious > 0 or suspicious > 0:
                            st.error("⚠️ File flagged as malicious or suspicious!")
                        else:
                            st.success("✅ File appears clean!")
                    else:
                        st.error("Could not retrieve file analysis status.")
                else:
                    st.error(f"File upload failed. (Status Code: {response.status_code})")