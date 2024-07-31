#!/usr/bin/env python
# coding: utf-8

# In[6]:


import gradio as gr

# A simple class to represent a cybercrime
class CyberCrime:
    def __init__(self, crime_id, description, crime_type):
        self.crime_id = crime_id
        self.description = description
        self.crime_type = crime_type

    def __str__(self):
        return f"ID: {self.crime_id}, Type: {self.crime_type}, Description: {self.description}"

# In-memory storage for cybercrime items
cybercrime_list = []

# Guidelines for analyzing different types of cybercrimes
analysis_guidelines = {
    "Phishing": (
        "Phishing involves tricking individuals into revealing sensitive information, "
        "such as login credentials or financial details, through fake emails or websites.\n"
        "1. Collect and preserve the phishing email or message.\n"
        "2. Analyze the email headers for details about the sender and the email's route.\n"
        "3. Identify suspicious links or attachments in the message.\n"
        "4. Use tools to verify the authenticity of the sender's domain.\n"
        "5. Educate potential victims about recognizing phishing attempts."
    ),
    "Malware": (
        "Malware refers to malicious software designed to damage or exploit systems.\n"
        "1. Isolate affected systems to prevent the spread of the malware.\n"
        "2. Use antivirus and anti-malware tools to identify and remove the malware.\n"
        "3. Analyze the malware's behavior and payload.\n"
        "4. Check for any backdoors or unauthorized access created by the malware.\n"
        "5. Restore systems from secure backups and update all software."
    ),
    "Denial of Service (DoS)": (
        "DoS attacks aim to overwhelm a system, making it unavailable to users.\n"
        "1. Monitor network traffic for abnormal spikes or patterns.\n"
        "2. Identify the source of the attack and implement measures to block traffic.\n"
        "3. Analyze logs to determine the nature and scope of the attack.\n"
        "4. Implement rate-limiting and filtering rules to mitigate the attack.\n"
        "5. Collaborate with ISPs and law enforcement if necessary."
    ),
    "Ransomware": (
        "Ransomware encrypts the victim's data, demanding payment for decryption.\n"
        "1. Immediately disconnect infected systems from the network.\n"
        "2. Do not pay the ransom; instead, seek professional assistance.\n"
        "3. Identify the ransomware strain and its encryption methods.\n"
        "4. Restore data from secure, offline backups.\n"
        "5. Improve security measures to prevent future infections."
    ),
    "Man-in-the-Middle (MitM)": (
        "MitM attacks intercept and alter communication between parties without their knowledge.\n"
        "1. Secure communication channels using strong encryption protocols.\n"
        "2. Verify SSL/TLS certificates and ensure they are valid.\n"
        "3. Monitor network traffic for signs of interception or alteration.\n"
        "4. Educate users on avoiding insecure public Wi-Fi networks.\n"
        "5. Implement mutual authentication mechanisms."
    ),
    "Social Engineering": (
        "Social engineering exploits human psychology to gain unauthorized access.\n"
        "1. Educate staff on recognizing social engineering tactics.\n"
        "2. Verify the identity of individuals requesting sensitive information.\n"
        "3. Implement strong security policies, including two-factor authentication.\n"
        "4. Review access logs for unusual or unauthorized access attempts.\n"
        "5. Conduct regular security awareness training."
    ),
    "Data Breach": (
        "A data breach involves unauthorized access to sensitive information.\n"
        "1. Identify the compromised data and the method of breach.\n"
        "2. Secure systems and prevent further unauthorized access.\n"
        "3. Notify affected parties and regulatory bodies as required.\n"
        "4. Conduct a thorough investigation to understand the breach.\n"
        "5. Implement stronger security controls and monitor systems continuously."
    ),
    "Unauthorized Access": (
        "Unauthorized access involves gaining entry to systems or data without permission.\n"
        "1. Review access logs to identify unauthorized access points.\n"
        "2. Implement multi-factor authentication and strong passwords.\n"
        "3. Disable unused accounts and enforce the principle of least privilege.\n"
        "4. Conduct a security audit to identify and fix vulnerabilities.\n"
        "5. Educate users on securing their credentials."
    ),
    "Identity Theft": (
        "Identity theft involves using someone's personal information without consent.\n"
        "1. Collect evidence of identity theft, such as unauthorized transactions.\n"
        "2. Work with financial institutions to freeze affected accounts.\n"
        "3. Advise victims to change passwords and secure personal data.\n"
        "4. Investigate the source and method of the identity theft.\n"
        "5. Provide guidance on monitoring for future identity theft."
    ),
    "Cyberstalking": (
        "Cyberstalking involves using the internet to harass or intimidate someone.\n"
        "1. Document all instances of cyberstalking, including messages and posts.\n"
        "2. Advise victims on blocking and reporting the stalker.\n"
        "3. Work with law enforcement to identify the perpetrator.\n"
        "4. Provide resources for victim support and legal action.\n"
        "5. Monitor for ongoing harassment and take protective measures."
    ),
    "Botnets": (
        "Botnets are networks of infected devices controlled by a malicious actor.\n"
        "1. Identify and isolate infected devices from the network.\n"
        "2. Use specialized tools to detect and remove botnet malware.\n"
        "3. Analyze the botnet's command and control (C&C) structure.\n"
        "4. Notify relevant parties to help dismantle the botnet infrastructure.\n"
        "5. Educate users on securing their devices to prevent future infections."
    ),
    "SQL Injection": (
        "SQL injection involves inserting malicious SQL code into a query to manipulate databases.\n"
        "1. Identify and isolate the affected application or database.\n"
        "2. Review and sanitize all user inputs to prevent SQL injection.\n"
        "3. Implement parameterized queries and stored procedures.\n"
        "4. Monitor database activity for suspicious queries.\n"
        "5. Conduct regular security audits of the database and applications."
    ),
    "Cross-Site Scripting (XSS)": (
        "XSS attacks inject malicious scripts into web pages viewed by others.\n"
        "1. Identify the affected web pages and sanitize user inputs.\n"
        "2. Implement Content Security Policy (CSP) headers to prevent XSS.\n"
        "3. Use input validation and output encoding techniques.\n"
        "4. Educate developers on secure coding practices.\n"
        "5. Regularly test web applications for XSS vulnerabilities."
    ),
    "Insider Threat": (
        "Insider threats involve malicious activities conducted by someone within an organization.\n"
        "1. Monitor employee access and behavior for suspicious activities.\n"
        "2. Implement role-based access control and the principle of least privilege.\n"
        "3. Educate employees on the importance of data security.\n"
        "4. Establish protocols for reporting and responding to insider threats.\n"
        "5. Regularly review and update security policies."
    ),
    "Spoofing": (
        "Spoofing involves disguising communication to appear as a trusted source.\n"
        "1. Verify the authenticity of communications, especially those requesting sensitive information.\n"
        "2. Implement email authentication protocols like SPF, DKIM, and DMARC.\n"
        "3. Educate users on recognizing and reporting spoofing attempts.\n"
        "4. Monitor network traffic for signs of IP or domain spoofing.\n"
        "5. Use strong encryption and authentication methods for sensitive communications."
    ),
    "Cryptojacking": (
        "Cryptojacking involves unauthorized use of a system's resources to mine cryptocurrency.\n"
        "1. Monitor system performance for unexplained slowdowns or high resource usage.\n"
        "2. Use specialized tools to detect cryptojacking malware.\n"
        "3. Isolate and clean infected systems.\n"
        "4. Educate users on the dangers of cryptojacking and how to avoid it.\n"
        "5. Implement robust security measures to prevent malware infections."
    ),
    "Zero-Day Exploits": (
        "Zero-day exploits target vulnerabilities that are unknown to the software vendor.\n"
        "1. Apply security patches and updates as soon as they are released.\n"
        "2. Use intrusion detection and prevention systems to monitor for unusual activity.\n"
        "3. Collaborate with security researchers to identify and patch vulnerabilities.\n"
        "4. Educate users on safe internet practices to avoid exploitation.\n"
        "5. Regularly back up critical data and systems."
    ),
    "Cyber Espionage": (
        "Cyber espionage involves spying on organizations or governments to steal sensitive information.\n"
        "1. Implement strict access controls and monitor sensitive data access.\n"
        "2. Use encryption for data at rest and in transit.\n"
        "3. Monitor for signs of data exfiltration or unauthorized access.\n"
        "4. Collaborate with national security agencies if necessary.\n"
        "5. Conduct regular security audits and vulnerability assessments."
    ),
    "Advanced Persistent Threats (APTs)": (
        "APTs are prolonged, targeted cyber attacks aimed at stealing information.\n"
        "1. Monitor network traffic and system behavior for signs of APTs.\n"
        "2. Use endpoint detection and response (EDR) tools to identify threats.\n"
        "3. Implement multi-layered security measures, including firewalls and intrusion detection systems.\n"
        "4. Conduct regular security training for employees.\n"
        "5. Collaborate with cybersecurity experts to mitigate the threat."
    ),
    "Cyber Terrorism": (
        "Cyber terrorism involves the use of technology to create fear or cause harm.\n"
        "1. Monitor critical infrastructure for signs of cyber attacks.\n"
        "2. Implement comprehensive cybersecurity measures and incident response plans.\n"
        "3. Collaborate with law enforcement and intelligence agencies.\n"
        "4. Educate the public on recognizing and reporting suspicious activities.\n"
        "5. Conduct regular drills and simulations to prepare for potential cyber terrorism incidents."
    )
}

# Simple authentication system for restricted access
USERNAME = "admin"
PASSWORD = "password123"

# Function to add a cybercrime
def add_cybercrime(crime_id, description, crime_type):
    cybercrime = CyberCrime(crime_id, description, crime_type)
    cybercrime_list.append(cybercrime)
    return f"Cybercrime with ID {crime_id} added successfully!"

# Function to view all recorded cybercrimes (restricted access)
def view_cybercrimes(username, password):
    if username == USERNAME and password == PASSWORD:
        if not cybercrime_list:
            return "No cybercrimes recorded yet."
        else:
            return "\n".join(str(crime) for crime in cybercrime_list)
    else:
        return "Access denied. Incorrect username or password."

# Function to get analysis guidelines for a given crime type
def get_guidelines(crime_type):
    return analysis_guidelines.get(crime_type, "No guidelines available for this type.")

# Define the Gradio interface
with gr.Blocks() as demo:
    gr.Markdown("## Cybercrime Investigation System")

    # Section to add a new cybercrime
    with gr.Tab("Cybercrime Details"):
        crime_id = gr.Textbox(label="Crime ID")
        description = gr.Textbox(label="Crime Description")
        crime_type = gr.Radio(label="Crime Type", choices=list(analysis_guidelines.keys()))
        add_button = gr.Button("Add Cybercrime")
        add_result = gr.Textbox(label="Result")
        add_button.click(fn=add_cybercrime, inputs=[crime_id, description, crime_type], outputs=add_result)

    # Section to view all cybercrimes with login
    with gr.Tab("View Cybercrimes"):
        gr.Markdown("### Restricted Access - Please log in to view recorded cybercrimes.")
        username = gr.Textbox(label="Username")
        password = gr.Textbox(label="Password", type="password")
        login_button = gr.Button("Log In")
        crime_list = gr.Textbox(label="Cybercrime List", lines=10, interactive=False)
        login_button.click(fn=view_cybercrimes, inputs=[username, password], outputs=crime_list)

    # Section to view guidelines for a specific type of cybercrime
    with gr.Tab("Analysis Guidelines for Investigators"):
        guidelines_crime_type = gr.Radio(label="Crime Type", choices=list(analysis_guidelines.keys()))
        guidelines_button = gr.Button("Get Guidelines")
        guidelines_output = gr.Textbox(label="Guidelines", lines=10, interactive=False)
        guidelines_button.click(fn=get_guidelines, inputs=guidelines_crime_type, outputs=guidelines_output)

# Launch the Gradio interface
demo.launch()



# In[ ]:





# In[ ]:




