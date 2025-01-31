🛠️ Setup Guide for Threat Intelligence Lookup Tool

Follow these steps to install and set up the tool on your system.
1️⃣ Install Python & Dependencies

Ensure you have Python 3 installed. Then, create a virtual environment:

python3 -m venv ~/threat_lookup_env
source ~/threat_lookup_env/bin/activate # For Linux/macOS
or

threat_lookup_env\Scripts\activate # For Windows (PowerShell)

Now install the required Python libraries:

pip install requests python-dotenv
2️⃣ Get API Keys

You need API keys for VirusTotal and AbuseIPDB.
🔑 VirusTotal API Key

    Go to VirusTotal API.
    Sign up and generate an API key.

🔑 AbuseIPDB API Key

    Go to AbuseIPDB API.
    Create an account and generate an API key.

3️⃣ Secure API Key Storage (Outside Project Folder)

Instead of storing API keys inside the project, we'll keep them securely in your home directory.

    Open a terminal and go to your home directory:
    cd ~

    Create a hidden environment file:
    nano .threat_lookup_env

    Add your API keys:
    VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
    ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

    Save the file (CTRL + X, then Y, then ENTER).

4️⃣ Load API Keys Automatically

To make sure your script can read the API keys, you need to load them when running the script.

For Linux/macOS, add this line to ~/.bashrc or ~/.zshrc:
export $(grep -v '^#' ~/.threat_lookup_env | xargs)

For Windows (PowerShell), run this command before using the script:
Get-Content ~/.threat_lookup_env | ForEach-Object { $name, $value = $_ -split '='; Set-Item -Path "Env:$name" -Value $value }
5️⃣ Run the Script

Now, you can execute the tool:

python3 threat_lookup.py

✅ Setup Complete! Now, check USAGE.md to see how to use the tool. 
