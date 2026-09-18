# 🔐 SecureLogin Inspector

**SecureLogin Inspector – Passive Web Security Configuration Analyzer**

A Python-based security analysis tool designed to identify common web-security configuration issues in authorized applications.

## 🚀 Features

* 🔗 URL validation
* 🔒 HTTPS configuration analysis
* 🛡️ Security header analysis
* 🍪 Cookie security analysis
* 🔑 Login form detection
* 🌐 HTTPS redirect checking
* 📄 Mixed-content detection
* 🖥️ Server information disclosure detection
* 📦 Content-Type analysis
* 🔄 CORS configuration analysis
* 📊 Security score and grade
* 🚨 Security findings and severity
* 💡 Security recommendations
* 📑 PDF security report generation
* 🖥️ Interactive Streamlit dashboard
* 🧪 Local Flask test application

## 🛠️ Technologies Used

* Python
* Streamlit
* Flask
* Requests
* BeautifulSoup
* ReportLab
* SQLite
* HTML/CSS

## 📂 Project Structure

```text
SecureLogin-Inspector/
│
├── security_inspector/
│   ├── dashboard.py
│   ├── security_checks.py
│   ├── security_score.py
│   ├── url_validator.py
│   └── report_generator.py
│
├── test_login_app/
│   ├── app.py
│   ├── templates/
│   └── static/
│
├── screenshots/
│
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/SecureLogin-Inspector.git
```

Enter the project directory:

```bash
cd SecureLogin-Inspector
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Install the required packages:

```powershell
python -m pip install -r requirements.txt
```

## ▶️ Run the Security Inspector

Go to the security inspector folder:

```powershell
cd security_inspector
```

Run:

```powershell
python -m streamlit run dashboard.py
```

The Streamlit application will open in your browser.

## 🧪 Local Testing

The project includes a Flask-based local test application.

Open another terminal and run:

```powershell
cd test_login_app
python app.py
```

The local application can then be tested using the SecureLogin Inspector.

## 📊 Security Analysis

The analyzer performs passive checks including:

* HTTPS
* HTTPS redirection
* Security headers
* Authentication cookie attributes
* Login form configuration
* Mixed content
* CORS
* Server information disclosure
* Content-Type configuration

The results are converted into a security score and presented with findings and recommendations.

## ⚠️ Responsible Use

This project is intended for **educational purposes and authorized security testing only**.

Only analyze websites and applications that you own or have explicit permission to test.

The tool performs passive security configuration analysis and should not be considered a complete penetration-testing solution.

## 🔮 Future Enhancements

* Scan history
* Security-result comparison
* Advanced security checks
* Improved vulnerability classification
* Database-based report storage
* More detailed security reports
* Additional security standards

## 👨‍💻 Author

**Amirrtesh**

B.Tech Computer Science and Engineering

## 📜 License

This project is released under the MIT License.
