# Dhanyah Crypto Utility

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)](https://microsoft.com/windows)
[![FIPS 140-2/3 Level 3](https://img.shields.io/badge/FIPS%20140--2%2F3-Level%203-green.svg)](https://csrc.nist.gov/)
[![Indian CCA DSC Compliant](https://img.shields.io/badge/CCA%20India-DSC%20Compliant-orange.svg)](https://cca.gov.in/)

**Dhanyah Crypto Utility** is a unified, enterprise-grade desktop application and local cryptographic service built for the Indian PKI ecosystem. It provides a single universal management interface, local hardware token monitor, and PKI signing suite for all four major FIPS 140-2/3 Level 3 crypto USB tokens used for Digital Signature Certificates (DSC):

1. **HyperPKI / HYP 2003 FIPS L3** (Feitian Technologies)
2. **mToken CryptoID** (Longmai Technology)
3. **Watchdata ProxKey** (Watchdata Technologies)
4. **Precision InnaITKey** (Precision Biometric India)

---

## 🌟 Why Dhanyah Crypto Utility?

In India, Chartered Accountants, Tax Professionals, Company Secretaries, and Businesses currently juggle **4 distinct proprietary vendor management tools**. Each tool has conflicting drivers, outdated user interfaces, and separate middleware. 

**Dhanyah Crypto Utility** solves this by providing:
- **🌐 Network DSC Mesh**: Zero-config peer discovery over LAN (Wi-Fi/Ethernet). Share connected USB tokens from any office workstation and mount them virtually on other PCs for remote signing across web portals.
- **⚡ Resilient Hardware Detection (New in v1.1.1)**: Multi-layer detection engine with PC/SC reader-name resilience, dual-scope WinSCard (User & System), and direct PKCS#11 hardware polling. Eliminates startup false-disconnect warnings and `CKR_SLOT_ID_INVALID` slot errors.
- **🏛️ Multi-Port Govt Loopback Gateway (`:15085`, `:18200`, `:26443`)**: Coexists safely with official eMudhra emBridge, providing seamless plug-and-play signing in **MCA V3, GST Portal, Income Tax, EPFO, and e-Tenders**.
- **100% Zero-Install Portability**: Bundles verified standalone 64-bit PKCS#11 libraries for all 4 tokens. You do **NOT** need to install any proprietary vendor utilities.
- **Unified Hardware Auto-Detection**: Uses Windows Smart Card Resource Manager (`winscard`) to automatically detect tokens via ATR (Answer To Reset) signatures and reader hardware strings.
- **Dynamic Slot Auto-Resolution**: Automatically queries and targets the token's active hardware slot ID (e.g. `0x10000000` on Longmai mToken), eliminating `CKR_FUNCTION_NOT_SUPPORTED` errors.
- **Indian CCA Certificate Inspector**: Automatically extracts and displays Subject Common Name, PAN Number (OID `2.5.4.45`), Certificate Class (Class 3 / Class 2), Issuing CA (eMudhra, Capricorn, VSign, IDSign, Pantasign), and 30-day expiration warnings.
- **Hardware-Isolated Signing**: Private keys never leave the secure hardware cryptographic boundary.
- **Dual-Tab PAdES PDF Digital Signer**: Standalone Single and Batch PDF signer creating `adbe.pkcs7.detached` signatures with visible placement or invisible compliance.
- **Modern UI with Light / Dark Mode**: Enterprise desktop interface with real-time theme toggling (`☀️ Light Mode` / `🌙 Dark Mode`).

---

## 🛡️ Supported Crypto Hardware Tokens

| Token Brand | Vendor | Bundled Middleware | Hardware Standard |
| :--- | :--- | :--- | :--- |
| **HyperPKI / HYP 2003** | Feitian / HyperPKI | `eps2003csp11v2.dll` | FIPS 140-2 Level 3 |
| **mToken CryptoID** | Longmai Technology | `cryptoida_pkcs11.dll` | FIPS 140-2 Level 3 |
| **Watchdata ProxKey** | Watchdata | `WDPKCS.dll` + companions | FIPS 140-2 Level 3 |
| **Precision InnaITKey** | Precision Biometrics | `InnaITPKCS11Driver.dll` | FIPS 140-3 Level 3 |

---

## 🚀 Quick Start (Pre-built Windows Installer)

### Download & Install (v1.1.6)
[![Download Dhanyah Crypto Utility v1.1.6](https://img.shields.io/badge/Download-Installer%20v1.1.6%20(.exe)-blue?style=for-the-badge&logo=windows)](https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY/releases/download/v1.1.6/DhanyahCryptoUtility_Setup_v1.1.6.exe)

1. Download **[DhanyahCryptoUtility_Setup_v1.1.6.exe](https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY/releases/download/v1.1.6/DhanyahCryptoUtility_Setup_v1.1.6.exe)** from the [Releases](https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY/releases) page or from the `releases/` directory in this repository.
2. Run the setup installer (Administrator privileges required to register Windows Smart Card MiniDrivers & 32-bit SysWOW64 DLLs).
3. Plug in any of the 4 supported USB tokens — the application will automatically detect the token, display its certificates, and allow safe PIN operations and signing.

---

## 💻 Developer Setup & Running from Source

### Prerequisites
- Windows 10, Windows 11, or Windows Server
- Python 3.10+ (64-bit)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY.git
   cd DHANYAH-CRYPTO-UTILITY
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```
   *(Or double-click `run.bat`)*

### Headless Service Mode (No GUI)
To run only the background Loopback REST Gateway without launching the desktop GUI:
```bash
python main.py --headless --port 18200
```

### Simulation / Demo Mode
Test the application without needing physical hardware tokens:
```bash
python main.py --sim MTOKEN
```
*(Options: `HYP2003`, `MTOKEN`, `PROXKEY`, `INNAIT`)*

---

## 📦 Building Standalone Executable (.exe)

To compile the standalone portable Windows executable:
```bash
build_exe.bat
```
The compiled, zero-install portable application will be output to:
`dist\DhanyahCryptoUtility\DhanyahCryptoUtility.exe`

---

## 🌐 Localhost Loopback REST API (Port 18200)

The loopback server runs on `http://127.0.0.1:18200` with full CORS support (`Access-Control-Allow-Origin: *`).

### Endpoints:

#### 1. Token & Driver Status
```http
GET http://127.0.0.1:18200/status
```
**Response:**
```json
{
  "service": "Dhanyah Crypto Utility Gateway",
  "version": "1.0.0",
  "status": "ready",
  "token_connected": true,
  "token": {
    "token_id": "MTOKEN",
    "name": "mToken CryptoID",
    "vendor": "Longmai Technology",
    "reader": "Longmai mTokenCryptoFIPS 0",
    "driver_path": "drivers\\mtoken\\cryptoida_pkcs11.dll",
    "is_simulated": false
  }
}
```

#### 2. Get Certificates (with CCA metadata)
```http
GET http://127.0.0.1:18200/certificates
```

#### 3. Safe PIN Verification
```http
POST http://127.0.0.1:18200/verify/pin
Content-Type: application/json

{
  "pin": "12345678"
}
```

#### 4. Hardware SHA-256 Hash Signing
```http
POST http://127.0.0.1:18200/sign/hash
Content-Type: application/json

{
  "pin": "12345678",
  "hash_hex": "a35b...64_char_hex..."
}
```

#### 5. PDF Signing (PAdES Detached)
```http
POST http://127.0.0.1:18200/sign/pdf
Content-Type: application/json

{
  "pin": "12345678",
  "pdf_base64": "JVBERi0xLjQK...",
  "reason": "MCA Annual Filing",
  "location": "Chennai"
}
```

---

## 🧪 Testing

Run the automated test suite:
```bash
pytest tests/
```
All 12 unit tests verify:
- ATR identification for all 4 vendor token profiles
- Reader string heuristic matching
- Simulation mode and mock certificate synthesis
- 30-day DSC expiration alert calculation
- Loopback HTTP REST endpoints and CORS pre-flight
- Hardware RSA signature construction & PAdES PDF signer engine

---

## 👤 Author & Contact

- **Author**: CA Akash J. Bhayani
- **Website**: [https://ca-akash.in](https://ca-akash.in)
- **Email**: [mail@ca-akash.in](mailto:mail@ca-akash.in)
- **Repository**: [https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY](https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY)

---

## 📄 License

This project is licensed under the GNU General Public License v3 - see the [LICENSE](LICENSE) file for details.
