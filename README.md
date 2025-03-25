# SwiftForge-MT103 – SWIFT Message Generator & Validator  

**SwiftForge-MT103** is a powerful Python-based tool for generating, validating, and analyzing **MT103 SWIFT payment messages**. Designed for financial professionals, developers, and researchers, this script ensures **accuracy, security, and compliance** in handling international transactions.  

## 👉 Features  
- **MT103 Message Generation** – Create structured SWIFT payment messages dynamically.  
- **Validation & Compliance Check** – Ensure messages conform to SWIFT standards.  
- **Message Parsing & Extraction** – Read and extract transaction details with ease.  
- **Stealth & Security Mode** – Protect sensitive transaction data with encryption.  
- **Customizable Fields** – Modify sender, receiver, currency, and transaction details.  
- **Transaction Logging** – Keep a record of generated and validated messages.  

## 🛠 Installation  

### Prerequisites  
Ensure you have **Python 3.12** installed on your system.  

### 1️⃣ Clone the Repository  
```sh  
git clone https://github.com/yourusername/SwiftForge-MT103.git  
cd SwiftForge-MT103  
```  

### 2️⃣ Install Dependencies  
```sh  
pip install -r requirements.txt  
```  

## 🚀 Usage  

### 1. Generate an MT103 Message  
Run the script to generate an **MT103** message:  
```sh  
python mt103_generator.py  
```  
The generated message will be saved as `output.mt103`.  

### 2. Validate an MT103 Message  
Check if an existing **MT103** message follows the SWIFT format:  
```sh  
python mt103_validator.py --file output.mt103  
```  

### 3. Extract Data from an MT103 File  
```sh  
python mt103_parser.py --file output.mt103  
```  

## 📄 Example MT103 Message  

```
{1:F01BANKDEFMAXXX0000000000}{2:I103BANKXYZXXXXN}{4:  
:20:1234567890  
:23B:CRED  
:32A:240325EUR10000,00  
:50K:/1234567890  
John Doe  
123 Main Street  
New York, USA  
:59:/9876543210  
Jane Smith  
456 Elm Street  
London, UK  
:70:Invoice Payment  
:71A:OUR  
-}  
```

This message contains:  
- **Sender & Receiver Bank Information**  
- **Transaction Amount & Currency**  
- **Ordering & Beneficiary Customer Details**  
- **Purpose of Payment**  

## ⚙️ Configuration  

Modify `config.json` to customize transaction details:  

```json  
{
  "sender_bank": "BANKDEFMAXXX",
  "receiver_bank": "BANKXYZXXXX",
  "transaction_reference": "1234567890",
  "amount": "10000.00",
  "currency": "EUR",
  "date": "240325",
  "sender_name": "John Doe",
  "receiver_name": "Jane Smith",
  "message_purpose": "Invoice Payment"
}  
```  

## 🔒 Security & Compliance  

⚠ **Disclaimer:**  
This tool is intended **for educational and research purposes only**. Unauthorized use of financial message formats may violate laws and regulations. Ensure that you have the necessary permissions before handling real transactions.  

## 🚀 Future Enhancements  

- **Encryption for Secure Transactions**  
- **Automated SWIFT Network Simulation**  
- **API Integration for Real-Time Processing**  

## 🤝 Contributing  

Pull requests are welcome! Feel free to **fork** this repo, make improvements, and submit a **PR**.  

## 📚 License  

This project is licensed under the
