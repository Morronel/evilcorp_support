# 🏴‍☠️ EvilCorp Support Portal

## 🎯 Challenge Information

**Competition**: First National Ukrainian CTF Finals  
**Organizer**: Federation of Military-Tech Sports of Ukraine  
**Platform**: Cyber Unit Range  
**Difficulty**: Medium  
**Category**: Web Security

## 📋 Challenge Description

Welcome to EvilCorp's internal support portal! As a leading corporation in... *questionable* business practices, EvilCorp has developed a state-of-the-art support system for their employees. 

The portal features:
- 💬 Real-time chat with automated support agents
- 🎫 Comprehensive ticket management system  
- 👥 Multi-role user management (User/Support/Admin)
- 🔧 Advanced administrative diagnostics tools

Your mission, should you choose to accept it, is to explore this corporate environment and uncover what EvilCorp is trying to hide. Can you navigate through their security measures and discover their secrets?

## 🚀 Quick Start

### Prerequisites
- Docker installed on your system
- Port 5000 available

### Setup Instructions

1. **Build the container**:
   ```bash
   sudo docker build -t evilcorp_support .
   ```

2. **Run the application**:
   ```bash
   sudo docker run -p 5000:5000 evilcorp_support
   ```

3. **Access the portal**:
   - Navigate to `http://localhost:5000`
   - Register a new account to begin your investigation

## 🎯 Objective

Investigate the EvilCorp Support Portal and find the hidden flag. This challenge tests your skills in:
- Web application security assessment
- Multi-stage attack chaining
- Social engineering techniques
- Privilege escalation

## ⚠️ Disclaimer

This application contains **intentional security vulnerabilities** designed for educational purposes in a controlled CTF environment. 

**DO NOT** deploy this application in production or on public-facing servers.

---

*"At EvilCorp, we take security seriously... or do we?"* 😈

## 📝 Notes

- The challenge involves multiple interconnected vulnerabilities
- Pay attention to how different user roles interact with the system
- Sometimes the most innocent features hide the biggest secrets
- For the complete solution walkthrough, see `writeup.md`

Good luck!