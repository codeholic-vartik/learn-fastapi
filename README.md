# learn-fastapi   

pip install disposable-email-domains


https://github.com/shaileshpandit141/dns-smtp-email-validator


# Step-by-Step Guide: Setting Up an SMTP Server on Vultr and Verifying Emails Without Sending

## 1. Setting Up an SMTP Server on Vultr

### Step 1: Deploy a Vultr VPS
1. Sign up at [Vultr](https://www.vultr.com/) and log in.
2. Click **Deploy New Server**.
3. Choose **Cloud Compute Instance**.
4. Select **Ubuntu 22.04** (recommended) as your operating system.
5. Choose at least **2GB RAM** for optimal performance.
6. Select a data center location near your users.
7. Add an SSH key for secure access (optional but recommended).
8. Click **Deploy Now** and wait for the server to be created.

### Step 2: Connect to Your Server via SSH
Once your server is deployed, find its **IP address** in your Vultr dashboard and connect using:
```bash
ssh root@your_server_ip
```
Replace `your_server_ip` with your actual server IP address.

### Step 3: Update and Install Required Packages
Run the following commands to update the server and install essential packages:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install postfix dovecot-core dovecot-imapd -y
```

### Step 4: Configure Postfix (SMTP Server)
1. Open the Postfix configuration file:
```bash
sudo nano /etc/postfix/main.cf
```
2. Add or modify the following lines:
```
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
inet_interfaces = all
mydestination = localhost
mynetworks = 127.0.0.0/8
relayhost =
```
3. Save and exit (Press `CTRL + X`, then `Y`, then `ENTER`).

### Step 5: Restart and Enable Postfix
```bash
sudo systemctl restart postfix
sudo systemctl enable postfix
```

### Step 6: Configure Firewall
Allow SMTP traffic through the firewall:
```bash
sudo ufw allow 25
sudo ufw allow 587
sudo ufw allow 465
sudo ufw enable
```

## 2. Verifying Emails Without Sending an Actual Email

### How It Works
1. **Lookup the recipient domain's MX records** to find the mail server.
2. **Connect to the mail server using SMTP**.
3. **Use the `RCPT TO` command** to check if the email exists (without sending an email).

### Implementation in Python

```python
import asyncio
import aiosmtplib
import aiodns
import json
import logging
from async_timeout import timeout
from email_validator import validate_email, EmailNotValidError
from typing import Optional

# Configure logging
logger = logging.getLogger("smtp_verifier")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '{"time": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
))
logger.addHandler(handler)

class SMTPEmailVerifier:
    def __init__(self, timeout: int = 10, retries: int = 3):
        self.timeout = timeout
        self.retries = retries
        self.dns_resolver = aiodns.DNSResolver()

    async def get_mx_records(self, domain: str):
        try:
            records = await self.dns_resolver.query(domain, 'MX')
            return sorted([r.host for r in records], key=lambda x: x.priority)
        except Exception as e:
            logger.error(json.dumps({"event": "mx_lookup_failed", "domain": domain, "error": str(e)}))
            return []

    async def verify_email(self, email: str) -> bool:
        try:
            valid_email = validate_email(email, check_deliverability=False)
            domain = valid_email.domain
            mx_hosts = await self.get_mx_records(domain)
            if not mx_hosts:
                return False

            for mx_host in mx_hosts:
                for attempt in range(self.retries + 1):
                    try:
                        async with timeout(self.timeout):
                            smtp = aiosmtplib.SMTP(hostname=mx_host, port=25)
                            await smtp.connect()
                            await smtp.helo()
                            code, _ = await smtp.mail("verify@example.org")
                            code, _ = await smtp.rcpt(email)
                            await smtp.quit()
                            return code == 250
                    except Exception as e:
                        await asyncio.sleep(2 ** attempt)
            return False
        except EmailNotValidError:
            return False

# Usage Example
def verify_single_email(email: str) -> bool:
    verifier = SMTPEmailVerifier()
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(verifier.verify_email(email))

if __name__ == "__main__":
    test_email = "example@gmail.com"
    result = verify_single_email(test_email)
    print(f"Email: {test_email}, Valid: {result}")
```

## 3. Conclusion
By setting up your **own SMTP server on Vultr**, you gain **full control** over email verification. This approach allows you to check if an email exists **without sending an actual email**, reducing spam risk and ensuring high deliverability rates. 🚀
