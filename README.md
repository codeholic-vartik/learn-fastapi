```py
import smtplib
import dns.resolver

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return str(answers[0].exchange)
    except Exception as e:
        return None

def verify_email(email):
    domain = email.split('@')[-1]
    mx_record = get_mx_record(domain)

    if not mx_record:
        return False  # No mail server found

    try:
        server = smtplib.SMTP(mx_record, 25, timeout=5)
        server.helo()
        server.mail(email)  # Use a relay email here
        code, message = server.rcpt(email)
        print(code)
        server.quit()

        return code == 250  # 250 means email exists
    except:
        return False  # Could not verify

# Test the function
email = "codeholic.ritin@gmail.com"
print(verify_email(email))  # True if email exists, False if not

```


# Step-by-Step Guide: Setting Up an SMTP Server on Vultr and Verifying Emails Without Sending

## 1. Setting Up an SMTP Server on Vultr

### Step 1: Deploy a Vultr VPS
- Sign up at [Vultr](https://www.vultr.com/).
- Deploy a **Cloud Compute Instance** with **Ubuntu 22.04** or another Linux distribution.
- Choose at least **2GB RAM** for better performance.

### Step 2: Update and Install Required Packages
SSH into your Vultr server and run:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install postfix dovecot-core dovecot-imapd -y
```

### Step 3: Configure Postfix (SMTP Server)
- Open the Postfix config:
```bash
sudo nano /etc/postfix/main.cf
```
- Add or update these lines:
```
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
inet_interfaces = all
mydestination = localhost
mynetworks = 127.0.0.0/8
relayhost =
```
- Save and exit (CTRL + X, then Y, then ENTER).

### Step 4: Restart Postfix
```bash
sudo systemctl restart postfix
sudo systemctl enable postfix
```

### Step 5: Configure Firewall
- Allow SMTP traffic:
```bash
sudo ufw allow 25
sudo ufw allow 587
sudo ufw allow 465
sudo ufw enable
```

## 2. Preventing IP Blocks When Verifying Emails

### Why Can Your SMTP Server Get Blocked?
If you verify too many emails too quickly, email providers may block your IP. Here’s how to avoid that:

- **Excessive Lookups:** Avoid verifying too many emails in a short time.
- **Frequent Failed Verifications:** Too many invalid email checks may get flagged.
- **Reverse DNS (rDNS) Issues:** Ensure your **PTR record** is set correctly.
- **Not on an Allowed IP List:** Some email providers restrict access to known sources.

### Best Practices to Protect Your SMTP Server

✅ **Set Up Reverse DNS (PTR Record)**
- Configure it on your **Vultr dashboard → Networking → Reverse DNS**.
- Set your **PTR record** to match your SMTP domain (e.g., `mail.yourdomain.com`).

✅ **Throttle Verification Requests**
- Add **random delays** between requests (`1-5 sec`).
- Use an **exponential backoff strategy** (retry slowly after failures).

✅ **Rotate Multiple IPs**
- Use **multiple SMTP servers** if possible.
- Assign multiple IP addresses to your server and **rotate them**.

✅ **Monitor Your SMTP Server Health**
- Check **if your IP is blacklisted**: [MXToolbox Blacklist Check](https://mxtoolbox.com/blacklists.aspx).
- Track your SMTP logs (`/var/log/mail.log`) for **rejections and errors**.

✅ **Use SOCKS5 Proxies for Extra Safety**
- Rotate proxies to avoid direct SMTP connections from your IP.

## 3. Verifying Emails Without Sending an Actual Email (with Proxy Rotation)

### How It Works
1. Look up the recipient domain's **MX records**.
2. Connect to the mail server using **SMTP**.
3. Use the `RCPT TO` command to check if the email exists (without sending an email).
4. Rotate through proxies to avoid detection.

### Implementation in Python

```python
import asyncio
import aiosmtplib
import aiodns
import aiosocks
import json
import logging
import random
from async_timeout import timeout
from email_validator import validate_email, EmailNotValidError
from typing import Optional, List

# Configure logging
logger = logging.getLogger("smtp_verifier")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '{"time": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
))
logger.addHandler(handler)

class SMTPEmailVerifier:
    def __init__(self, proxy_list: Optional[List[str]] = None, timeout: int = 10, retries: int = 3):
        self.timeout = timeout
        self.retries = retries
        self.dns_resolver = aiodns.DNSResolver()
        self.proxy_list = proxy_list or []
        self.proxy_index = 0

    def get_next_proxy(self) -> Optional[str]:
        if not self.proxy_list:
            return None
        self.proxy_index = (self.proxy_index + 1) % len(self.proxy_list)
        return self.proxy_list[self.proxy_index]

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
                    proxy = self.get_next_proxy()
                    try:
                        async with timeout(self.timeout):
                            smtp = aiosmtplib.SMTP(hostname=mx_host, port=25)
                            if proxy:
                                smtp = aiosmtplib.SMTP(proxy=proxy)
                            await smtp.connect()
                            await smtp.helo()
                            code, _ = await smtp.mail("verify@example.org")
                            code, _ = await smtp.rcpt(email)
                            await smtp.quit()
                            return code == 250
                    except Exception:
                        await asyncio.sleep(2 ** attempt)
            return False
        except EmailNotValidError:
            return False

# Usage Example
def verify_single_email(email: str, proxy_list: List[str] = None) -> bool:
    verifier = SMTPEmailVerifier(proxy_list=proxy_list)
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(verifier.verify_email(email))

if __name__ == "__main__":
    test_email = "example@gmail.com"
    proxies = ["socks5://proxy1:1080", "socks5://proxy2:1080"]
    result = verify_single_email(test_email, proxies)
    print(f"Email: {test_email}, Valid: {result}")
```

## 4. Conclusion
By setting up your **own SMTP server on Vultr**, you gain **full control** over email verification. This guide includes **proxy rotation** to avoid IP blocks and ensures safer email validation without sending real emails. 🚀
