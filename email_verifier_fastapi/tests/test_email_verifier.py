from app.core.disposable_domains import DisposableDomains

# Use the default GitHub repository (strict mode)
disposable_checker = DisposableDomains()

email = "mailvartik@gmailð.com"
if disposable_checker.is_disposable_email(email):
    print(f"{email} is a disposable email.")
else:
    print(f"{email} is not a disposable email.")