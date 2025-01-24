from app.core.disposable_domains import DisposableDomains

# Use the default GitHub repository (strict mode)
disposable_checker = DisposableDomains()
# leheqodi@thetechnext.net  tokodi8328@dfesc.com

email = "leheqodi@thetechnext.net"
if disposable_checker.is_disposable_email(email):
    print(f"{email} is a disposable email.")
else:
    print(f"{email} is not a disposable email.")