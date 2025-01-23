from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from validate_email import validate_email
from ipaddress import IPv4Address, IPv6Address
from dns_smtp_email_validator import DNSSMTPEmailValidator
import freemail
# Create FastAPI instance
app = FastAPI()

# Define the request body using Pydantic


class EmailRequest(BaseModel):
    email_address: str


@app.post("/validate_email/")
async def validate_user_email(payload: EmailRequest):
    try:
        # validator = DNSSMTPEmailValidator(email=payload.email_address)
        # if not validator.is_valid():
        #     # Extract error messages
        #     error_messages = [
        #         f"{error['message']}" for error in validator.errors]
        #     raise HTTPException(
        #         status_code=400,
        #         detail=f"Invalid email address: {
        #             ', '.join(error_messages)}"  # Join error messages
        #     )

        # Use the validate_email function with the necessary parameters
        is_valid = validate_email(
            email_address=payload.email_address,
            check_format=True,
            check_blacklist=True,
            check_dns=True,
            dns_timeout=10,
            check_smtp=True,
            smtp_timeout=10,
            smtp_helo_host='my.host.name',
            smtp_from_address='my@from.addr.ess',
            smtp_skip_tls=False,
            smtp_tls_context=None,
            smtp_debug=False,
            address_types=frozenset([IPv4Address, IPv6Address])
        )
        is_free = freemail.is_disposable(payload.email_address)
        is_disposable = freemail.is_disposable(payload.email_address)
        if is_valid:
            return {"status": "success", "message": "Email is valid", "data": is_valid, "is_free": is_free, "is_disposable": is_disposable}
        else:
            return {"status": "failure", "message": "Email is invalid"}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error validating email: {str(e)}")

# Run the app with Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
