import requests
from typing import List, Optional

class DisposableDomains:
    """
    Utility class to check if an email domain is disposable.
    Combines both strict and normal lists of disposable domains for comprehensive checking.
    """

    def __init__(self):
        """
        Initialize the DisposableDomains utility.
        Fetches both strict and normal lists of disposable domains.
        """
        self.strict_url = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_strict.txt"
        self.normal_url = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt"
        self.domains: List[str] = self._fetch_and_combine_domains()

    def _fetch_and_combine_domains(self) -> List[str]:
        """
        Fetch both strict and normal lists of disposable domains,
        combine them, remove duplicates, and sort the list.
        :return: Sorted list of unique disposable domains.
        """
        try:
            # Fetch strict list
            strict_response = requests.get(self.strict_url)
            strict_response.raise_for_status()
            strict_domains = strict_response.text.splitlines()

            # Fetch normal list
            normal_response = requests.get(self.normal_url)
            normal_response.raise_for_status()
            normal_domains = normal_response.text.splitlines()

            # Combine, remove duplicates, and sort
            combined_domains = list(set(strict_domains + normal_domains))  # Remove duplicates
            combined_domains.sort()  # Sort alphabetically

            return combined_domains
        except requests.RequestException as e:
            print(f"Failed to fetch disposable domains: {e}")
            return []

    def is_disposable_email(self, email: str) -> bool:
        """
        Check if the domain of a given email is disposable.
        :param email: The email address to check (e.g., "test@mailinator.com").
        :return: True if the email domain is disposable, False otherwise.
        """
        try:
            # Extract the domain from the email
            domain = email.split('@')[1].lower()
            return domain in self.domains
        except IndexError:
            # Invalid email format (no '@' symbol)
            print(f"Invalid email format: {email}")
            return False