import re

class Sanitization:
    """
    Utility class to sanitize names for different environments
    by removing or replacing invalid characters.
    """

    @staticmethod
    def standard(value: str) -> str:
        """
        Sanitize a string to conform to the following rules:
        - Must be 3-24 characters long
        - Must start with a letter
        - Must end with a letter or digit
        - Only lowercase alphanumeric and hyphens allowed
        - No consecutive hyphens

        Args:
            value (str): Raw input string

        Returns:
            str: Sanitized string
        """
        if not isinstance(value, str):
            raise TypeError("Sanitization.standard: input must be a string")

        # Lowercase and replace invalid characters with hyphens
        value = re.sub(r"[^a-z0-9\-]", "-", value.lower())

        # Remove consecutive hyphens
        value = re.sub(r"-{2,}", "-", value)

        # Strip hyphens from beginning and end
        value = value.strip("-")

        # Ensure it starts with a letter
        if not value or not value[0].isalpha():
            value = "a" + value

        # Ensure it ends with a letter or digit
        if not value[-1].isalnum():
            value = value + "0"

        # Enforce length constraints
        if len(value) < 3:
            value += "xyz"[:3 - len(value)]
        elif len(value) > 24:
            value = value[:24]

        return value

    @staticmethod
    def purge(secret_key: str) -> str:
        """
        Purges a secret key by removing everything except alphanumeric characters (a-z, A-Z, 0-9),
        and converts all characters to lowercase.

        Args:
            secret_key (str): The secret name to be sanitized.

        Returns:
            str: The sanitized and lowercase secret name.
        """
        # Remove any character that is not alphanumeric and convert to lowercase
        sanitized_key = re.sub(r'[^a-zA-Z0-9]', '', secret_key).lower()
        return sanitized_key

purge = Sanitization.purge