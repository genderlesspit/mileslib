import re

class Sanitization:
    """
    Utility class to sanitize names for different environments
    by removing or replacing invalid characters.
    """

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