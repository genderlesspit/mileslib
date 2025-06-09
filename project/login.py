import dataclasses

class Login:
    from msal import ConfidentialClientApplication

    user  = ConfidentialClientApplication(
        client_id="your-client-id",
        authority="https://login.microsoftonline.com/<TENANT_ID>",
        client_credential="your-client-secret"
    )

result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])