FROM mcr.microsoft.com/azure-cli
WORKDIR /app
CMD ["sh", "-c", "az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID && tail -f /dev/null"]
