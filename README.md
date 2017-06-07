# GetSecretFromKeyVaultViaRest

## What is this?

A simple proof of concept that covers how to Authenticate to the Azure Rest API using an AD Application and Certificate Authentication and then get a secret from a Key Vault

## Wouldn't it be easier to just use the Client API?

Indeed it would. We needed to do this for reasons that I won't go into here!

## What do I need to make this run?
* An Azure keyvault
* A .p12 file containing your secret and public key
* A Application Id set up and the certificate added (Follow the steps here: https://blogs.msdn.microsoft.com/adrianpadilla/2016/03/31/certificate-authentication-into-azure-key-vault/, note that you will need extract your public key to a .cer file).
* A secrets.config file containing file following: -

```
<?xml version="1.0" encoding="utf-8" ?>
<appSettings>
  <add key="AppClientId" value="your app id"/>
  <add key="TenantId" value="your tenant id"/>
  <add key="CertPassword" value="the password for you .p12 file"/>
  <add key="CertFile" value="the path to your .p12 file"/>
  <add key="KeyVaultName" value="the name of your keyvault"/>
  <add key="SecretName" value="the name of the secret you want to get"/>
</appSettings>
```
