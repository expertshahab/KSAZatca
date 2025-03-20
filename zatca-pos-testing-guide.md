# ZATCA POS Testing Guide

This guide will walk you through the steps to test your ZATCA Phase 2 compliant API implementation using the POS testing tool.

## Step 1: Setup

1. Create a new .NET Core console application project
2. Copy the provided code into your project
3. Add the required NuGet packages:
   ```
   Microsoft.Extensions.Hosting
   Microsoft.Extensions.Configuration
   Microsoft.Extensions.Configuration.Json
   Microsoft.Extensions.Configuration.CommandLine
   Microsoft.Extensions.Configuration.EnvironmentVariables
   Microsoft.Extensions.DependencyInjection
   Microsoft.Extensions.Http
   Microsoft.Extensions.Logging
   System.CommandLine
   System.CommandLine.Hosting
   ```
4. Copy the `appsettings.json` file to your project and ensure it's set to copy to the output directory
5. Build the project

## Step 2: Create API User

Before using the POS system, you need to create a user in your API:

1. Using a tool like Postman, create a user by sending a POST request to `/api/auth/register`
2. Use an admin account with the appropriate privileges to create the user
3. Save the credentials for logging in through the POS system

## Step 3: Login

After building the POS system, log in to establish a connection with your API:

```
.\ZatcaPosSystem.exe login --username admin --password YourPassword
```

This will save the authentication token to your `appsettings.json` file.

## Step 4: Device Registration Process

Follow these steps to register a device with ZATCA:

### 1. Register a device

```
.\ZatcaPosSystem.exe register --serialNumber "POS123456" --deviceName "Test POS" --model "Model X1" --vatNumber "123456789012345" --companyName "Test Company LLC" --crnNumber "1234567890" --streetName "King Fahd Road" --buildingNumber "1234" --cityName "Riyadh" --districtName "Al Olaya" --postalCode "12345"
```

### 2. Generate a CSR (Certificate Signing Request)

```
.\ZatcaPosSystem.exe generatecsr --serialNumber "POS123456"
```

### 3. Request a compliance certificate

```
.\ZatcaPosSystem.exe compliance --serialNumber "POS123456"
```

### 4. Get an OTP from ZATCA portal

For the sandbox environment:
1. Login to the ZATCA portal at https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx
2. Navigate to the sandbox testing area
3. Register for sandbox testing and get an OTP

### 5. Request a production certificate using the OTP

```
.\ZatcaPosSystem.exe production --serialNumber "POS123456" --otp "123456"
```

## Step 5: Create and Report Invoices

Now that your device is registered and has a valid certificate, you can create invoices:

### Create a standard B2B invoice

```
.\ZatcaPosSystem.exe invoice --serialNumber "POS123456" --invoiceNumber "INV-001" --buyerName "Buyer Company LLC" --buyerVat "311111111111113" --totalAmount 1000 --vatRate 15 --type "standard"
```

### Create a simplified invoice

```
.\ZatcaPosSystem.exe invoice --serialNumber "POS123456" --invoiceNumber "INV-002" --buyerName "Individual Consumer" --buyerVat "300000000000003" --totalAmount 100 --vatRate 15 --type "simplified"
```

### Create a credit note

```
.\ZatcaPosSystem.exe creditnote --serialNumber "POS123456" --creditNoteNumber "CN-001" --relatedInvoice "INV-001" --buyerName "Buyer Company LLC" --buyerVat "311111111111113" --totalAmount 200 --vatRate 15 --type "standard"
```

## Step 6: Check Invoice Status

Check the compliance status of a previously submitted invoice:

```
.\ZatcaPosSystem.exe check --serialNumber "POS123456" --uuid "your-invoice-uuid"
```

## Step 7: List Devices

View all registered devices:

```
.\ZatcaPosSystem.exe devices
```

## Troubleshooting

### Connection Issues

- Ensure your API is running and accessible at the URL specified in `appsettings.json`
- Check that your authentication token is valid and not expired
- Verify firewall settings allow the application to communicate with your API

### Certificate Issues

- If you encounter certificate errors, ensure your API is correctly implementing the ZATCA cryptographic requirements
- Check that the CSR generation process is working correctly in your API

### Invoice Reporting Issues

- If invoice reporting fails, check the validation errors returned by your API
- Ensure your invoice data follows the ZATCA format requirements
- Verify that the device has an active production certificate

## Using With ZATCA Sandbox

To test with the official ZATCA sandbox environment:

1. Update the `ZatcaApi:BaseUrl` in `appsettings.json` to point to your API implementation
2. Register your API with the ZATCA sandbox portal
3. Follow the onboarding process provided by ZATCA
4. Use this POS system to verify that your API correctly communicates with ZATCA sandbox

## Production Deployment

Before moving to production:

1. Thoroughly test all aspects of the e-invoicing process with the sandbox
2. Verify QR code generation and validation
3. Test the clearance process for B2B invoices
4. Test the reporting process for simplified invoices
5. Ensure proper error handling and logging

Once fully tested with the sandbox, you can update your API to point to the ZATCA production endpoints and use this POS system to verify the integration.
