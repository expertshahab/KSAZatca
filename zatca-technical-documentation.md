# ZATCA Phase 2 API - Technical Implementation & Rollout Guide

## Table of Contents

1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [API Specifications](#api-specifications)
4. [Security Implementation](#security-implementation)
5. [Certificate Management](#certificate-management)
6. [Invoice Generation & Submission](#invoice-generation--submission)
7. [Sandbox Implementation](#sandbox-implementation)
8. [Production Rollout](#production-rollout)
9. [Monitoring & Maintenance](#monitoring--maintenance)
10. [Appendices](#appendices)

---

## 1. Introduction

### 1.1 Purpose

This technical document provides comprehensive implementation details for the ZATCA Phase 2 e-invoicing API. It serves as a guide for technical teams implementing the API, with detailed instructions for both sandbox testing and production deployment.

### 1.2 Scope

The document covers:
- System architecture and design
- API endpoints and functionality
- Security implementation
- Certificate management
- Invoice generation and submission
- Testing in the ZATCA sandbox environment
- Production rollout procedures
- Monitoring and maintenance

### 1.3 References

- [ZATCA E-Invoicing Portal](https://zatca.gov.sa/en/E-Invoicing/Pages/default.aspx)
- [ZATCA E-Invoicing Technical Specifications](https://zatca.gov.sa/en/E-Invoicing/Introduction/Pages/Technical-Specifications.aspx)
- [UBL 2.1 Standard](http://docs.oasis-open.org/ubl/UBL-2.1.html)
- [XML Digital Signatures](https://www.w3.org/TR/xmldsig-core1/)

---

## 2. System Architecture

### 2.1 Overall Architecture

The ZATCA Phase 2 API implementation follows a microservices-based architecture, with distinct services for:

1. **Authentication Service**: Manages user authentication and authorization
2. **Device Service**: Handles device registration and certificate management
3. **Invoice Service**: Manages invoice generation, signing, and submission
4. **Compliance Service**: Handles compliance validation and status checking

![System Architecture Diagram](https://example.com/architecture-diagram.png)

### 2.2 Technology Stack

- **Framework**: .NET Core 6.0
- **Database**: SQL Server 2019
- **Authentication**: JWT Bearer Token
- **Cryptography**: OpenSSL for certificate operations
- **XML Processing**: .NET XML libraries with XPath and XSLT
- **API Documentation**: Swagger/OpenAPI
- **Logging**: Serilog with structured logging
- **Monitoring**: Application Insights

### 2.3 Data Flow

1. **Device Registration Flow**:
   - Client application registers device
   - System generates CSR
   - System submits CSR to ZATCA
   - ZATCA issues compliance certificate
   - User obtains OTP from ZATCA portal
   - System requests production certificate using OTP
   - ZATCA issues production certificate
   - System stores certificate securely

2. **Invoice Submission Flow**:
   - Client generates invoice data
   - System creates UBL 2.1 XML
   - System validates XML against schema
   - System calculates invoice hash
   - System signs XML with device certificate
   - System generates QR code
   - System submits to ZATCA (clearance or reporting)
   - System stores results and updates status

---

## 3. API Specifications

### 3.1 Base URLs

- **Development**: `https://dev-api.example.com/zatca/v1`
- **Sandbox**: `https://sandbox-api.example.com/zatca/v1`
- **Production**: `https://api.example.com/zatca/v1`

### 3.2 Authentication Endpoints

#### 3.2.1 Login

- **Endpoint**: `POST /api/auth/login`
- **Description**: Authenticates user and returns JWT token
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response**:
  ```json
  {
    "token": "string",
    "expiration": "2023-01-01T12:00:00Z",
    "username": "string",
    "role": "string"
  }
  ```

#### 3.2.2 Register User

- **Endpoint**: `POST /api/auth/register`
- **Description**: Registers a new user (admin only)
- **Authentication**: Bearer Token (Admin role)
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string",
    "email": "string",
    "companyName": "string",
    "vatRegistrationNumber": "string",
    "role": "User"
  }
  ```
- **Response**:
  ```json
  {
    "username": "string",
    "email": "string",
    "role": "string"
  }
  ```

### 3.3 Device Management Endpoints

#### 3.3.1 Register Device

- **Endpoint**: `POST /api/devices/register`
- **Description**: Registers a new device
- **Authentication**: Bearer Token
- **Request Body**:
  ```json
  {
    "deviceSerialNumber": "string",
    "deviceName": "string",
    "model": "string",
    "hardwareVersion": "string",
    "softwareVersion": "string",
    "vatRegistrationNumber": "string",
    "companyName": "string",
    "commercialRegistrationNumber": "string",
    "streetName": "string",
    "buildingNumber": "string",
    "cityName": "string",
    "districtName": "string",
    "postalCode": "string",
    "countryCode": "SA",
    "certificateType": "Compliance"
  }
  ```
- **Response**:
  ```json
  {
    "zatcaDeviceId": "string",
    "zatcaDeviceToken": "string",
    "registrationDate": "2023-01-01T12:00:00Z",
    "status": "Success",
    "message": "string"
  }
  ```

#### 3.3.2 Get Device

- **Endpoint**: `GET /api/devices/{serialNumber}`
- **Description**: Gets device details by serial number
- **Authentication**: Bearer Token
- **Response**:
  ```json
  {
    "id": 0,
    "deviceSerialNumber": "string",
    "deviceName": "string",
    "model": "string",
    "status": "Active",
    "vatRegistrationNumber": "string",
    "companyName": "string",
    "registrationDate": "2023-01-01T12:00:00Z",
    "certificateExpiryDate": "2024-01-01T12:00:00Z",
    "certificateType": "Production"
  }
  ```

#### 3.3.3 Generate CSR

- **Endpoint**: `POST /api/devices/{serialNumber}/generatecsr`
- **Description**: Generates a CSR for the device
- **Authentication**: Bearer Token
- **Response**:
  ```json
  {
    "message": "CSR generated successfully"
  }
  ```

#### 3.3.4 Request Compliance Certificate

- **Endpoint**: `POST /api/devices/{serialNumber}/compliancecertificate`
- **Description**: Requests a compliance certificate from ZATCA
- **Authentication**: Bearer Token
- **Response**:
  ```json
  {
    "message": "Compliance certificate requested successfully"
  }
  ```

#### 3.3.5 Request Production Certificate

- **Endpoint**: `POST /api/devices/{serialNumber}/productioncertificate`
- **Description**: Requests a production certificate using an OTP
- **Authentication**: Bearer Token
- **Request Body**:
  ```json
  "123456"
  ```
- **Response**:
  ```json
  {
    "message": "Production certificate requested successfully"
  }
  ```

### 3.4 Invoice Management Endpoints

#### 3.4.1 Report Invoice

- **Endpoint**: `POST /api/invoices/report`
- **Description**: Reports a standard invoice to ZATCA
- **Authentication**: Bearer Token
- **Request Body**:
  ```json
  {
    "deviceSerialNumber": "string",
    "documentNumber": "string",
    "documentDate": "2023-01-01T12:00:00Z",
    "documentIssueTime": "2023-01-01T12:00:00Z",
    "sellerName": "string",
    "sellerVatNumber": "string",
    "sellerStreetName": "string",
    "sellerBuildingNumber": "string",
    "sellerCityName": "string",
    "sellerPostalCode": "string",
    "sellerDistrictName": "string",
    "sellerCountryCode": "SA",
    "buyerName": "string",
    "buyerVatNumber": "string",
    "buyerStreetName": "string",
    "buyerBuildingNumber": "string",
    "buyerCityName": "string",
    "buyerPostalCode": "string",
    "buyerDistrictName": "string",
    "buyerCountryCode": "SA",
    "totalAmount": 0,
    "totalWithoutVat": 0,
    "vatAmount": 0,
    "discount": 0,
    "invoiceType": 0,
    "transactionType": 0,
    "invoiceCurrency": "SAR",
    "paymentMethod": "CASH",
    "lineItems": [
      {
        "lineNumber": 0,
        "itemName": "string",
        "itemDescription": "string",
        "quantity": 0,
        "unitOfMeasure": "EA",
        "unitPrice": 0,
        "netAmount": 0,
        "vatRate": 0,
        "vatAmount": 0,
        "totalAmount": 0,
        "discountAmount": 0,
        "discountPercentage": 0
      }
    ],
    "generateXml": true
  }
  ```
- **Response**:
  ```json
  {
    "zatcaReportId": "string",
    "status": "Success",
    "qrCode": "string",
    "validationResults": "string",
    "complianceStatus": "string",
    "message": "string",
    "invoiceHash": "string",
    "clearanceStatus": "Cleared",
    "uuid": "string",
    "validationWarnings": [
      {
        "code": "string",
        "message": "string",
        "category": "string",
        "status": "string"
      }
    ]
  }
  ```

#### 3.4.2 Report Credit Note

- **Endpoint**: `POST /api/invoices/creditnote`
- **Description**: Reports a credit note to ZATCA
- **Authentication**: Bearer Token
- **Request Body**: Same as invoice report with additional `relatedInvoiceNumber` field
- **Response**: Same as invoice report

#### 3.4.3 Generate Invoice XML

- **Endpoint**: `POST /api/invoices/generatexml`
- **Description**: Generates UBL 2.1 XML without submitting to ZATCA
- **Authentication**: Bearer Token
- **Request Body**: Same as invoice report
- **Response**:
  ```json
  {
    "invoiceXml": "string"
  }
  ```

#### 3.4.4 Validate Invoice

- **Endpoint**: `POST /api/invoices/validate`
- **Description**: Validates an invoice XML against ZATCA requirements
- **Authentication**: Bearer Token
- **Request Body**:
  ```json
  {
    "invoiceXml": "string",
    "deviceSerialNumber": "string"
  }
  ```
- **Response**:
  ```json
  {
    "validationResults": "string"
  }
  ```

---

## 4. Security Implementation

### 4.1 Authentication & Authorization

The API uses JWT (JSON Web Token) Bearer authentication:

1. **Token Generation**:
   - Tokens are generated during login
   - Tokens include user identity and roles
   - Tokens are signed with a secure key
   - Tokens expire after 1 hour

2. **Token Validation**:
   - All protected endpoints validate token authenticity
   - Claims are verified (issuer, audience, expiration)
   - Role-based authorization is enforced

3. **Password Security**:
   - Passwords are hashed using SHA-256
   - Passwords are never stored in plain text
   - Failed login attempts are rate-limited

### 4.2 API Security

1. **Transport Security**:
   - HTTPS is enforced for all endpoints
   - TLS 1.2 or higher is required
   - HSTS is enabled

2. **Request Validation**:
   - All inputs are validated
   - Content-Type validation is enforced
   - Request size limits are applied

3. **Response Security**:
   - Sensitive data is never returned in responses
   - Appropriate status codes are used
   - Error messages do not reveal system details

### 4.3 Certificate Security

1. **Private Key Protection**:
   - Private keys are stored securely
   - Keys are encrypted at rest
   - Keys are never exposed in responses

2. **Certificate Storage**:
   - Certificates are stored in a secure certificate store
   - Access to certificates is restricted
   - Certificate operations are logged

---

## 5. Certificate Management

### 5.1 CSR Generation

The system generates Certificate Signing Requests (CSRs) with:
- RSA-2048 key pair
- Organization details from device registration
- Common Name based on VAT registration number
- SHA-256 signature algorithm

```csharp
// Example CSR generation code
public async Task<string> GenerateCSRAsync(string commonName, string organizationName, string organizationUnit, string countryCode)
{
    using var rsa = RSA.Create(2048);
    var subjectName = new X500DistinguishedName($"CN={commonName}, O={organizationName}, OU={organizationUnit}, C={countryCode}");
    var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    
    // Add extensions if needed
    
    // Export the CSR in PEM format
    var csrBytes = request.CreateSigningRequest();
    return $"-----BEGIN CERTIFICATE REQUEST-----\n{Convert.ToBase64String(csrBytes)}\n-----END CERTIFICATE REQUEST-----";
}
```

### 5.2 Certificate Lifecycle

1. **Compliance Certificate**:
   - Obtained during initial registration
   - Valid for 1 year
   - Used for testing and onboarding

2. **Production Certificate**:
   - Obtained using OTP from ZATCA portal
   - Valid for 3 years
   - Used for production invoices

3. **Certificate Renewal**:
   - System monitors certificate expiration
   - Renewal process starts 30 days before expiration
   - New CSR is generated
   - Renewal request is sent to ZATCA

### 5.3 Certificate Operations

1. **Signing Operations**:
   - Invoices are signed using the device's certificate
   - XML Digital Signature is applied
   - Signature includes the entire document
   - Canonicalization is applied before signing

2. **Verification Operations**:
   - Signatures are verified using ZATCA's public key
   - Certificate chain is validated
   - Certificate revocation status is checked

---

## 6. Invoice Generation & Submission

### 6.1 UBL 2.1 XML Generation

The system generates UBL 2.1 XML documents with:
- Required ZATCA namespaces
- Correct invoice type codes
- All mandatory fields
- Proper structure for extensions

```csharp
// Example XML generation (simplified)
public async Task<string> ConvertToUBLXmlAsync(InvoiceReportRequest request)
{
    var document = new XmlDocument();
    var declaration = document.CreateXmlDeclaration("1.0", "UTF-8", null);
    document.AppendChild(declaration);
    
    // Create root element with namespaces
    var rootElement = document.CreateElement("Invoice", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2");
    AddNamespaces(rootElement);
    document.AppendChild(rootElement);
    
    // Add UBL extensions for signature and QR code
    AddUBLExtensions(document, rootElement);
    
    // Add all required invoice elements
    AddInvoiceElements(document, rootElement, request);
    
    // Return as string
    using var writer = new StringWriter();
    using var xmlWriter = XmlWriter.Create(writer, new XmlWriterSettings { Indent = true });
    document.WriteTo(xmlWriter);
    xmlWriter.Flush();
    return writer.ToString();
}
```

### 6.2 QR Code Generation

The system generates QR codes in TLV (Tag-Length-Value) format with:
- Seller name (tag 1)
- VAT registration number (tag 2)
- Timestamp (tag 3)
- Invoice total with VAT (tag 4)
- VAT amount (tag 5)
- Invoice hash (tag 6)
- Digital signature (tag 7)

```csharp
// Example QR code generation
public byte[] GenerateTLVEncodedQR(Dictionary<int, string> qrData)
{
    using var memoryStream = new MemoryStream();
    
    foreach (var entry in qrData)
    {
        // Tag (1 byte)
        memoryStream.WriteByte((byte)entry.Key);
        
        // Value bytes
        var valueBytes = Encoding.UTF8.GetBytes(entry.Value);
        var length = valueBytes.Length;
        
        // Length (1 byte if length < 128, 2 bytes otherwise)
        if (length < 128)
        {
            memoryStream.WriteByte((byte)length);
        }
        else
        {
            memoryStream.WriteByte((byte)(0x80 | 1));
            memoryStream.WriteByte((byte)length);
        }
        
        // Value
        memoryStream.Write(valueBytes, 0, valueBytes.Length);
    }
    
    return memoryStream.ToArray();
}
```

### 6.3 Invoice Submission Processes

#### 6.3.1 Clearance Process (B2B Standard Invoices)

1. Client submits invoice data
2. System generates UBL 2.1 XML
3. System validates XML against schema
4. System signs XML with device certificate
5. System submits to ZATCA clearance API
6. ZATCA validates and clears the invoice
7. System stores clearance status and results

```csharp
// Example clearance process
public async Task<InvoiceReportResponse> ClearInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber)
{
    // Get device information
    var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
    
    // Prepare clearance request
    var signedInvoiceBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedInvoiceXml));
    var requestData = new
    {
        invoiceHash = CalculateHash(signedInvoiceXml),
        uuid = ExtractUUID(signedInvoiceXml),
        invoice = signedInvoiceBase64
    };
    
    // Call ZATCA API
    var response = await _httpClient.PostAsync(
        _configuration["ZatcaApi:ClearanceEndpoint"],
        new StringContent(JsonSerializer.Serialize(requestData), Encoding.UTF8, "application/json"));
    
    // Process response
    // ...
    
    return new InvoiceReportResponse { /* ... */ };
}
```

#### 6.3.2 Reporting Process (Simplified Invoices)

1. Client submits invoice data
2. System generates UBL 2.1 XML
3. System validates XML against schema
4. System signs XML with device certificate
5. System submits to ZATCA reporting API
6. ZATCA validates and records the invoice
7. System stores reporting status and results

---

## 7. Sandbox Implementation

### 7.1 Sandbox Environment Setup

1. **Configuration**:
   - Update `appsettings.json` to point to ZATCA sandbox URLs
   - Configure sandbox credentials
   - Set environment to "Sandbox"

```json
{
  "ZatcaApi": {
    "BaseUrl": "https://gw-fatoora-zatca-sandbox.portal.gov.sa/",
    "ComplianceCsrEndpoint": "...",
    "ProductionCsrEndpoint": "...",
    "ClearanceEndpoint": "...",
    "ReportingEndpoint": "..."
  },
  "Environment": "Sandbox"
}
```

2. **Sandbox Account Registration**:
   - Register on ZATCA portal for sandbox access
   - Obtain sandbox credentials
   - Configure API with sandbox credentials

### 7.2 Sandbox Testing Process

1. **Device Registration Testing**:
   - Register a test device
   - Generate CSR
   - Request compliance certificate
   - Get OTP from sandbox portal
   - Request production certificate

2. **Invoice Testing**:
   - Generate and submit test invoices
   - Test all invoice types (standard, simplified, credit/debit notes)
   - Verify clearance and reporting processes
   - Test error scenarios and validation errors

3. **Validation Testing**:
   - Test with valid and invalid invoices
   - Verify validation error handling
   - Test response to ZATCA validation warnings

### 7.3 Sandbox Test Cases

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TC-001 | Register device with valid details | Device registered successfully |
| TC-002 | Generate CSR for registered device | CSR generated successfully |
| TC-003 | Request compliance certificate | Certificate issued successfully |
| TC-004 | Request production certificate with valid OTP | Production certificate issued |
| TC-005 | Submit valid standard B2B invoice | Invoice cleared successfully |
| TC-006 | Submit valid simplified invoice | Invoice reported successfully |
| TC-007 | Submit valid credit note | Credit note processed successfully |
| TC-008 | Submit invoice with validation warnings | Invoice processed with warnings |
| TC-009 | Submit invalid invoice | Invoice rejected with validation errors |
| TC-010 | Check compliance status of submitted invoice | Status retrieved successfully |

---

## 8. Production Rollout

### 8.1 Pre-Production Checklist

1. **Compliance Verification**:
   - All sandbox tests passed
   - QR code validation successful
   - XML generation meets UBL 2.1 requirements
   - Digital signatures validated

2. **Performance Testing**:
   - Load testing completed
   - Performance meets requirements
   - Error handling verified

3. **Security Audit**:
   - Security audit completed
   - Certificate management reviewed
   - Authentication and authorization tested

### 8.2 Production Configuration

1. **Environment Configuration**:
   - Update `appsettings.json` to point to ZATCA production URLs
   - Configure production credentials
   - Set environment to "Production"

```json
{
  "ZatcaApi": {
    "BaseUrl": "https://gw-fatoora.zatca.gov.sa/",
    "ComplianceCsrEndpoint": "...",
    "ProductionCsrEndpoint": "...",
    "ClearanceEndpoint": "...",
    "ReportingEndpoint": "..."
  },
  "Environment": "Production"
}
```

2. **Production Certificate Management**:
   - Properly secure production certificates
   - Implement certificate monitoring
   - Set up renewal notifications

### 8.3 Rollout Strategy

1. **Phased Rollout**:
   - Start with a limited set of users/devices
   - Gradually increase usage
   - Monitor for issues

2. **Rollback Plan**:
   - Define criteria for rollback
   - Document rollback procedures
   - Test rollback scenarios

3. **Support Readiness**:
   - Train support team
   - Prepare troubleshooting guides
   - Establish escalation procedures

### 8.4 Go-Live Procedure

1. **Infrastructure Deployment**:
   - Deploy API to production environment
   - Configure firewalls and security
   - Verify connectivity to ZATCA

2. **Initial Device Registration**:
   - Register production devices
   - Obtain production certificates
   - Verify certificate validity

3. **Initial Transaction Processing**:
   - Process initial set of invoices
   - Verify end-to-end functionality
   - Monitor for issues

4. **Full Deployment**:
   - Enable for all users
   - Monitor system performance
   - Provide support as needed

---

## 9. Monitoring & Maintenance

### 9.1 Performance Monitoring

1. **Key Metrics**:
   - API response time
   - Error rates
   - Certificate expiration
   - Invoice submission success rates

2. **Alerting**:
   - Set up alerts for critical failures
   - Configure certificate expiration alerts
   - Monitor ZATCA API availability

### 9.2 Log Management

1. **Logging Strategy**:
   - Implement structured logging
   - Log all API calls and responses
   - Log certificate operations
   - Log invoice submission and status

2. **Log Retention**:
   - Retain logs for compliance purposes
   - Implement log rotation
   - Secure access to logs

### 9.3 Regular Maintenance

1. **Certificate Maintenance**:
   - Monitor certificate expiration
   - Renew certificates before expiration
   - Verify certificate validity

2. **System Updates**:
   - Update dependencies regularly
   - Apply security patches
   - Test updates in a staging environment

3. **ZATCA Compliance Updates**:
   - Monitor ZATCA announcements
   - Implement required changes
   - Test compliance updates

---

## 10. Appendices

### 10.1 Error Codes and Handling

| Error Code | Description | Handling Strategy |
|------------|-------------|-------------------|
| AUTH001 | Authentication failed | Retry with valid credentials |
| AUTH002 | Token expired | Obtain new token |
| DEV001 | Device not found | Verify device serial number |
| DEV002 | CSR generation failed | Check device configuration |
| CERT001 | Certificate request failed | Verify CSR and retry |
| CERT002 | Invalid OTP | Obtain new OTP from ZATCA portal |
| INV001 | Invoice validation failed | Fix validation errors and retry |
| INV002 | Clearance failed | Check error details and retry |
| API001 | ZATCA API unavailable | Retry with exponential backoff |

### 10.2 XML Schema References

- UBL 2.1 Invoice Schema: `http://docs.oasis-open.org/ubl/os-UBL-2.1/xsd/maindoc/UBL-Invoice-2.1.xsd`
- ZATCA Extensions Schema: `https://zatca.gov.sa/e-invoicing/schemas/zatca-extensions.xsd`

### 10.3 ZATCA API Reference

- Sandbox Base URL: `https://gw-fatoora-zatca-sandbox.portal.gov.sa/`
- Production Base URL: `https://gw-fatoora.zatca.gov.sa/`

| Endpoint | Description | HTTP Method |
|----------|-------------|------------|
| `/compliance` | Request compliance certificate | POST |
| `/production` | Request production certificate | POST |
| `/clearance` | Clear B2B invoice | POST |
| `/reporting` | Report simplified invoice | POST |
| `/status` | Check invoice status | GET |

### 10.4 Sample Requests and Responses

#### Sample CSR Request

```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...AAAA\n-----END CERTIFICATE REQUEST-----",
  "taxpayerVatId": "123456789012345",
  "taxpayerName": "Test Company LLC",
  "taxpayerCRN": "1234567890"
}
```

#### Sample Standard Invoice Clearance Response

```json
{
  "clearanceStatus": "CLEARED",
  "reportId": "BR-f9e9ba5c-91f3-4c30-9e9b-a5c91f36c307",
  "uuid": "1ec26c6e-1713-4a38-bd43-48a8eb926c6c",
  "status": "SUCCESS",
  "clearedInvoiceXmlUrl": "https://example.com/invoice123.xml",
  "validationResults": [
    {
      "code": "WARNING1001",
      "message": "Optional field missing",
      "category": "warning",
      "status": "WARNING"
    }
  ]
}
```

### 10.5 Implementation Checklist

- [ ] Authentication service implemented
- [ ] Device registration flow implemented
- [ ] CSR generation implemented
- [ ] Certificate management implemented
- [ ] XML generation implemented
- [ ] Digital signature implemented
- [ ] QR code generation implemented
- [ ] Invoice clearance implemented
- [ ] Invoice reporting implemented
- [ ] Error handling implemented
- [ ] Logging implemented
- [ ] Monitoring implemented
- [ ] Sandbox testing completed
- [ ] Production configuration prepared
- [ ] Rollout plan prepared
- [ ] Support documents prepared
