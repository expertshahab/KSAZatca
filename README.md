# ZATCA Phase 2 E-Invoicing API

A comprehensive .NET Core implementation for ZATCA (Zakat, Tax and Customs Authority) Phase 2 e-invoicing compliance in Saudi Arabia.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET Core](https://img.shields.io/badge/.NET%20Core-6.0-blue)](https://dotnet.microsoft.com/download/dotnet/6.0)

## Overview

This solution provides a complete implementation of the ZATCA Phase 2 e-invoicing requirements for businesses operating in Saudi Arabia. It includes all necessary components for device registration, certificate management, invoice generation, signing, QR code creation, and submission to ZATCA.

### Key Features

- **Complete ZATCA Phase 2 Compliance**: Supports standard invoices, simplified invoices, credit notes, debit notes, and sales returns
- **Device Management**: Full device lifecycle management with secure certificate handling
- **UBL 2.1 XML Generation**: Generates fully compliant XML documents according to ZATCA specifications
- **Digital Signature Implementation**: Implements XML digital signatures using cryptographic standards
- **QR Code Generation**: Creates TLV-formatted QR codes as required by ZATCA
- **Secure JWT Authentication**: Protects API endpoints with role-based security
- **Comprehensive Validation**: Validates documents against ZATCA business rules
- **Error Handling**: Detailed error reporting and handling for all operations
- **Swagger Documentation**: Complete API documentation with Swagger UI

## Architecture

The solution follows a modern, layered architecture:

- **Web API Layer**: ASP.NET Core Web API providing RESTful endpoints
- **Service Layer**: Core business logic implementing ZATCA requirements
- **Data Access Layer**: Entity Framework Core for database operations
- **Utilities Layer**: Common functions for cryptography, XML processing, etc.

## System Requirements

- **Runtime**: .NET Core 6.0 or higher
- **Database**: SQL Server 2019 or higher
- **OS**: Windows Server 2019/2022 or Linux (Ubuntu 20.04+)
- **Additional**: 
  - OpenSSL for certificate operations (Linux)
  - Internet connectivity to ZATCA API endpoints

## Getting Started

### Installation

#### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/zatca-phase2-api.git
cd zatca-phase2-api

# Build and run with Docker Compose
docker-compose up -d
```

#### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zatca-phase2-api.git
cd zatca-phase2-api

# Build the solution
dotnet build

# Run database migrations
dotnet ef database update

# Run the API
dotnet run --project src/ZatcaPhase2Api/ZatcaPhase2Api.csproj
```

### Configuration

The primary configuration file is `appsettings.json`. Configure it according to your environment:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=ZatcaPhase2;User=sa;Password=YourStrongPassword!;MultipleActiveResultSets=true"
  },
  "Jwt": {
    "Key": "your_secure_key_here_at_least_32_characters_long",
    "Issuer": "your_issuer",
    "Audience": "your_audience",
    "ExpiryMinutes": 60
  },
  "ZatcaApi": {
    "BaseUrl": "https://gw-fatoora-zatca-sandbox.portal.gov.sa/",
    "ComplianceCsrEndpoint": "compliance",
    "ProductionCsrEndpoint": "production",
    "ClearanceEndpoint": "clearance",
    "ReportingEndpoint": "reporting"
  },
  "Environment": "Sandbox"
}
```

For production, update the `ZatcaApi:BaseUrl` to the production endpoint and set `Environment` to "Production".

## Usage

### API Endpoints

The API provides the following main endpoint groups:

#### Authentication

- `POST /api/auth/login`: Authenticate and get a JWT token
- `POST /api/auth/register`: Register a new user (admin only)

#### Device Management

- `POST /api/devices/register`: Register a new device
- `GET /api/devices/{serialNumber}`: Get device details
- `GET /api/devices`: List all devices
- `POST /api/devices/{serialNumber}/generatecsr`: Generate CSR for a device
- `POST /api/devices/{serialNumber}/compliancecertificate`: Request compliance certificate
- `POST /api/devices/{serialNumber}/productioncertificate`: Request production certificate

#### Invoice Management

- `POST /api/invoices/report`: Report standard invoice to ZATCA
- `POST /api/invoices/creditnote`: Report credit note to ZATCA
- `POST /api/invoices/debitnote`: Report debit note to ZATCA
- `POST /api/invoices/salesreturn`: Report sales return to ZATCA
- `POST /api/invoices/generatexml`: Generate UBL 2.1 XML for an invoice
- `POST /api/invoices/validate`: Validate invoice XML against ZATCA requirements

### Usage Examples

#### Device Registration Flow

1. Register a device:
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '{
  "deviceSerialNumber": "POS123456",
  "deviceName": "Test POS",
  "model": "Model X1",
  "vatRegistrationNumber": "123456789012345",
  "companyName": "Test Company LLC",
  "commercialRegistrationNumber": "1234567890",
  "streetName": "King Fahd Road",
  "buildingNumber": "1234",
  "cityName": "Riyadh",
  "districtName": "Al Olaya",
  "postalCode": "12345"
}' https://your-api.com/api/devices/register
```

2. Generate CSR:
```bash
curl -X POST -H "Authorization: Bearer {token}" https://your-api.com/api/devices/POS123456/generatecsr
```

3. Request compliance certificate:
```bash
curl -X POST -H "Authorization: Bearer {token}" https://your-api.com/api/devices/POS123456/compliancecertificate
```

4. Request production certificate (after obtaining OTP from ZATCA):
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '"123456"' https://your-api.com/api/devices/POS123456/productioncertificate
```

#### Invoice Reporting

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d '{
  "deviceSerialNumber": "POS123456",
  "documentNumber": "INV-001",
  "documentDate": "2023-01-01T12:00:00",
  "sellerName": "Test Company LLC",
  "sellerVatNumber": "123456789012345",
  "buyerName": "Buyer Company LLC",
  "buyerVatNumber": "311111111111113",
  "totalAmount": 1000,
  "totalWithoutVat": 1000,
  "vatAmount": 150,
  "invoiceType": 0,
  "generateXml": true,
  "lineItems": [
    {
      "lineNumber": 1,
      "itemName": "Product A",
      "quantity": 2,
      "unitOfMeasure": "EA",
      "unitPrice": 500,
      "netAmount": 1000,
      "vatRate": 15,
      "vatAmount": 150,
      "totalAmount": 1150
    }
  ]
}' https://your-api.com/api/invoices/report
```

## Testing

### Using Postman

A comprehensive Postman collection is included in the `/postman` directory. Import this collection to test all API endpoints.

### Running Unit Tests

```bash
dotnet test
```

### Sandbox Testing

For sandbox testing:

1. Configure the API to use ZATCA sandbox URLs
2. Register on ZATCA sandbox portal to get credentials
3. Test the complete device registration flow
4. Test invoice clearance and reporting
5. Verify QR code validation using ZATCA's mobile app

## Documentation

Comprehensive documentation is available in the `/docs` directory:

- **Technical Documentation**: System architecture and design
- **Administration Guide**: Installation, configuration, monitoring
- **Developer Guide**: API integration, code examples
- **Postman Collection**: API testing

## Migrating to Production

To move from sandbox to production:

1. Update ZATCA API endpoints in configuration
2. Obtain production-ready certificates
3. Update environment setting to "Production"
4. Perform end-to-end testing
5. Set up monitoring and alerts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- ZATCA for their e-invoicing technical specifications
- The .NET Core community
- All contributors to this project

## Support

For questions and support, please open an issue in the GitHub repository or contact the maintainers.

## Disclaimer

This software is provided as-is without warranty of any kind. While every effort has been made to ensure compliance with ZATCA requirements, users should verify compliance with the latest ZATCA regulations.
