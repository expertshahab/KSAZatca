# ZATCA Phase 2 API - Developer Guide

## Introduction

This developer guide provides practical instructions for implementing the ZATCA (Zakat, Tax and Customs Authority) Phase 2 e-invoicing API in .NET Core. It includes code examples, best practices, and implementation details to help developers quickly integrate with ZATCA's e-invoicing system.

## Getting Started

### Prerequisites

- Visual Studio 2022 or later
- .NET Core 6.0 or later
- SQL Server 2019 or later
- OpenSSL for certificate operations
- Basic understanding of XML, cryptography, and REST APIs

### Required NuGet Packages

```
Microsoft.AspNetCore.Authentication.JwtBearer
Microsoft.EntityFrameworkCore.SqlServer
System.Security.Cryptography.Xml
System.Security.Cryptography.X509Certificates
System.Text.Json
```

### Project Setup

1. Create a new ASP.NET Core Web API project
2. Add the required NuGet packages
3. Set up your project structure with the following folders:
   - Controllers
   - Models
   - Services
   - Data
   - Utilities

## Implementation Guide

### 1. Database Configuration

Set up your database context and models:

```csharp
// ApplicationDbContext.cs
public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<Device> Devices { get; set; }
    public DbSet<User> Users { get; set; }
    public DbSet<InvoiceReport> InvoiceReports { get; set; }
    public DbSet<CreditNoteReport> CreditNoteReports { get; set; }
    public DbSet<DebitNoteReport> DebitNoteReports { get; set; }
    public DbSet<SalesReturnReport> SalesReturnReports { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure Device entity
        modelBuilder.Entity<Device>()
            .HasIndex(d => d.DeviceSerialNumber)
            .IsUnique();

        // Configure User entity
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username)
            .IsUnique();
    }
}
```

### 2. Authentication Service

Implement JWT-based authentication:

```csharp
// AuthService.cs
public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthService(ApplicationDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    public async Task<AuthResponse> AuthenticateAsync(AuthRequest request)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null || !VerifyPasswordHash(request.Password, user.PasswordHash))
        {
            return null;
        }

        var token = GenerateJwtToken(user);
        return new AuthResponse
        {
            Token = token.token,
            Expiration = token.expiration,
            Username = user.Username,
            Role = user.Role.ToString()
        };
    }

    private string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hashedBytes);
    }

    private bool VerifyPasswordHash(string password, string storedHash)
    {
        var passwordHash = HashPassword(password);
        return passwordHash == storedHash;
    }

    private (string token, DateTime expiration) GenerateJwtToken(User user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role.ToString())
        };

        var expiration = DateTime.UtcNow.AddHours(1);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: expiration,
            signingCredentials: credentials
        );

        return (new JwtSecurityTokenHandler().WriteToken(token), expiration);
    }
}
```

### 3. Device Registration & Certificate Management

Implement device registration and certificate operations:

```csharp
// DeviceService.cs
public class DeviceService : IDeviceService
{
    private readonly ApplicationDbContext _context;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly IZatcaCryptographyService _cryptoService;

    public DeviceService(
        ApplicationDbContext context,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        IZatcaCryptographyService cryptoService)
    {
        _context = context;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _cryptoService = cryptoService;
    }

    public async Task<DeviceRegistrationResponse> RegisterDeviceAsync(DeviceRegistrationRequest request)
    {
        // Check if device exists
        var existingDevice = await _context.Devices
            .FirstOrDefaultAsync(d => d.DeviceSerialNumber == request.DeviceSerialNumber);

        if (existingDevice != null)
        {
            return new DeviceRegistrationResponse
            {
                Status = "Error",
                Message = "Device with this serial number already exists"
            };
        }

        // Create new device
        var device = new Device
        {
            DeviceSerialNumber = request.DeviceSerialNumber,
            DeviceName = request.DeviceName,
            Model = request.Model,
            HardwareVersion = request.HardwareVersion,
            SoftwareVersion = request.SoftwareVersion,
            VatRegistrationNumber = request.VatRegistrationNumber,
            CompanyName = request.CompanyName,
            CommercialRegistrationNumber = request.CommercialRegistrationNumber,
            StreetName = request.StreetName,
            BuildingNumber = request.BuildingNumber,
            CityName = request.CityName,
            DistrictName = request.DistrictName,
            PostalCode = request.PostalCode,
            CountryCode = request.CountryCode,
            RegistrationDate = DateTime.UtcNow,
            LastCommunicationDate = DateTime.UtcNow,
            Status = DeviceStatus.Pending,
            CertificateType = request.CertificateType
        };

        _context.Devices.Add(device);
        await _context.SaveChangesAsync();

        return new DeviceRegistrationResponse
        {
            Status = "Success",
            ZatcaDeviceId = device.DeviceSerialNumber,
            RegistrationDate = device.RegistrationDate.Value,
            Message = "Device registered successfully"
        };
    }

    public async Task<bool> GenerateCSRAsync(string serialNumber)
    {
        var device = await _context.Devices
            .FirstOrDefaultAsync(d => d.DeviceSerialNumber == serialNumber);

        if (device == null)
        {
            return false;
        }

        var commonName = $"ZATCA-{device.VatRegistrationNumber}";
        var csrContent = await _cryptoService.GenerateCSRAsync(
            commonName, 
            device.CompanyName, 
            "E-Invoicing Unit", 
            device.CountryCode);
        
        device.CsrContent = csrContent;
        device.LastCommunicationDate = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        
        return true;
    }

    public async Task<bool> RequestComplianceCertificateAsync(string serialNumber)
    {
        var device = await _context.Devices
            .FirstOrDefaultAsync(d => d.DeviceSerialNumber == serialNumber);

        if (device == null || string.IsNullOrEmpty(device.CsrContent))
        {
            return false;
        }

        try
        {
            // Call ZATCA API
            var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
            var requestUrl = $"{_configuration["ZatcaApi:ComplianceCsrEndpoint"]}";
            
            var requestData = new
            {
                csr = device.CsrContent,
                taxpayerVatId = device.VatRegistrationNumber,
                taxpayerName = device.CompanyName,
                taxpayerCRN = device.CommercialRegistrationNumber
            };

            var content = new StringContent(
                JsonSerializer.Serialize(requestData),
                Encoding.UTF8,
                "application/json");

            var response = await httpClient.PostAsync(requestUrl, content);
            
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var responseData = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);
                
                if (responseData.ContainsKey("binarySecurityToken"))
                {
                    var signedCertificate = responseData["binarySecurityToken"].ToString();
                    var (certificateContent, privateKeyContent) = await _cryptoService.ProcessSignedCertificateAsync(
                        device.CsrContent, signedCertificate);
                    
                    device.CertificateContent = certificateContent;
                    device.PrivateKeyContent = privateKeyContent;
                    device.CertificateExpiryDate = DateTime.UtcNow.AddYears(1);
                    device.Status = DeviceStatus.Registered;
                    
                    await _context.SaveChangesAsync();
                    return true;
                }
            }
            
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
```

### 4. Cryptography Service

Implement certificate and signature operations:

```csharp
// ZatcaCryptographyService.cs
public class ZatcaCryptographyService : IZatcaCryptographyService
{
    public async Task<string> GenerateCSRAsync(string commonName, string organizationName, string organizationUnit, string countryCode)
    {
        // In a real implementation, you'd use OpenSSL or BouncyCastle
        // This is a simplified example
        using var rsa = RSA.Create(2048);
        var subjectName = new X500DistinguishedName($"CN={commonName}, O={organizationName}, OU={organizationUnit}, C={countryCode}");
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        var csrBytes = request.CreateSigningRequest();
        return $"-----BEGIN CERTIFICATE REQUEST-----\n{Convert.ToBase64String(csrBytes)}\n-----END CERTIFICATE REQUEST-----";
    }

    public async Task<string> SignXmlAsync(string invoiceXml, string deviceSerialNumber)
    {
        // Load the certificate and private key
        // Sign the XML according to ZATCA requirements
        // Return the signed XML
        
        // This is placeholder code - in a real implementation you would:
        // 1. Load the certificate from storage
        // 2. Use System.Security.Cryptography.Xml to sign the document
        // 3. Return the signed XML
        
        return invoiceXml;  // Placeholder
    }

    public async Task<string> GenerateInvoiceHashAsync(string xml)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(xml);
        var hashBytes = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hashBytes);
    }
}
```

### 5. XML Generation and Validation

Implement UBL 2.1 XML generation and validation:

```csharp
// XmlSchemaValidator.cs
public class XmlSchemaValidator : IXmlSchemaValidator
{
    public async Task<string> ConvertToUBLXmlAsync(InvoiceReportRequest request)
    {
        var document = new XmlDocument();
        
        // XML Declaration
        var xmlDeclaration = document.CreateXmlDeclaration("1.0", "UTF-8", null);
        document.AppendChild(xmlDeclaration);
        
        // Create root element with namespaces
        var rootElement = document.CreateElement("Invoice", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2");
        
        // Add namespaces
        var namespaces = new Dictionary<string, string>
        {
            {"", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"},
            {"cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"},
            {"cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"},
            {"ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"}
        };
        
        foreach (var ns in namespaces)
        {
            if (string.IsNullOrEmpty(ns.Key))
            {
                rootElement.SetAttribute("xmlns", ns.Value);
            }
            else
            {
                rootElement.SetAttribute($"xmlns:{ns.Key}", ns.Value);
            }
        }
        
        document.AppendChild(rootElement);
        
        // Add UBL extensions for ZATCA (signature and QR code placeholders)
        AddUblExtensions(document, rootElement, namespaces);
        
        // Add core invoice elements
        AddCoreInvoiceElements(document, rootElement, request, namespaces);
        
        // Add seller information
        AddSellerInformation(document, rootElement, request, namespaces);
        
        // Add buyer information
        AddBuyerInformation(document, rootElement, request, namespaces);
        
        // Add tax information
        AddTaxInformation(document, rootElement, request, namespaces);
        
        // Add monetary totals
        AddMonetaryTotals(document, rootElement, request, namespaces);
        
        // Add line items
        AddLineItems(document, rootElement, request, namespaces);
        
        // Convert to string
        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { Indent = true });
        document.WriteTo(xmlWriter);
        xmlWriter.Flush();
        
        return stringWriter.ToString();
    }
    
    public async Task<(bool isValid, List<string> errors)> ValidateUBLInvoiceAsync(string xml)
    {
        var errors = new List<string>();
        
        try
        {
            // Load XML document
            var document = new XmlDocument();
            document.LoadXml(xml);
            
            // Create namespace manager
            var nsManager = new XmlNamespaceManager(document.NameTable);
            nsManager.AddNamespace("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
            nsManager.AddNamespace("cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
            nsManager.AddNamespace("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
            
            // Check required elements
            var requiredElements = new Dictionary<string, string>
            {
                { "//cbc:ProfileID", "Profile ID" },
                { "//cbc:ID", "Invoice ID" },
                { "//cbc:IssueDate", "Issue Date" },
                { "//cbc:InvoiceTypeCode", "Invoice Type Code" },
                { "//cbc:DocumentCurrencyCode", "Document Currency Code" },
                { "//cac:AccountingSupplierParty", "Seller Information" },
                { "//cac:AccountingCustomerParty", "Buyer Information" }
            };
            
            foreach (var element in requiredElements)
            {
                var node = document.SelectSingleNode(element.Key, nsManager);
                if (node == null)
                {
                    errors.Add($"Missing required element: {element.Value}");
                }
            }
            
            // Check VAT registration numbers
            var sellerVatNode = document.SelectSingleNode("//cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID", nsManager);
            if (sellerVatNode == null || !IsValidVatNumber(sellerVatNode.InnerText))
            {
                errors.Add("Invalid or missing Seller VAT registration number");
            }
            
            var buyerVatNode = document.SelectSingleNode("//cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID", nsManager);
            if (buyerVatNode == null || !IsValidVatNumber(buyerVatNode.InnerText))
            {
                errors.Add("Invalid or missing Buyer VAT registration number");
            }
            
            return (errors.Count == 0, errors);
        }
        catch (Exception ex)
        {
            errors.Add($"XML validation error: {ex.Message}");
            return (false, errors);
        }
    }
    
    private bool IsValidVatNumber(string vatNumber)
    {
        // VAT number validation logic
        // Saudi VAT numbers are 15 digits
        return !string.IsNullOrEmpty(vatNumber) && vatNumber.Length == 15 && vatNumber.All(char.IsDigit);
    }
    
    private void AddUblExtensions(XmlDocument doc, XmlElement root, Dictionary<string, string> ns)
    {
        var extensions = doc.CreateElement("ext", "UBLExtensions", ns["ext"]);
        root.AppendChild(extensions);
        
        // Extension for signature
        var signatureExtension = doc.CreateElement("ext", "UBLExtension", ns["ext"]);
        extensions.AppendChild(signatureExtension);
        
        var signatureContent = doc.CreateElement("ext", "ExtensionContent", ns["ext"]);
        signatureExtension.AppendChild(signatureContent);
        
        // Extension for QR code
        var qrExtension = doc.CreateElement("ext", "UBLExtension", ns["ext"]);
        extensions.AppendChild(qrExtension);
        
        var qrContent = doc.CreateElement("ext", "ExtensionContent", ns["ext"]);
        qrExtension.AppendChild(qrContent);
    }
    
    // Add other helper methods for XML generation...
}
```

### 6. QR Code Generation

Implement TLV-formatted QR codes:

```csharp
// QRCodeService.cs
public class QRCodeService : IQRCodeService
{
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

    public async Task<(string base64QR, string tlvQR)> EncodeQrCodeAsync(
        string sellerName, string vatNumber, DateTime timestamp, 
        decimal totalWithVat, decimal vatAmount, string invoiceHash, string signature)
    {
        // Create TLV data
        var qrData = new Dictionary<int, string>
        {
            { 1, sellerName },        // Seller Name
            { 2, vatNumber },         // VAT Registration Number
            { 3, timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ") }, // Timestamp
            { 4, totalWithVat.ToString("0.00") },  // Invoice Total (with VAT)
            { 5, vatAmount.ToString("0.00") },     // VAT Amount
            { 6, invoiceHash },       // Invoice Hash
            { 7, signature }          // Digital Signature
        };
        
        // Generate TLV encoded QR code
        var tlvQRBytes = GenerateTLVEncodedQR(qrData);
        
        // Convert to Base64 and Hex string
        var base64QR = Convert.ToBase64String(tlvQRBytes);
        var tlvQR = BitConverter.ToString(tlvQRBytes).Replace("-", "");
        
        return (base64QR, tlvQR);
    }
}
```

### 7. Invoice Reporting Service

Implement invoice submission to ZATCA:

```csharp
// ZatcaService.cs
public class ZatcaService : IZatcaService
{
    private readonly ApplicationDbContext _context;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IDeviceService _deviceService;
    private readonly IConfiguration _configuration;
    private readonly IZatcaCryptographyService _cryptoService;
    private readonly IQRCodeService _qrCodeService;
    private readonly IXmlSchemaValidator _xmlValidator;
    private readonly IClearanceService _clearanceService;
    private readonly ILogger<ZatcaService> _logger;

    public ZatcaService(
        ApplicationDbContext context,
        IHttpClientFactory httpClientFactory,
        IDeviceService deviceService,
        IConfiguration configuration,
        IZatcaCryptographyService cryptoService,
        IQRCodeService qrCodeService,
        IXmlSchemaValidator xmlValidator,
        IClearanceService clearanceService,
        ILogger<ZatcaService> logger)
    {
        _context = context;
        _httpClientFactory = httpClientFactory;
        _deviceService = deviceService;
        _configuration = configuration;
        _cryptoService = cryptoService;
        _qrCodeService = qrCodeService;
        _xmlValidator = xmlValidator;
        _clearanceService = clearanceService;
        _logger = logger;
    }

    public async Task<InvoiceReportResponse> ReportInvoiceAsync(InvoiceReportRequest request)
    {
        try
        {
            // Check if device exists and is active
            var device = await _deviceService.GetDeviceBySerialNumberAsync(request.DeviceSerialNumber);
            if (device == null || device.Status != DeviceStatus.Active)
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Device not found or not active"
                };
            }

            // Generate or use provided invoice XML
            string invoiceXml;
            if (request.GenerateXml || string.IsNullOrEmpty(request.DocumentXml))
            {
                _logger.LogInformation("Generating invoice XML");
                invoiceXml = await _xmlValidator.ConvertToUBLXmlAsync(request);
            }
            else
            {
                invoiceXml = request.DocumentXml;
            }

            // Validate the XML against schema and business rules
            var (isValid, validationErrors) = await _xmlValidator.ValidateUBLInvoiceAsync(invoiceXml);
            if (!isValid)
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Invoice XML validation failed",
                    ValidationResults = string.Join(", ", validationErrors)
                };
            }

            // Generate hash and signature
            _logger.LogInformation("Generating invoice hash and signature");
            var invoiceHash = await _cryptoService.GenerateInvoiceHashAsync(invoiceXml);
            var signature = await _cryptoService.GetDigitalSignatureAsync(invoiceXml, request.DeviceSerialNumber);
            
            // Generate QR code
            _logger.LogInformation("Generating QR code");
            var (base64QR, tlvQR) = await _qrCodeService.EncodeQrCodeAsync(
                request.SellerName,
                request.SellerVatNumber,
                request.DocumentIssueTime,
                request.TotalAmount + request.VatAmount,
                request.VatAmount,
                invoiceHash,
                signature);
            
            // Add QR code to XML
            var xmlWithQR = _xmlValidator.AddQRCodeToXml(invoiceXml, base64QR);
            
            // Sign the XML
            _logger.LogInformation("Signing invoice XML");
            var signedXml = await _cryptoService.SignXmlAsync(xmlWithQR, request.DeviceSerialNumber);
            
            // Submit to ZATCA based on invoice type
            InvoiceReportResponse zatcaResponse;
            if (request.InvoiceType == InvoiceType.Standard && 
                (request.TransactionType == InvoiceTransactionType.Standard || 
                 request.TransactionType == InvoiceTransactionType.CreditNote ||
                 request.TransactionType == InvoiceTransactionType.DebitNote))
            {
                _logger.LogInformation("Submitting for clearance");
                // B2B standard invoices require clearance
                zatcaResponse = await _clearanceService.ClearInvoiceAsync(signedXml, request.DeviceSerialNumber);
            }
            else
            {
                _logger.LogInformation("Submitting for reporting");
                // Simplified invoices use reporting
                zatcaResponse = await _clearanceService.ReportInvoiceAsync(signedXml, request.DeviceSerialNumber);
            }

            // Save the invoice report
            await SaveInvoiceReport(request, signedXml, invoiceHash, base64QR, zatcaResponse);
            
            return zatcaResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reporting invoice");
            return new InvoiceReportResponse
            {
                Status = "Error",
                Message = $"Exception: {ex.Message}"
            };
        }
    }
    
    private async Task SaveInvoiceReport(
        InvoiceReportRequest request, 
        string signedXml, 
        string invoiceHash, 
        string qrCode, 
        InvoiceReportResponse zatcaResponse)
    {
        var report = new InvoiceReport
        {
            DocumentNumber = request.DocumentNumber,
            DocumentDate = request.DocumentDate,
            DocumentIssueTime = request.DocumentIssueTime,
            SellerName = request.SellerName,
            SellerVatNumber = request.SellerVatNumber,
            BuyerName = request.BuyerName,
            BuyerVatNumber = request.BuyerVatNumber,
            TotalAmount = request.TotalAmount,
            VatAmount = request.VatAmount,
            DocumentUUID = zatcaResponse.UUID ?? Guid.NewGuid().ToString(),
            DocumentHash = invoiceHash,
            DocumentXml = request.DocumentXml,
            SignedDocumentXml = signedXml,
            ZatcaQrCode = qrCode,
            ZatcaReportId = zatcaResponse.ZatcaReportId,
            ZatcaReportingStatus = zatcaResponse.Status,
            ReportingDate = DateTime.UtcNow,
            ClearanceDate = zatcaResponse.ClearanceStatus == ClearanceStatus.Cleared ? DateTime.UtcNow : null,
            ClearanceStatus = zatcaResponse.ClearanceStatus,
            DeviceSerialNumber = request.DeviceSerialNumber,
            InvoiceType = request.InvoiceType,
            TransactionType = request.TransactionType
        };
        
        _context.InvoiceReports.Add(report);
        await _context.SaveChangesAsync();
    }
}
```

### 8. Clearance and Reporting Service

Implement communication with ZATCA APIs:

```csharp
// ClearanceService.cs
public class ClearanceService : IClearanceService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly IDeviceService _deviceService;
    private readonly ILogger<ClearanceService> _logger;

    public ClearanceService(
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        IDeviceService deviceService,
        ILogger<ClearanceService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _deviceService = deviceService;
        _logger = logger;
    }

    public async Task<InvoiceReportResponse> ClearInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber)
    {
        try
        {
            // Get device info
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null)
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Device not found",
                    ClearanceStatus = ClearanceStatus.Error
                };
            }

            // Prepare HTTP client
            var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
            
            // Prepare request
            var requestUrl = _configuration["ZatcaApi:ClearanceEndpoint"];
            var signedInvoiceBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedInvoiceXml));
            
            // Extract invoice hash and UUID from XML
            var invoiceHash = ExtractInvoiceHash(signedInvoiceXml);
            var uuid = ExtractUUID(signedInvoiceXml);
            
            var requestData = new
            {
                invoiceHash = invoiceHash,
                uuid = uuid,
                invoice = signedInvoiceBase64
            };
            
            var content = new StringContent(
                JsonSerializer.Serialize(requestData),
                Encoding.UTF8,
                "application/json");
            
            // Add required headers
            httpClient.DefaultRequestHeaders.Clear();
            httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
            httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
            
            // Send request
            _logger.LogInformation("Sending clearance request to ZATCA");
            var response = await httpClient.PostAsync(requestUrl, content);
            
            // Process response
            var responseContent = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("Received clearance response: {Response}", responseContent);
            
            if (response.IsSuccessStatusCode)
            {
                var responseObject = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent);
                
                var clearanceStatus = response.StatusCode == System.Net.HttpStatusCode.OK
                    ? ClearanceStatus.Cleared
                    : ClearanceStatus.PartialClearance;
                
                var validationWarnings = new List<ZatcaValidationWarning>();
                
                // Extract validation results if available
                if (responseObject.ContainsKey("validationResults") && 
                    responseObject["validationResults"].ValueKind == JsonValueKind.Array)
                {
                    foreach (var warning in responseObject["validationResults"].EnumerateArray())
                    {
                        validationWarnings.Add(new ZatcaValidationWarning
                        {
                            Code = warning.GetProperty("code").GetString(),
                            Message = warning.GetProperty("message").GetString(),
                            Category = warning.GetProperty("category").GetString(),
                            Status = warning.GetProperty("status").GetString()
                        });
                    }
                }
                
                // Extract other response details
                string reportId = null;
                if (responseObject.ContainsKey("reportId"))
                {
                    reportId = responseObject["reportId"].GetString();
                }
                
                string responseUuid = null;
                if (responseObject.ContainsKey("uuid"))
                {
                    responseUuid = responseObject["uuid"].GetString();
                }
                
                string responseInvoiceHash = null;
                if (responseObject.ContainsKey("invoiceHash"))
                {
                    responseInvoiceHash = responseObject["invoiceHash"].GetString();
                }
                
                List<string> clearedInvoiceXmlUrls = new List<string>();
                if (responseObject.ContainsKey("clearedInvoiceXmlUrl") && 
                    responseObject["clearedInvoiceXmlUrl"].ValueKind == JsonValueKind.Array)
                {
                    foreach (var url in responseObject["clearedInvoiceXmlUrl"].EnumerateArray())
                    {
                        clearedInvoiceXmlUrls.Add(url.GetString());
                    }
                }
                
                return new InvoiceReportResponse
                {
                    Status = "Success",
                    Message = "Invoice cleared successfully",
                    ZatcaReportId = reportId,
                    UUID = responseUuid ?? uuid,
                    InvoiceHash = responseInvoiceHash ?? invoiceHash,
                    ClearanceStatus = clearanceStatus,
                    ValidationWarnings = validationWarnings,
                    ComplianceStatus = clearanceStatus == ClearanceStatus.Cleared ? "Compliant" : "Partially Compliant",
                    SignedInvoiceBase64 = signedInvoiceBase64,
                    ClearedInvoiceXmlUrls = clearedInvoiceXmlUrls
                };
            }
            else
            {
                _logger.LogError("Clearance failed: {StatusCode} - {Response}", response.StatusCode, responseContent);
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = $"Clearance failed: {response.StatusCode} - {responseContent}",
                    ClearanceStatus = ClearanceStatus.Rejected
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during clearance process");
            return new InvoiceReportResponse
            {
                Status = "Error",
                Message = $"Clearance process error: {ex.Message}",
                ClearanceStatus = ClearanceStatus.Error
            };
        }
    }

    public async Task<InvoiceReportResponse> ReportInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber)
    {
        try
        {
            // Get device info
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null)
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Device not found",
                    ClearanceStatus = ClearanceStatus.Error
                };
            }

            // Prepare HTTP client
            var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
            
            // Prepare request
            var requestUrl = _configuration["ZatcaApi:ReportingEndpoint"];
            var signedInvoiceBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedInvoiceXml));
            
            // Extract invoice hash and UUID from XML
            var invoiceHash = ExtractInvoiceHash(signedInvoiceXml);
            var uuid = ExtractUUID(signedInvoiceXml);
            
            var requestData = new
            {
                invoiceHash = invoiceHash,
                uuid = uuid,
                invoice = signedInvoiceBase64
            };
            
            var content = new StringContent(
                JsonSerializer.Serialize(requestData),
                Encoding.UTF8,
                "application/json");
            
            // Add required headers
            httpClient.DefaultRequestHeaders.Clear();
            httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
            httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
            
            // Send request
            _logger.LogInformation("Sending reporting request to ZATCA");
            var response = await httpClient.PostAsync(requestUrl, content);
            
            // Process response
            var responseContent = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("Received reporting response: {Response}", responseContent);
            
            if (response.IsSuccessStatusCode)
            {
                var responseObject = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent);
                
                var validationWarnings = new List<ZatcaValidationWarning>();
                
                // Extract validation results if available
                if (responseObject.ContainsKey("validationResults") && 
                    responseObject["validationResults"].ValueKind == JsonValueKind.Array)
                {
                    foreach (var warning in responseObject["validationResults"].EnumerateArray())
                    {
                        validationWarnings.Add(new ZatcaValidationWarning
                        {
                            Code = warning.GetProperty("code").GetString(),
                            Message = warning.GetProperty("message").GetString(),
                            Category = warning.GetProperty("category").GetString(),
                            Status = warning.GetProperty("status").GetString()
                        });
                    }
                }
                
                // Extract other response details
                string reportId = null;
                if (responseObject.ContainsKey("reportId"))
                {
                    reportId = responseObject["reportId"].GetString();
                }
                
                string responseUuid = null;
                if (responseObject.ContainsKey("uuid"))
                {
                    responseUuid = responseObject["uuid"].GetString();
                }
                
                string responseInvoiceHash = null;
                if (responseObject.ContainsKey("invoiceHash"))
                {
                    responseInvoiceHash = responseObject["invoiceHash"].GetString();
                }
                
                return new InvoiceReportResponse
                {
                    Status = "Success",
                    Message = "Invoice reported successfully",
                    ZatcaReportId = reportId,
                    UUID = responseUuid ?? uuid,
                    InvoiceHash = responseInvoiceHash ?? invoiceHash,
                    ClearanceStatus = ClearanceStatus.Pending,
                    ValidationWarnings = validationWarnings,
                    ComplianceStatus = "Reported",
                    SignedInvoiceBase64 = signedInvoiceBase64
                };
            }
            else
            {
                _logger.LogError("Reporting failed: {StatusCode} - {Response}", response.StatusCode, responseContent);
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = $"Reporting failed: {response.StatusCode} - {responseContent}",
                    ClearanceStatus = ClearanceStatus.Rejected
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during reporting process");
            return new InvoiceReportResponse
            {
                Status = "Error",
                Message = $"Reporting process error: {ex.Message}",
                ClearanceStatus = ClearanceStatus.Error
            };
        }
    }

    private string GetBasicAuthHeader(Device device)
    {
        // Combine certificate serial number and device token
        var credentials = $"{device.CertificateSerialNumber}:{device.ZatcaDeviceToken}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
    }

    private string ExtractInvoiceHash(string xml)
    {
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            
            // In a real implementation, you would extract the hash from the XML
            // This is a placeholder implementation
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(xml);
            var hashBytes = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hashBytes);
        }
        catch
        {
            return Guid.NewGuid().ToString();
        }
    }

    private string ExtractUUID(string xml)
    {
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            
            var nsManager = new XmlNamespaceManager(doc.NameTable);
            nsManager.AddNamespace("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
            
            var uuidNode = doc.SelectSingleNode("//cbc:UUID", nsManager);
            return uuidNode?.InnerText ?? Guid.NewGuid().ToString();
        }
        catch
        {
            return Guid.NewGuid().ToString();
        }
    }
}
```

### 9. API Controllers

Implement the API controllers to expose the functionality:

```csharp
// AuthController.cs
[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] AuthRequest request)
    {
        _logger.LogInformation("Login attempt for user: {Username}", request.Username);
        
        var response = await _authService.AuthenticateAsync(request);
        if (response == null)
        {
            _logger.LogWarning("Login failed for user: {Username}", request.Username);
            return Unauthorized();
        }

        _logger.LogInformation("Login successful for user: {Username}", request.Username);
        return Ok(response);
    }

    [HttpPost("register")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Registering new user: {Username}", request.Username);
        
        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            CompanyName = request.CompanyName,
            VatRegistrationNumber = request.VatRegistrationNumber,
            Role = request.Role
        };

        var result = await _authService.RegisterUserAsync(user, request.Password);
        if (result == null)
        {
            _logger.LogWarning("User registration failed: {Username} (already exists)", request.Username);
            return BadRequest("User with this username already exists");
        }

        _logger.LogInformation("User registered successfully: {Username}", request.Username);
        return Ok(new
        {
            Username = result.Username,
            Email = result.Email,
            Role = result.Role.ToString()
        });
    }
}

// DeviceController.cs
[ApiController]
[Route("api/devices")]
[Authorize]
public class DeviceController : ControllerBase
{
    private readonly IDeviceService _deviceService;
    private readonly ILogger<DeviceController> _logger;

    public DeviceController(IDeviceService deviceService, ILogger<DeviceController> logger)
    {
        _deviceService = deviceService;
        _logger = logger;
    }

    [HttpPost("register")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RegisterDevice([FromBody] DeviceRegistrationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Registering device: {SerialNumber}", request.DeviceSerialNumber);
        
        var result = await _deviceService.RegisterDeviceAsync(request);
        if (result.Status == "Error")
        {
            _logger.LogWarning("Device registration failed: {SerialNumber} - {Message}", 
                request.DeviceSerialNumber, result.Message);
            return BadRequest(result);
        }

        _logger.LogInformation("Device registered successfully: {SerialNumber}", request.DeviceSerialNumber);
        return Ok(result);
    }

    [HttpGet("{serialNumber}")]
    public async Task<IActionResult> GetDeviceBySerialNumber(string serialNumber)
    {
        _logger.LogInformation("Getting device: {SerialNumber}", serialNumber);
        
        var device = await _deviceService.GetDeviceBySerialNumberAsync(serialNumber);
        if (device == null)
        {
            _logger.LogWarning("Device not found: {SerialNumber}", serialNumber);
            return NotFound();
        }

        return Ok(device);
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllDevices()
    {
        _logger.LogInformation("Getting all devices");
        
        var devices = await _deviceService.GetAllDevicesAsync();
        return Ok(devices);
    }

    [HttpPost("{serialNumber}/generatecsr")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GenerateCSR(string serialNumber)
    {
        _logger.LogInformation("Generating CSR for device: {SerialNumber}", serialNumber);
        
        var result = await _deviceService.GenerateCSRAsync(serialNumber);
        if (!result)
        {
            _logger.LogWarning("CSR generation failed for device: {SerialNumber}", serialNumber);
            return NotFound("Device not found or CSR generation failed");
        }

        _logger.LogInformation("CSR generated successfully for device: {SerialNumber}", serialNumber);
        return Ok(new { Message = "CSR generated successfully" });
    }

    [HttpPost("{serialNumber}/compliancecertificate")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RequestComplianceCertificate(string serialNumber)
    {
        _logger.LogInformation("Requesting compliance certificate for device: {SerialNumber}", serialNumber);
        
        var result = await _deviceService.RequestComplianceCertificateAsync(serialNumber);
        if (!result)
        {
            _logger.LogWarning("Compliance certificate request failed for device: {SerialNumber}", serialNumber);
            return BadRequest("Failed to request compliance certificate");
        }

        _logger.LogInformation("Compliance certificate requested successfully for device: {SerialNumber}", serialNumber);
        return Ok(new { Message = "Compliance certificate requested successfully" });
    }

    [HttpPost("{serialNumber}/productioncertificate")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RequestProductionCertificate(string serialNumber, [FromBody] string otp)
    {
        _logger.LogInformation("Requesting production certificate for device: {SerialNumber}", serialNumber);
        
        var result = await _deviceService.RequestProductionCertificateAsync(serialNumber, otp);
        if (!result)
        {
            _logger.LogWarning("Production certificate request failed for device: {SerialNumber}", serialNumber);
            return BadRequest("Failed to request production certificate");
        }

        _logger.LogInformation("Production certificate requested successfully for device: {SerialNumber}", serialNumber);
        return Ok(new { Message = "Production certificate requested successfully" });
    }
}

// InvoiceController.cs
[ApiController]
[Route("api/invoices")]
[Authorize]
public class InvoiceController : ControllerBase
{
    private readonly IZatcaService _zatcaService;
    private readonly ILogger<InvoiceController> _logger;

    public InvoiceController(IZatcaService zatcaService, ILogger<InvoiceController> logger)
    {
        _zatcaService = zatcaService;
        _logger = logger;
    }

    [HttpPost("report")]
    public async Task<IActionResult> ReportInvoice([FromBody] InvoiceReportRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Reporting invoice: {InvoiceNumber} for device: {SerialNumber}", 
            request.DocumentNumber, request.DeviceSerialNumber);
        
        var result = await _zatcaService.ReportInvoiceAsync(request);
        if (result.Status == "Error")
        {
            _logger.LogWarning("Invoice reporting failed: {InvoiceNumber} - {Message}", 
                request.DocumentNumber, result.Message);
            return BadRequest(result);
        }

        _logger.LogInformation("Invoice reported successfully: {InvoiceNumber}", request.DocumentNumber);
        return Ok(result);
    }

    [HttpPost("creditnote")]
    public async Task<IActionResult> ReportCreditNote([FromBody] CreditNoteReportRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Reporting credit note: {CreditNoteNumber} for device: {SerialNumber}", 
            request.DocumentNumber, request.DeviceSerialNumber);
        
        var result = await _zatcaService.ReportCreditNoteAsync(request);
        if (result.Status == "Error")
        {
            _logger.LogWarning("Credit note reporting failed: {CreditNoteNumber} - {Message}", 
                request.DocumentNumber, result.Message);
            return BadRequest(result);
        }

        _logger.LogInformation("Credit note reported successfully: {CreditNoteNumber}", request.DocumentNumber);
        return Ok(result);
    }

    [HttpPost("validate")]
    public async Task<IActionResult> ValidateInvoice([FromBody] InvoiceValidationRequest request)
    {
        _logger.LogInformation("Validating invoice XML for device: {SerialNumber}", request.DeviceSerialNumber);
        
        var result = await _zatcaService.ValidateInvoiceAsync(request.InvoiceXml, request.DeviceSerialNumber);
        return Ok(new { ValidationResults = result });
    }

    [HttpPost("generatexml")]
    public async Task<IActionResult> GenerateInvoiceXml([FromBody] InvoiceReportRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Generating invoice XML: {InvoiceNumber} for device: {SerialNumber}", 
            request.DocumentNumber, request.DeviceSerialNumber);
        
        var result = await _zatcaService.GenerateInvoiceXmlAsync(request);
        return Ok(new { InvoiceXml = result });
    }
}
```

### 10. Configuration

Set up the application configuration in `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=ZatcaPhase2;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
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
    "ReportingEndpoint": "reporting",
    "ComplianceCheckEndpoint": "compliance/check",
    "ClearedInvoiceEndpoint": "clearance/invoice"
  },
  "Environment": "Sandbox"
}
```

### 11. Startup Configuration

Configure services and middleware in `Program.cs`:

```csharp
var builder = WebApplication.CreateBuilder(args);

// Add database context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add services
builder.Services.AddScoped<IDeviceService, DeviceService>();
builder.Services.AddScoped<IZatcaService, ZatcaService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IXmlSchemaValidator, XmlSchemaValidator>();
builder.Services.AddScoped<IZatcaCryptographyService, ZatcaCryptographyService>();
builder.Services.AddScoped<IQRCodeService, QRCodeService>();
builder.Services.AddScoped<IClearanceService, ClearanceService>();

// Configure ZATCA API Client
builder.Services.AddHttpClient("ZatcaApi", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ZatcaApi:BaseUrl"]);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

// Configure JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            builder.Configuration["Jwt:Key"]))
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

// Configure Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ZATCA Phase 2 API",
        Version = "v1",
        Description = "API for ZATCA Phase 2 compliance in Saudi Arabia"
    });

    // Configure Swagger to use JWT Authentication
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

## Testing Guide

### 1. Using Postman

1. Use the provided Postman collection to test the API endpoints.
2. Set up environment variables for:
   - `base_url` (e.g., `https://localhost:5001`)
   - `token` (will be populated automatically after login)

### 2. Testing Flow

Follow this sequence to test the complete flow:

1. Register an admin user (if not already done)
2. Login to get a JWT token
3. Register a device
4. Generate a CSR for the device
5. Request a compliance certificate
6. Get an OTP from ZATCA sandbox portal
7. Request a production certificate using the OTP
8. Create and report a standard invoice
9. Create and report a simplified invoice
10. Create and report a credit note
11. Check compliance status

### 3. Sandbox Testing

Configure the application to use the ZATCA sandbox environment:

1. Update `ZatcaApi:BaseUrl` in `appsettings.json` to point to the sandbox URL
2. Register on the ZATCA sandbox portal to get credentials
3. Use the sandbox credentials in your API calls

## Troubleshooting

### Common Issues and Solutions

#### 1. Certificate Issues

**Problem**: Invalid certificate or signature errors.

**Solution**:
- Verify that the CSR generation is correct
- Ensure the certificate and private key are stored correctly
- Check that the signing process uses the correct certificate

#### 2. XML Validation Errors

**Problem**: Invoice XML fails validation with ZATCA.

**Solution**:
- Check the UBL 2.1 schema compliance
- Ensure all required fields are present
- Verify that VAT numbers are in the correct format
- Ensure XML namespaces are correctly defined

#### 3. QR Code Issues

**Problem**: QR code is not accepted by ZATCA or cannot be scanned.

**Solution**:
- Verify the TLV format implementation
- Ensure all required tags are present
- Check that values are encoded correctly
- Test the QR code with ZATCA's mobile app

#### 4. API Connection Issues

**Problem**: Cannot connect to ZATCA APIs.

**Solution**:
- Verify network connectivity
- Check that the ZATCA base URL is correct
- Ensure authentication headers are correctly set
- Verify that certificates are valid and not expired

## Best Practices

### 1. Security

- **Secure Certificate Storage**: Never store private keys in plain text. Use a secure certificate store or encrypt them in the database.
- **Use HTTPS**: Always use HTTPS for all API endpoints.
- **Validate Input**: Validate all input data before processing.
- **Log Securely**: Do not log sensitive information like private keys or tokens.

### 2. Performance

- **Optimize Database Queries**: Use indexes for frequently queried fields.
- **Implement Caching**: Cache frequently used data like device information.
- **Use Asynchronous Programming**: Use async/await pattern for I/O operations.
- **Batch Operations**: Use batch processing for multiple invoices when possible.

### 3. Reliability

- **Implement Retry Logic**: Use retry mechanisms for ZATCA API calls.
- **Transaction Management**: Use database transactions for critical operations.
- **Error Handling**: Implement comprehensive error handling.
- **Monitoring**: Set up logging and monitoring to track system health.

### 4. Maintainability

- **Follow Clean Code Principles**: Use meaningful names, keep methods small, and follow SOLID principles.
- **Write Unit Tests**: Cover critical functionality with unit tests.
- **Document Your Code**: Add XML documentation to methods and classes.
- **Versioning**: Implement API versioning for future compatibility.

## Migration to Production

When moving from sandbox to production:

1. **Update Configuration**:
   - Change ZATCA API endpoints to production URLs
   - Update `Environment` setting to "Production"
   - Use production credentials

2. **Certificate Management**:
   - Ensure production certificates are properly secured
   - Implement certificate renewal process
   - Monitor certificate expiry dates

3. **Testing**:
   - Perform end-to-end testing in production environment
   - Test with real VAT numbers and business data
   - Verify compliance with ZATCA production requirements

4. **Monitoring**:
   - Set up alerts for failed invoice submissions
   - Monitor certificate expiration dates
   - Track API response times and availability

## Conclusion

This developer guide provides a comprehensive foundation for implementing the ZATCA Phase 2 e-invoicing API in .NET Core. By following these implementation details and best practices, you can create a compliant, secure, and efficient solution for e-invoicing in Saudi Arabia.

Remember to regularly check the ZATCA portal for any updates to the e-invoicing requirements and adjust your implementation accordingly.