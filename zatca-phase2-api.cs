    // Implementation of QR Code Service
    public class QRCodeService : IQRCodeService
    {
        public async Task<string> GenerateQrCodeAsync(string sellerName, string vatNumber, DateTime timestamp, decimal totalWithVat, decimal vatAmount, string invoiceHash, string signature)
        {
            // Create TLV data structure
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
            
            // Convert to Base64
            return Convert.ToBase64String(tlvQRBytes);
        }
        
        public async Task<string> GenerateQrCodeFromInvoiceAsync(string invoiceXml, string signature)
        {
            try
            {
                // Parse invoice XML to extract required data
                var doc = new XmlDocument();
                doc.LoadXml(invoiceXml);
                
                var nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
                nsManager.AddNamespace("cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
                
                // Extract seller name
                var sellerNameNode = doc.SelectSingleNode("//cac:AccountingSupplierParty/cac:Party/cac:PartyLegalEntity/cbc:RegistrationName", nsManager);
                var sellerName = sellerNameNode?.InnerText ?? "Unknown";
                
                // Extract VAT number
                var vatNumberNode = doc.SelectSingleNode("//cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID", nsManager);
                var vatNumber = vatNumberNode?.InnerText ?? "000000000000000";
                
                // Extract timestamp
                var issueDateNode = doc.SelectSingleNode("//cbc:IssueDate", nsManager);
                var issueTimeNode = doc.SelectSingleNode("//cbc:IssueTime", nsManager);
                
                var issueDate = issueDateNode?.InnerText ?? DateTime.UtcNow.ToString("yyyy-MM-dd");
                var issueTime = issueTimeNode?.InnerText ?? DateTime.UtcNow.ToString("HH:mm:ss");
                
                var timestamp = DateTime.Parse($"{issueDate}T{issueTime}");
                
                // Extract total with VAT
                var taxInclusiveAmountNode = doc.SelectSingleNode("//cac:LegalMonetaryTotal/cbc:TaxInclusiveAmount", nsManager);
                var totalWithVat = decimal.Parse(taxInclusiveAmountNode?.InnerText ?? "0.00");
                
                // Extract VAT amount
                var taxAmountNode = doc.SelectSingleNode("//cac:TaxTotal/cbc:TaxAmount", nsManager);
                var vatAmount = decimal.Parse(taxAmountNode?.InnerText ?? "0.00");
                
                // Calculate invoice hash (simplified for example)
                var invoiceHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(invoiceXml)));
                
                // Generate QR code
                return await GenerateQrCodeAsync(sellerName, vatNumber, timestamp, totalWithVat, vatAmount, invoiceHash, signature);
            }
            catch (Exception)
            {
                // In case of error, return a placeholder
                return "QR_ERROR";
            }
        }
        
        public async Task<(string base64QR, string tlvQR)> EncodeQrCodeAsync(string sellerName, string vatNumber, DateTime timestamp, decimal totalWithVat, decimal vatAmount, string invoiceHash, string signature)
        {
            // Create TLV data structure
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
        
        public byte[] GenerateTLVEncodedQR(Dictionary<int, string> qrData)
        {
            using var memoryStream = new MemoryStream();
            
            foreach (var entry in qrData)
            {
                // Tag (1 byte)
                memoryStream.WriteByte((byte)entry.Key);
                
                // Length (1 byte if length < 128, 2 bytes otherwise)
                var valueBytes = Encoding.UTF8.GetBytes(entry.Value);
                var length = valueBytes.Length;
                
                if (length < 128)
                {
                    memoryStream.WriteByte((byte)length);
                }
                else
                {
                    // Length indicator with high bit set plus length of length
                    memoryStream.WriteByte((byte)(0x80 | 1));
                    memoryStream.WriteByte((byte)length);
                }
                
                // Value
                memoryStream.Write(valueBytes, 0, valueBytes.Length);
            }
            
            return memoryStream.ToArray();
        }
    }
    
    // Implementation of Clearance Service
    public class ClearanceService : IClearanceService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IDeviceService _deviceService;
        
        public ClearanceService(
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            IDeviceService deviceService)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _deviceService = deviceService;
        }
        
        public async Task<InvoiceReportResponse> ClearInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent))
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Device not found or missing certificate",
                    ClearanceStatus = ClearanceStatus.Error
                };
            }
            
            try
            {
                // Create HTTP client for ZATCA API
                var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
                
                // Prepare the clearance request
                var requestUrl = _configuration["ZatcaApi:ClearanceEndpoint"];
                
                // Convert the signed XML to Base64
                var signedInvoiceBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedInvoiceXml));
                
                // Prepare the request body
                var requestData = new
                {
                    invoiceHash = "",  // This would be calculated in a real implementation
                    uuid = "",         // This would be extracted from the invoice in a real implementation
                    invoice = signedInvoiceBase64
                };
                
                var content = new StringContent(
                    JsonSerializer.Serialize(requestData),
                    Encoding.UTF8,
                    "application/json");
                
                // Add required headers
                httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
                httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
                
                // Send the request
                var response = await httpClient.PostAsync(requestUrl, content);
                
                // Process the response
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
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
                    
                    string uuid = null;
                    if (responseObject.ContainsKey("uuid"))
                    {
                        uuid = responseObject["uuid"].GetString();
                    }
                    
                    string invoiceHash = null;
                    if (responseObject.ContainsKey("invoiceHash"))
                    {
                        invoiceHash = responseObject["invoiceHash"].GetString();
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
                    
                    // Return the response
                    return new InvoiceReportResponse
                    {
                        Status = "Success",
                        Message = "Invoice cleared successfully",
                        ZatcaReportId = reportId,
                        UUID = uuid,
                        InvoiceHash = invoiceHash,
                        ClearanceStatus = clearanceStatus,
                        ValidationWarnings = validationWarnings,
                        ComplianceStatus = clearanceStatus == ClearanceStatus.Cleared ? "Compliant" : "Partially Compliant",
                        SignedInvoiceBase64 = signedInvoiceBase64,
                        ClearedInvoiceXmlUrls = clearedInvoiceXmlUrls
                    };
                }
                else
                {
                    // Handle error response
                    var responseContent = await response.Content.ReadAsStringAsync();
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
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent))
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Device not found or missing certificate",
                    ClearanceStatus = ClearanceStatus.Error
                };
            }
            
            try
            {
                // Create HTTP client for ZATCA API
                var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
                
                // Prepare the reporting request
                var requestUrl = _configuration["ZatcaApi:ReportingEndpoint"];
                
                // Convert the signed XML to Base64
                var signedInvoiceBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedInvoiceXml));
                
                // Prepare the request body
                var requestData = new
                {
                    invoiceHash = "",  // This would be calculated in a real implementation
                    uuid = "",         // This would be extracted from the invoice in a real implementation
                    invoice = signedInvoiceBase64
                };
                
                var content = new StringContent(
                    JsonSerializer.Serialize(requestData),
                    Encoding.UTF8,
                    "application/json");
                
                // Add required headers
                httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
                httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
                
                // Send the request
                var response = await httpClient.PostAsync(requestUrl, content);
                
                // Process the response
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var responseObject = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent);
                    
                    // Extract validation results if available
                    var validationWarnings = new List<ZatcaValidationWarning>();
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
                    
                    string uuid = null;
                    if (responseObject.ContainsKey("uuid"))
                    {
                        uuid = responseObject["uuid"].GetString();
                    }
                    
                    string invoiceHash = null;
                    if (responseObject.ContainsKey("invoiceHash"))
                    {
                        invoiceHash = responseObject["invoiceHash"].GetString();
                    }
                    
                    // Return the response
                    return new InvoiceReportResponse
                    {
                        Status = "Success",
                        Message = "Invoice reported successfully",
                        ZatcaReportId = reportId,
                        UUID = uuid,
                        InvoiceHash = invoiceHash,
                        ClearanceStatus = ClearanceStatus.Pending,
                        ValidationWarnings = validationWarnings,
                        ComplianceStatus = "Reported",
                        SignedInvoiceBase64 = signedInvoiceBase64
                    };
                }
                else
                {
                    // Handle error response
                    var responseContent = await response.Content.ReadAsStringAsync();
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
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = $"Reporting process error: {ex.Message}",
                    ClearanceStatus = ClearanceStatus.Error
                };
            }
        }
        
        public async Task<bool> CheckInvoiceComplianceStatusAsync(string uuid, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent))
            {
                return false;
            }
            
            try
            {
                // Create HTTP client for ZATCA API
                var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
                
                // Prepare the compliance check request
                var requestUrl = $"{_configuration["ZatcaApi:ComplianceCheckEndpoint"]}/{uuid}";
                
                // Add required headers
                httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
                httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
                
                // Send the request
                var response = await httpClient.GetAsync(requestUrl);
                
                // Process the response
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
        
        public async Task<string> GetClearedInvoiceAsync(string uuid, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent))
            {
                return null;
            }
            
            try
            {
                // Create HTTP client for ZATCA API
                var httpClient = _httpClientFactory.CreateClient("ZatcaApi");
                
                // Prepare the cleared invoice request
                var requestUrl = $"{_configuration["ZatcaApi:ClearedInvoiceEndpoint"]}/{uuid}";
                
                // Add required headers
                httpClient.DefaultRequestHeaders.Add("Accept-Language", "en");
                httpClient.DefaultRequestHeaders.Add("Accept-Version", "V2");
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {GetBasicAuthHeader(device)}");
                
                // Send the request
                var response = await httpClient.GetAsync(requestUrl);
                
                // Process the response
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    return null;
                }
            }
            catch
            {
                return null;
            }
        }
        
        private string GetBasicAuthHeader(Device device)
        {
            // In a real implementation, this would generate the Basic Auth header required by ZATCA API
            // consisting of the certificate details and device token
            var combinedCredentials = $"{device.CertificateSerialNumber}:{device.ZatcaDeviceToken}";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(combinedCredentials));
        }
    }
    
    // Auth Service implementation
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

        public async Task<User> RegisterUserAsync(User user, string password)
        {
            if (await _context.Users.AnyAsync(u => u.Username == user.Username))
            {
                return null;
            }

            user.PasswordHash = HashPassword(password);
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return user;
        }

        public async Task<User> GetUserByUsernameAsync(string username)
        {
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Username == username);
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
    
    // Controller Implementations
    [ApiController]
    [Route("api/devices")]
    public class DeviceController : ControllerBase
    {
        private readonly IDeviceService _deviceService;

        public DeviceController(IDeviceService deviceService)
        {
            _deviceService = deviceService;
        }

        [HttpPost("register")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RegisterDevice([FromBody] DeviceRegistrationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _deviceService.RegisterDeviceAsync(request);
            if (result.Status == "Error")
            {
                return BadRequest(result);
            }

            return Ok(result);
        }

        [HttpGet("{serialNumber}")]
        [Authorize]
        public async Task<IActionResult> GetDeviceBySerialNumber(string serialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(serialNumber);
            if (device == null)
            {
                return NotFound();
            }

            return Ok(device);
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllDevices()
        {
            var devices = await _deviceService.GetAllDevicesAsync();
            return Ok(devices);
        }

        [HttpPut("{serialNumber}/status")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateDeviceStatus(string serialNumber, [FromBody] DeviceStatus status)
        {
            var result = await _deviceService.UpdateDeviceStatusAsync(serialNumber, status);
            if (!result)
            {
                return NotFound();
            }

            return NoContent();
        }
        
        [HttpPost("{serialNumber}/generatecsr")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GenerateCSR(string serialNumber)
        {
            var result = await _deviceService.GenerateCSRAsync(serialNumber);
            if (!result)
            {
                return NotFound("Device not found or CSR generation failed");
            }

            return Ok(new { Message = "CSR generated successfully" });
        }
        
        [HttpPost("{serialNumber}/compliancecertificate")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RequestComplianceCertificate(string serialNumber)
        {
            var result = await _deviceService.RequestComplianceCertificateAsync(serialNumber);
            if (!result)
            {
                return BadRequest("Failed to request compliance certificate");
            }

            return Ok(new { Message = "Compliance certificate requested successfully" });
        }
        
        [HttpPost("{serialNumber}/productioncertificate")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RequestProductionCertificate(string serialNumber, [FromBody] string otp)
        {
            var result = await _deviceService.RequestProductionCertificateAsync(serialNumber, otp);
            if (!result)
            {
                return BadRequest("Failed to request production certificate");
            }

            return Ok(new { Message = "Production certificate requested successfully" });
        }
        
        [HttpPost("{serialNumber}/renewcertificate")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RenewCertificate(string serialNumber)
        {
            var result = await _deviceService.RenewCertificateAsync(serialNumber);
            if (!result)
            {
                return BadRequest("Failed to renew certificate");
            }

            return Ok(new { Message = "Certificate renewal initiated" });
        }
        
        [HttpGet("{serialNumber}/certificate")]
        [Authorize]
        public async Task<IActionResult> GetCertificateDetails(string serialNumber)
        {
            var result = await _deviceService.GetCertificateDetailsAsync(serialNumber);
            if (string.IsNullOrEmpty(result))
            {
                return NotFound("Certificate not found");
            }

            return Ok(new { CertificateDetails = result });
        }
    }

    [ApiController]
    [Route("api/invoices")]
    public class InvoiceController : ControllerBase
    {
        private readonly IZatcaService _zatcaService;

        public InvoiceController(IZatcaService zatcaService)
        {
            _zatcaService = zatcaService;
        }

        [HttpPost("report")]
        [Authorize]
        public async Task<IActionResult> ReportInvoice([FromBody] InvoiceReportRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.ReportInvoiceAsync(request);
            if (result.Status == "Error")
            {
                return BadRequest(result);
            }

            return Ok(result);
        }

        [HttpPost("creditnote")]
        [Authorize]
        public async Task<IActionResult> ReportCreditNote([FromBody] CreditNoteReportRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.ReportCreditNoteAsync(request);
            if (result.Status == "Error")
            {
                return BadRequest(result);
            }

            return Ok(result);
        }

        [HttpPost("debitnote")]
        [Authorize]
        public async Task<IActionResult> ReportDebitNote([FromBody] DebitNoteReportRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.ReportDebitNoteAsync(request);
            if (result.Status == "Error")
            {
                return BadRequest(result);
            }

            return Ok(result);
        }

        [HttpPost("salesreturn")]
        [Authorize]
        public async Task<IActionResult> ReportSalesReturn([FromBody] SalesReturnReportRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.ReportSalesReturnAsync(request);
            if (result.Status == "Error")
            {
                return BadRequest(result);
            }

            return Ok(result);
        }
        
        [HttpPost("validate")]
        [Authorize]
        public async Task<IActionResult> ValidateInvoice([FromBody] string invoiceXml, string deviceSerialNumber)
        {
            var result = await _zatcaService.ValidateInvoiceAsync(invoiceXml, deviceSerialNumber);
            return Ok(new { ValidationResults = result });
        }
        
        [HttpPost("generatexml")]
        [Authorize]
        public async Task<IActionResult> GenerateInvoiceXml([FromBody] InvoiceReportRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _zatcaService.GenerateInvoiceXmlAsync(request);
            return Ok(new { InvoiceXml = result });
        }
    }

    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            var response = await _authService.AuthenticateAsync(request);
            if (response == null)
            {
                return Unauthorized();
            }

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
                return BadRequest("User with this username already exists");
            }

            return Ok(new
            {
                Username = result.Username,
                Email = result.Email,
                Role = result.Role.ToString()
            });
        }
    }

    // User Registration DTO
    public class UserRegistrationRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public string Email { get; set; }
        public string CompanyName { get; set; }
        public string VatRegistrationNumber { get; set; }
        public UserRole Role { get; set; } = UserRole.User;
    }        public async Task<string> ValidateInvoiceAsync(string invoiceXml, string deviceSerialNumber)
        {
            // Validate the invoice XML against UBL 2.1 schema and ZATCA business rules
            var (isValid, validationErrors) = await _xmlValidator.ValidateUBLInvoiceAsync(invoiceXml);
            
            if (!isValid)
            {
                return string.Join(", ", validationErrors);
            }
            
            return "Validation successful";
        }
    }
    
    // Implementation of XML Schema Validator
    public class XmlSchemaValidator : IXmlSchemaValidator
    {
        private readonly IConfiguration _configuration;
        
        public XmlSchemaValidator(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        public async Task<bool> ValidateXmlAgainstSchemaAsync(string xml, string schemaFileName)
        {
            try
            {
                // Load the schema
                var schemaPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Schemas", schemaFileName);
                var schema = XmlSchema.Read(new XmlTextReader(schemaPath), null);
                
                var schemas = new XmlSchemaSet();
                schemas.Add(schema);
                
                // Validate the XML
                var document = new XmlDocument();
                document.LoadXml(xml);
                
                document.Schemas = schemas;
                document.Validate(null);
                
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
        
        public async Task<(bool isValid, List<string> errors)> ValidateUBLInvoiceAsync(string xml)
        {
            var errors = new List<string>();
            
            try
            {
                // 1. Validate against UBL 2.1 Invoice schema
                var isValidAgainstSchema = await ValidateXmlAgainstSchemaAsync(xml, "UBL-Invoice-2.1.xsd");
                if (!isValidAgainstSchema)
                {
                    errors.Add("XML does not conform to UBL 2.1 Invoice schema");
                }
                
                // 2. Validate ZATCA business rules
                var document = new XmlDocument();
                document.LoadXml(xml);
                
                // Check for required ZATCA namespaces
                var nsManager = new XmlNamespaceManager(document.NameTable);
                nsManager.AddNamespace("cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2");
                nsManager.AddNamespace("cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2");
                nsManager.AddNamespace("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
                
                // 3. Check invoice type code
                var invoiceTypeCodeNode = document.SelectSingleNode("//cbc:InvoiceTypeCode", nsManager);
                if (invoiceTypeCodeNode == null)
                {
                    errors.Add("Missing InvoiceTypeCode element");
                }
                
                // 4. Check for required elements
                var requiredElements = new[] 
                {
                    "//cbc:ProfileID", 
                    "//cbc:ID", 
                    "//cbc:IssueDate", 
                    "//cbc:IssueTime",
                    "//cac:AccountingSupplierParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
                    "//cac:AccountingCustomerParty/cac:Party/cac:PartyTaxScheme/cbc:CompanyID",
                    "//cbc:DocumentCurrencyCode"
                };
                
                foreach (var element in requiredElements)
                {
                    var node = document.SelectSingleNode(element, nsManager);
                    if (node == null)
                    {
                        errors.Add($"Missing required element: {element}");
                    }
                }
                
                // 5. Check for ZATCA specific extensions (signature placeholder, QR code placeholder)
                var extensionNode = document.SelectSingleNode("//ext:UBLExtensions", nsManager);
                if (extensionNode == null)
                {
                    errors.Add("Missing UBLExtensions element for ZATCA requirements");
                }
                
                return (errors.Count == 0, errors);
            }
            catch (Exception ex)
            {
                errors.Add($"Validation error: {ex.Message}");
                return (false, errors);
            }
        }
        
        public async Task<string> ConvertToUBLXmlAsync(InvoiceReportRequest request)
        {
            // Generate a UBL 2.1 XML document based on the invoice request
            var ublDocument = new XmlDocument();
            
            // XML Declaration
            var xmlDeclaration = ublDocument.CreateXmlDeclaration("1.0", "UTF-8", null);
            ublDocument.AppendChild(xmlDeclaration);
            
            // Create root element with required namespaces
            var rootElement = ublDocument.CreateElement("Invoice", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2");
            
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
            
            ublDocument.AppendChild(rootElement);
            
            // UBL Extensions for ZATCA (Signature and QR code placeholders)
            var ublExtensions = ublDocument.CreateElement("ext", "UBLExtensions", namespaces["ext"]);
            rootElement.AppendChild(ublExtensions);
            
            // Add extension for signature
            var signatureExtension = ublDocument.CreateElement("ext", "UBLExtension", namespaces["ext"]);
            ublExtensions.AppendChild(signatureExtension);
            
            var extContent = ublDocument.CreateElement("ext", "ExtensionContent", namespaces["ext"]);
            signatureExtension.AppendChild(extContent);
            
            // Add extension for QR code
            var qrExtension = ublDocument.CreateElement("ext", "UBLExtension", namespaces["ext"]);
            ublExtensions.AppendChild(qrExtension);
            
            var qrExtContent = ublDocument.CreateElement("ext", "ExtensionContent", namespaces["ext"]);
            qrExtension.AppendChild(qrExtContent);
            
            // Add document elements
            
            // Profile ID (Standard/Simplified)
            var profileID = ublDocument.CreateElement("cbc", "ProfileID", namespaces["cbc"]);
            profileID.InnerText = request.InvoiceType == InvoiceType.Standard ? "reporting:1.0" : "simplified:1.0";
            rootElement.AppendChild(profileID);
            
            // Invoice ID
            var id = ublDocument.CreateElement("cbc", "ID", namespaces["cbc"]);
            id.InnerText = request.DocumentNumber;
            rootElement.AppendChild(id);
            
            // UUID
            var uuid = ublDocument.CreateElement("cbc", "UUID", namespaces["cbc"]);
            uuid.InnerText = Guid.NewGuid().ToString();
            rootElement.AppendChild(uuid);
            
            // Issue Date
            var issueDate = ublDocument.CreateElement("cbc", "IssueDate", namespaces["cbc"]);
            issueDate.InnerText = request.DocumentDate.ToString("yyyy-MM-dd");
            rootElement.AppendChild(issueDate);
            
            // Issue Time
            var issueTime = ublDocument.CreateElement("cbc", "IssueTime", namespaces["cbc"]);
            issueTime.InnerText = request.DocumentIssueTime.ToString("HH:mm:ss");
            rootElement.AppendChild(issueTime);
            
            // Invoice Type Code
            var invoiceTypeCode = ublDocument.CreateElement("cbc", "InvoiceTypeCode", namespaces["cbc"]);
            
            // Set the appropriate invoice type code based on transaction type
            switch (request.TransactionType)
            {
                case InvoiceTransactionType.Standard:
                    invoiceTypeCode.InnerText = "388"; // Standard Tax Invoice
                    break;
                case InvoiceTransactionType.CreditNote:
                    invoiceTypeCode.InnerText = "381"; // Credit Note
                    break;
                case InvoiceTransactionType.DebitNote:
                    invoiceTypeCode.InnerText = "383"; // Debit Note
                    break;
                default:
                    invoiceTypeCode.InnerText = "388"; // Default to Standard
                    break;
            }
            rootElement.AppendChild(invoiceTypeCode);
            
            // Document Currency Code
            var currencyCode = ublDocument.CreateElement("cbc", "DocumentCurrencyCode", namespaces["cbc"]);
            currencyCode.InnerText = request.InvoiceCurrency;
            rootElement.AppendChild(currencyCode);
            
            // Tax Currency Code
            var taxCurrencyCode = ublDocument.CreateElement("cbc", "TaxCurrencyCode", namespaces["cbc"]);
            taxCurrencyCode.InnerText = "SAR"; // Always SAR for ZATCA
            rootElement.AppendChild(taxCurrencyCode);
            
            // Add supplier information
            var accountingSupplierParty = ublDocument.CreateElement("cac", "AccountingSupplierParty", namespaces["cac"]);
            rootElement.AppendChild(accountingSupplierParty);
            
            var supplierParty = ublDocument.CreateElement("cac", "Party", namespaces["cac"]);
            accountingSupplierParty.AppendChild(supplierParty);
            
            // Supplier postal address
            var supplierPostalAddress = ublDocument.CreateElement("cac", "PostalAddress", namespaces["cac"]);
            supplierParty.AppendChild(supplierPostalAddress);
            
            // Street Name
            if (!string.IsNullOrEmpty(request.SellerStreetName))
            {
                var streetName = ublDocument.CreateElement("cbc", "StreetName", namespaces["cbc"]);
                streetName.InnerText = request.SellerStreetName;
                supplierPostalAddress.AppendChild(streetName);
            }
            
            // Building Number
            if (!string.IsNullOrEmpty(request.SellerBuildingNumber))
            {
                var buildingNumber = ublDocument.CreateElement("cbc", "BuildingNumber", namespaces["cbc"]);
                buildingNumber.InnerText = request.SellerBuildingNumber;
                supplierPostalAddress.AppendChild(buildingNumber);
            }
            
            // City Name
            if (!string.IsNullOrEmpty(request.SellerCityName))
            {
                var cityName = ublDocument.CreateElement("cbc", "CityName", namespaces["cbc"]);
                cityName.InnerText = request.SellerCityName;
                supplierPostalAddress.AppendChild(cityName);
            }
            
            // Postal Zone
            if (!string.IsNullOrEmpty(request.SellerPostalCode))
            {
                var postalZone = ublDocument.CreateElement("cbc", "PostalZone", namespaces["cbc"]);
                postalZone.InnerText = request.SellerPostalCode;
                supplierPostalAddress.AppendChild(postalZone);
            }
            
            // Country
            var country = ublDocument.CreateElement("cac", "Country", namespaces["cac"]);
            supplierPostalAddress.AppendChild(country);
            
            var identificationCode = ublDocument.CreateElement("cbc", "IdentificationCode", namespaces["cbc"]);
            identificationCode.InnerText = request.SellerCountryCode;
            country.AppendChild(identificationCode);
            
            // Seller Tax Scheme
            var sellerPartyTaxScheme = ublDocument.CreateElement("cac", "PartyTaxScheme", namespaces["cac"]);
            supplierParty.AppendChild(sellerPartyTaxScheme);
            
            var sellerCompanyID = ublDocument.CreateElement("cbc", "CompanyID", namespaces["cbc"]);
            sellerCompanyID.InnerText = request.SellerVatNumber;
            sellerPartyTaxScheme.AppendChild(sellerCompanyID);
            
            var sellerTaxScheme = ublDocument.CreateElement("cac", "TaxScheme", namespaces["cac"]);
            sellerPartyTaxScheme.AppendChild(sellerTaxScheme);
            
            var sellerTaxSchemeID = ublDocument.CreateElement("cbc", "ID", namespaces["cbc"]);
            sellerTaxSchemeID.InnerText = "VAT";
            sellerTaxScheme.AppendChild(sellerTaxSchemeID);
            
            // Seller Legal Entity
            var sellerLegalEntity = ublDocument.CreateElement("cac", "PartyLegalEntity", namespaces["cac"]);
            supplierParty.AppendChild(sellerLegalEntity);
            
            var sellerRegistrationName = ublDocument.CreateElement("cbc", "RegistrationName", namespaces["cbc"]);
            sellerRegistrationName.InnerText = request.SellerName;
            sellerLegalEntity.AppendChild(sellerRegistrationName);
            
            // Add customer information
            var accountingCustomerParty = ublDocument.CreateElement("cac", "AccountingCustomerParty", namespaces["cac"]);
            rootElement.AppendChild(accountingCustomerParty);
            
            var customerParty = ublDocument.CreateElement("cac", "Party", namespaces["cac"]);
            accountingCustomerParty.AppendChild(customerParty);
            
            // Customer postal address
            var customerPostalAddress = ublDocument.CreateElement("cac", "PostalAddress", namespaces["cac"]);
            customerParty.AppendChild(customerPostalAddress);
            
            // Customer Street Name
            if (!string.IsNullOrEmpty(request.BuyerStreetName))
            {
                var streetName = ublDocument.CreateElement("cbc", "StreetName", namespaces["cbc"]);
                streetName.InnerText = request.BuyerStreetName;
                customerPostalAddress.AppendChild(streetName);
            }
            
            // Building Number
            if (!string.IsNullOrEmpty(request.BuyerBuildingNumber))
            {
                var buildingNumber = ublDocument.CreateElement("cbc", "BuildingNumber", namespaces["cbc"]);
                buildingNumber.InnerText = request.BuyerBuildingNumber;
                customerPostalAddress.AppendChild(buildingNumber);
            }
            
            // City Name
            if (!string.IsNullOrEmpty(request.BuyerCityName))
            {
                var cityName = ublDocument.CreateElement("cbc", "CityName", namespaces["cbc"]);
                cityName.InnerText = request.BuyerCityName;
                customerPostalAddress.AppendChild(cityName);
            }
            
            // Postal Zone
            if (!string.IsNullOrEmpty(request.BuyerPostalCode))
            {
                var postalZone = ublDocument.CreateElement("cbc", "PostalZone", namespaces["cbc"]);
                postalZone.InnerText = request.BuyerPostalCode;
                customerPostalAddress.AppendChild(postalZone);
            }
            
            // Country
            var buyerCountry = ublDocument.CreateElement("cac", "Country", namespaces["cac"]);
            customerPostalAddress.AppendChild(buyerCountry);
            
            var buyerIdentificationCode = ublDocument.CreateElement("cbc", "IdentificationCode", namespaces["cbc"]);
            buyerIdentificationCode.InnerText = request.BuyerCountryCode;
            buyerCountry.AppendChild(buyerIdentificationCode);
            
            // Buyer Tax Scheme
            var buyerPartyTaxScheme = ublDocument.CreateElement("cac", "PartyTaxScheme", namespaces["cac"]);
            customerParty.AppendChild(buyerPartyTaxScheme);
            
            var buyerCompanyID = ublDocument.CreateElement("cbc", "CompanyID", namespaces["cbc"]);
            buyerCompanyID.InnerText = request.BuyerVatNumber;
            buyerPartyTaxScheme.AppendChild(buyerCompanyID);
            
            var buyerTaxScheme = ublDocument.CreateElement("cac", "TaxScheme", namespaces["cac"]);
            buyerPartyTaxScheme.AppendChild(buyerTaxScheme);
            
            var buyerTaxSchemeID = ublDocument.CreateElement("cbc", "ID", namespaces["cbc"]);
            buyerTaxSchemeID.InnerText = "VAT";
            buyerTaxScheme.AppendChild(buyerTaxSchemeID);
            
            // Buyer Legal Entity
            var buyerLegalEntity = ublDocument.CreateElement("cac", "PartyLegalEntity", namespaces["cac"]);
            customerParty.AppendChild(buyerLegalEntity);
            
            var buyerRegistrationName = ublDocument.CreateElement("cbc", "RegistrationName", namespaces["cbc"]);
            buyerRegistrationName.InnerText = request.BuyerName;
            buyerLegalEntity.AppendChild(buyerRegistrationName);
            
            // Payment Means
            if (!string.IsNullOrEmpty(request.PaymentMethod))
            {
                var paymentMeans = ublDocument.CreateElement("cac", "PaymentMeans", namespaces["cac"]);
                rootElement.AppendChild(paymentMeans);
                
                var paymentMeansCode = ublDocument.CreateElement("cbc", "PaymentMeansCode", namespaces["cbc"]);
                paymentMeansCode.InnerText = request.PaymentMethod;
                paymentMeans.AppendChild(paymentMeansCode);
                
                if (request.PaymentDueDate.HasValue)
                {
                    var paymentDueDate = ublDocument.CreateElement("cbc", "PaymentDueDate", namespaces["cbc"]);
                    paymentDueDate.InnerText = request.PaymentDueDate.Value.ToString("yyyy-MM-dd");
                    paymentMeans.AppendChild(paymentDueDate);
                }
            }
            
            // Tax Total
            var taxTotal = ublDocument.CreateElement("cac", "TaxTotal", namespaces["cac"]);
            rootElement.AppendChild(taxTotal);
            
            var taxAmount = ublDocument.CreateElement("cbc", "TaxAmount", namespaces["cbc"]);
            taxAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            taxAmount.InnerText = request.VatAmount.ToString("0.00");
            taxTotal.AppendChild(taxAmount);
            
            // Tax Subtotal
            var taxSubtotal = ublDocument.CreateElement("cac", "TaxSubtotal", namespaces["cac"]);
            taxTotal.AppendChild(taxSubtotal);
            
            var taxableAmount = ublDocument.CreateElement("cbc", "TaxableAmount", namespaces["cbc"]);
            taxableAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            taxableAmount.InnerText = request.TotalWithoutVat.ToString("0.00");
            taxSubtotal.AppendChild(taxableAmount);
            
            var subtotalTaxAmount = ublDocument.CreateElement("cbc", "TaxAmount", namespaces["cbc"]);
            subtotalTaxAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            subtotalTaxAmount.InnerText = request.VatAmount.ToString("0.00");
            taxSubtotal.AppendChild(subtotalTaxAmount);
            
            // Tax Category
            var taxCategory = ublDocument.CreateElement("cac", "TaxCategory", namespaces["cac"]);
            taxSubtotal.AppendChild(taxCategory);
            
            var taxScheme = ublDocument.CreateElement("cac", "TaxScheme", namespaces["cac"]);
            taxCategory.AppendChild(taxScheme);
            
            var taxSchemeId = ublDocument.CreateElement("cbc", "ID", namespaces["cbc"]);
            taxSchemeId.InnerText = "VAT";
            taxScheme.AppendChild(taxSchemeId);
            
            // Legal Monetary Total
            var legalMonetaryTotal = ublDocument.CreateElement("cac", "LegalMonetaryTotal", namespaces["cac"]);
            rootElement.AppendChild(legalMonetaryTotal);
            
            var lineExtensionAmount = ublDocument.CreateElement("cbc", "LineExtensionAmount", namespaces["cbc"]);
            lineExtensionAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            lineExtensionAmount.InnerText = request.TotalWithoutVat.ToString("0.00");
            legalMonetaryTotal.AppendChild(lineExtensionAmount);
            
            var taxExclusiveAmount = ublDocument.CreateElement("cbc", "TaxExclusiveAmount", namespaces["cbc"]);
            taxExclusiveAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            taxExclusiveAmount.InnerText = request.TotalWithoutVat.ToString("0.00");
            legalMonetaryTotal.AppendChild(taxExclusiveAmount);
            
            var taxInclusiveAmount = ublDocument.CreateElement("cbc", "TaxInclusiveAmount", namespaces["cbc"]);
            taxInclusiveAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            taxInclusiveAmount.InnerText = (request.TotalWithoutVat + request.VatAmount).ToString("0.00");
            legalMonetaryTotal.AppendChild(taxInclusiveAmount);
            
            if (request.Discount > 0)
            {
                var allowanceTotalAmount = ublDocument.CreateElement("cbc", "AllowanceTotalAmount", namespaces["cbc"]);
                allowanceTotalAmount.SetAttribute("currencyID", request.InvoiceCurrency);
                allowanceTotalAmount.InnerText = request.Discount.ToString("0.00");
                legalMonetaryTotal.AppendChild(allowanceTotalAmount);
            }
            
            var payableAmount = ublDocument.CreateElement("cbc", "PayableAmount", namespaces["cbc"]);
            payableAmount.SetAttribute("currencyID", request.InvoiceCurrency);
            payableAmount.InnerText = (request.TotalWithoutVat + request.VatAmount).ToString("0.00");
            legalMonetaryTotal.AppendChild(payableAmount);
            
            // Invoice Lines
            if (request.LineItems != null && request.LineItems.Count > 0)
            {
                foreach (var item in request.LineItems)
                {
                    var invoiceLine = ublDocument.CreateElement("cac", "InvoiceLine", namespaces["cac"]);
                    rootElement.AppendChild(invoiceLine);
                    
                    var lineId = ublDocument.CreateElement("cbc", "ID", namespaces["cbc"]);
                    lineId.InnerText = item.LineNumber.ToString();
                    invoiceLine.AppendChild(lineId);
                    
                    var invoicedQuantity = ublDocument.CreateElement("cbc", "InvoicedQuantity", namespaces["cbc"]);
                    invoicedQuantity.SetAttribute("unitCode", item.UnitOfMeasure);
                    invoicedQuantity.InnerText = item.Quantity.ToString("0.00");
                    invoiceLine.AppendChild(invoicedQuantity);
                    
                    var lineExtensionAmountItem = ublDocument.CreateElement("cbc", "LineExtensionAmount", namespaces["cbc"]);
                    lineExtensionAmountItem.SetAttribute("currencyID", request.InvoiceCurrency);
                    lineExtensionAmountItem.InnerText = item.NetAmount.ToString("0.00");
                    invoiceLine.AppendChild(lineExtensionAmountItem);
                    
                    // Line Tax Total
                    var lineTaxTotal = ublDocument.CreateElement("cac", "TaxTotal", namespaces["cac"]);
                    invoiceLine.AppendChild(lineTaxTotal);
                    
                    var lineTaxAmount = ublDocument.CreateElement("cbc", "TaxAmount", namespaces["cbc"]);
                    lineTaxAmount.SetAttribute("currencyID", request.InvoiceCurrency);
                    lineTaxAmount.InnerText = item.VatAmount.ToString("0.00");
                    lineTaxTotal.AppendChild(lineTaxAmount);
                    
                    // Item description
                    var item1 = ublDocument.CreateElement("cac", "Item", namespaces["cac"]);
                    invoiceLine.AppendChild(item1);
                    
                    var itemName = ublDocument.CreateElement("cbc", "Name", namespaces["cbc"]);
                    itemName.InnerText = item.ItemName;
                    item1.AppendChild(itemName);
                    
                    if (!string.IsNullOrEmpty(item.ItemDescription))
                    {
                        var itemDescription = ublDocument.CreateElement("cbc", "Description", namespaces["cbc"]);
                        itemDescription.InnerText = item.ItemDescription;
                        item1.AppendChild(itemDescription);
                    }
                    
                    // Price
                    var price = ublDocument.CreateElement("cac", "Price", namespaces["cac"]);
                    invoiceLine.AppendChild(price);
                    
                    var priceAmount = ublDocument.CreateElement("cbc", "PriceAmount", namespaces["cbc"]);
                    priceAmount.SetAttribute("currencyID", request.InvoiceCurrency);
                    priceAmount.InnerText = item.UnitPrice.ToString("0.00");
                    price.AppendChild(priceAmount);
                }
            }
            
            // Convert XML document to string
            using var stringWriter = new StringWriter();
            using var xmlTextWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { Indent = true });
            ublDocument.WriteTo(xmlTextWriter);
            xmlTextWriter.Flush();
            
            return stringWriter.ToString();
        }
        
        public string AddQRCodeToXml(string xml, string qrCode)
        {
            try
            {
                var document = new XmlDocument();
                document.LoadXml(xml);
                
                var nsManager = new XmlNamespaceManager(document.NameTable);
                nsManager.AddNamespace("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
                
                // Find the second UBLExtension element (for QR code)
                var extensions = document.SelectNodes("//ext:UBLExtension", nsManager);
                if (extensions != null && extensions.Count >= 2)
                {
                    var qrExtension = extensions[1];
                    var extContent = qrExtension.SelectSingleNode("ext:ExtensionContent", nsManager);
                    
                    if (extContent != null)
                    {
                        // Create a QR code element
                        var qrElement = document.CreateElement("qr", "QRCode", "urn:zatca:qr:schema:1.0");
                        qrElement.InnerText = qrCode;
                        extContent.AppendChild(qrElement);
                    }
                }
                
                using var stringWriter = new StringWriter();
                using var xmlTextWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { Indent = true });
                document.WriteTo(xmlTextWriter);
                xmlTextWriter.Flush();
                
                return stringWriter.ToString();
            }
            catch
            {
                // If there's an error, return the original XML
                return xml;
            }
        }
    }
    
    // Implementation of ZATCA Cryptography Service
    public class ZatcaCryptographyService : IZatcaCryptographyService
    {
        private readonly IDeviceService _deviceService;
        
        public ZatcaCryptographyService(IDeviceService deviceService)
        {
            _deviceService = deviceService;
        }
        
        public async Task<string> SignXmlAsync(string invoiceXml, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent) || 
                string.IsNullOrEmpty(device.PrivateKeyContent))
            {
                return null;
            }

            try
            {
                // Load XML document
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.LoadXml(invoiceXml);
                
                // Create a reference to be signed
                var signedXml = new SignedXml(xmlDoc);
                
                // Load the certificate
                var certificate = new X509Certificate2(
                    Convert.FromBase64String(device.CertificateContent),
                    string.Empty,
                    X509KeyStorageFlags.Exportable);
                
                // Load the private key (would need proper implementation based on private key format)
                // This is a placeholder for actual implementation
                var rsa = RSA.Create();
                
                // In a real implementation, you would parse and load the private key
                // rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                
                // Set key for signing
                signedXml.SigningKey = rsa;
                
                // Create a reference to the entire document
                var reference = new Reference();
                reference.Uri = "";
                
                // Add a transform to canonicalize the XML
                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);
                
                var c14n = new XmlDsigC14NTransform();
                reference.AddTransform(c14n);
                
                // Add the reference to the SignedXml object
                signedXml.AddReference(reference);
                
                // Add key info
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(certificate));
                signedXml.KeyInfo = keyInfo;
                
                // Compute the signature
                signedXml.ComputeSignature();
                
                // Get the XML representation of the signature
                var xmlDigitalSignature = signedXml.GetXml();
                
                // Append the signature to the right location
                var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
                nsManager.AddNamespace("ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2");
                
                var extensions = xmlDoc.SelectNodes("//ext:UBLExtension", nsManager);
                if (extensions != null && extensions.Count > 0)
                {
                    var signatureExtension = extensions[0];
                    var extContent = signatureExtension.SelectSingleNode("ext:ExtensionContent", nsManager);
                    
                    if (extContent != null)
                    {
                        var importedNode = xmlDoc.ImportNode(xmlDigitalSignature, true);
                        extContent.AppendChild(importedNode);
                    }
                }
                
                // Convert back to string
                using var stringWriter = new StringWriter();
                using var xmlTextWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { Indent = true });
                xmlDoc.WriteTo(xmlTextWriter);
                xmlTextWriter.Flush();
                
                return stringWriter.ToString();
            }
            catch (Exception ex)
            {
                // Log exception
                return null;
            }
        }
        
        public async Task<string> GenerateInvoiceHashAsync(string xml)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(xml);
            var hashBytes = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hashBytes);
        }
        
        public async Task<string> GetDigitalSignatureAsync(string invoiceXml, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent) || 
                string.IsNullOrEmpty(device.PrivateKeyContent))
            {
                return null;
            }
            
            try
            {
                // Load the certificate
                var certificate = new X509Certificate2(
                    Convert.FromBase64String(device.CertificateContent),
                    string.Empty,
                    X509KeyStorageFlags.Exportable);
                
                // Load the private key (placeholder)
                var rsa = RSA.Create();
                
                // In a real implementation, you would parse and load the private key
                // rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                
                // Generate hash for the invoice
                var hash = await CalculateInvoiceHashAsync(invoiceXml);
                var hashBytes = Convert.FromBase64String(hash);
                
                // Sign the hash
                var signature = rsa.SignHash(hashBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                
                return Convert.ToBase64String(signature);
            }
            catch (Exception ex)
            {
                // Log exception
                return null;
            }
        }
        
        public async Task<string> CalculateInvoiceHashAsync(string canonicalXml)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(canonicalXml);
            var hashBytes = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hashBytes);
        }
        
        public async Task<bool> ValidateSignatureAsync(string signedXml, string certificateContent)
        {
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.LoadXml(signedXml);
                
                var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
                nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
                
                var signatureNode = xmlDoc.SelectSingleNode("//ds:Signature", nsManager);
                if (signatureNode == null)
                {
                    return false;
                }
                
                var signedXmlObj = new SignedXml(xmlDoc);
                signedXmlObj.LoadXml((XmlElement)signatureNode);
                
                var certificate = new X509Certificate2(Convert.FromBase64String(certificateContent));
                var key = certificate.GetRSAPublicKey();
                
                return signedXmlObj.CheckSignature(key);
            }
            catch
            {
                return false;
            }
        }
        
        public async Task<string> GenerateCSRAsync(string commonName, string organizationName, string organizationUnit, string countryCode)
        {
            // In a real implementation, you would generate a Certificate Signing Request (CSR)
            // This is a placeholder implementation
            
            // Generate key pair
            using var rsa = RSA.Create(2048);
            
            // Export the private key for later use
            var privateKeyBytes = rsa.ExportRSAPrivateKey();
            var privateKey = Convert.ToBase64String(privateKeyBytes);
            
            // Generate a CSR
            var subjectName = new string[]
            {
                $"CN={commonName}",
                $"O={organizationName}",
                $"OU={organizationUnit}",
                $"C={countryCode}"
            };
            
            // This is a placeholder for real CSR generation
            // CSR would be generated using OpenSSL or BouncyCastle libraries
            var csrPlaceholder = $"-----BEGIN CERTIFICATE REQUEST-----\n{Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join(",", subjectName)))}\n-----END CERTIFICATE REQUEST-----";
            
            return csrPlaceholder;
        }
        
        public async Task<(string certificateContent, string privateKeyContent)> ProcessSignedCertificateAsync(string csrContent, string signedCertificate)
        {
            // In a real implementation, you would:
            // 1. Extract the signed certificate from the ZATCA response
            // 2. Match it with the private key from the CSR
            // 3. Return both for storage
            
            // This is a placeholder implementation
            return (signedCertificate, "placeholder-private-key");
        }
    }using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;
using System.Xml.Serialization;
using System.Xml.Schema;
using System.Xml.Linq;
using System.Security.Cryptography.Xml;

namespace ZatcaPhase2Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

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
        }
    }

    // DbContext
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

    // Models
    public class Device
    {
        public int Id { get; set; }
        [Required]
        public string DeviceSerialNumber { get; set; }
        [Required]
        public string DeviceName { get; set; }
        [Required]
        public string Model { get; set; }
        public string HardwareVersion { get; set; }
        public string SoftwareVersion { get; set; }
        public string ZatcaDeviceId { get; set; }
        public string ZatcaDeviceToken { get; set; }
        public DateTime? RegistrationDate { get; set; }
        public DateTime? LastCommunicationDate { get; set; }
        public DeviceStatus Status { get; set; }
        [Required]
        public string VatRegistrationNumber { get; set; }
        [Required]
        public string CompanyName { get; set; }
        public string CommercialRegistrationNumber { get; set; }
        public string StreetName { get; set; }
        public string BuildingNumber { get; set; }
        public string CityName { get; set; }
        public string DistrictName { get; set; }
        public string PostalCode { get; set; }
        public string CountryCode { get; set; } = "SA"; // Default to Saudi Arabia
        [JsonIgnore]
        public string CertificateContent { get; set; }
        [JsonIgnore]
        public string PrivateKeyContent { get; set; }
        [JsonIgnore]
        public string CsrContent { get; set; }
        public string CertificateSerialNumber { get; set; }
        public string OTP { get; set; }
        public DateTime? CertificateExpiryDate { get; set; }
        public ZatcaCertificateType CertificateType { get; set; } = ZatcaCertificateType.Production;
        public bool IsCertificateRenewRequired { get; set; } = false;
    }

    public enum DeviceStatus
    {
        Pending,
        Registered,
        Active,
        Suspended,
        Deactivated
    }

    public enum ZatcaCertificateType
    {
        Compliance,
        Production
    }
    
    public enum ClearanceStatus
    {
        Pending,
        Cleared,
        Rejected,
        PartialClearance,
        Error
    }
    
    public enum InvoiceTransactionType
    {
        Standard,
        Simplified,
        CreditNote,
        DebitNote
    }

    public class User
    {
        public int Id { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        [JsonIgnore]
        public string PasswordHash { get; set; }
        public string Email { get; set; }
        public string CompanyName { get; set; }
        public string VatRegistrationNumber { get; set; }
        public UserRole Role { get; set; }
    }

    public enum UserRole
    {
        Admin,
        User,
        ApiClient
    }

    public abstract class BaseReport
    {
        public int Id { get; set; }
        [Required]
        public string DocumentNumber { get; set; }
        [Required]
        public DateTime DocumentDate { get; set; }
        public DateTime DocumentIssueTime { get; set; }
        [Required]
        public string SellerName { get; set; }
        [Required]
        public string SellerVatNumber { get; set; }
        public string SellerStreetName { get; set; }
        public string SellerBuildingNumber { get; set; }
        public string SellerCityName { get; set; }
        public string SellerPostalCode { get; set; }
        public string SellerDistrictName { get; set; }
        public string SellerCountryCode { get; set; } = "SA";
        [Required]
        public string BuyerName { get; set; }
        [Required]
        public string BuyerVatNumber { get; set; }
        public string BuyerStreetName { get; set; }
        public string BuyerBuildingNumber { get; set; }
        public string BuyerCityName { get; set; }
        public string BuyerPostalCode { get; set; }
        public string BuyerDistrictName { get; set; }
        public string BuyerCountryCode { get; set; } = "SA";
        [Required]
        public decimal TotalAmount { get; set; }
        [Required]
        public decimal VatAmount { get; set; }
        public decimal TotalWithVat { get; set; }
        public decimal TotalWithoutVat { get; set; }
        public decimal Discount { get; set; }
        public string DocumentUUID { get; set; } = Guid.NewGuid().ToString();
        public string PIH { get; set; } // Previous Invoice Hash
        public string DocumentHash { get; set; } // Current Invoice Hash
        public string DocumentXml { get; set; }
        public string SignedDocumentXml { get; set; }
        public string EmbeddedQRCode { get; set; }
        public string ZatcaResponse { get; set; }
        public string ZatcaReportingStatus { get; set; }
        public string ZatcaValidationResults { get; set; }
        public string ZatcaComplianceStatus { get; set; }
        public List<ZatcaValidationWarning> ValidationWarnings { get; set; } = new List<ZatcaValidationWarning>();
        public string ZatcaQrCode { get; set; }
        public string ZatcaReportId { get; set; }
        public DateTime? ReportingDate { get; set; }
        public DateTime? ClearanceDate { get; set; }
        public ClearanceStatus ClearanceStatus { get; set; } = ClearanceStatus.Pending;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string DeviceSerialNumber { get; set; }
        public InvoiceType InvoiceType { get; set; }
        public InvoiceTransactionType TransactionType { get; set; } = InvoiceTransactionType.Standard;
        public string InvoiceCurrency { get; set; } = "SAR";
        public string PaymentMethod { get; set; }
        public DateTime? PaymentDueDate { get; set; }
        public List<InvoiceLineItem> LineItems { get; set; } = new List<InvoiceLineItem>();
    }
    
    public class ZatcaValidationWarning
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public string Category { get; set; }
        public string Status { get; set; }
    }
    
    public class InvoiceLineItem
    {
        public int Id { get; set; }
        public int LineNumber { get; set; }
        public string ItemName { get; set; }
        public string ItemDescription { get; set; }
        public decimal Quantity { get; set; }
        public string UnitOfMeasure { get; set; }
        public decimal UnitPrice { get; set; }
        public decimal NetAmount { get; set; }
        public decimal VatRate { get; set; }
        public decimal VatAmount { get; set; }
        public decimal TotalAmount { get; set; }
        public decimal DiscountAmount { get; set; }
        public decimal DiscountPercentage { get; set; }
    }

    public class InvoiceReport : BaseReport { }

    public class CreditNoteReport : BaseReport
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public class DebitNoteReport : BaseReport
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public class SalesReturnReport : BaseReport
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public enum InvoiceType
    {
        Standard,
        Simplified
    }

    // DTOs
    public class DeviceRegistrationRequest
    {
        [Required]
        public string DeviceSerialNumber { get; set; }
        [Required]
        public string DeviceName { get; set; }
        [Required]
        public string Model { get; set; }
        public string HardwareVersion { get; set; }
        public string SoftwareVersion { get; set; }
        [Required]
        public string VatRegistrationNumber { get; set; }
        [Required]
        public string CompanyName { get; set; }
        [Required]
        public string CommercialRegistrationNumber { get; set; }
        [Required]
        public string StreetName { get; set; }
        [Required]
        public string BuildingNumber { get; set; }
        [Required]
        public string CityName { get; set; }
        [Required]
        public string DistrictName { get; set; }
        [Required]
        public string PostalCode { get; set; }
        public string CountryCode { get; set; } = "SA";
        
        [JsonIgnore]
        public string CertificateContent { get; set; }
        [JsonIgnore]
        public string PrivateKeyContent { get; set; }
        [JsonIgnore]
        public string CsrContent { get; set; }
        public ZatcaCertificateType CertificateType { get; set; } = ZatcaCertificateType.Production;
    }

    public class DeviceRegistrationResponse
    {
        public string ZatcaDeviceId { get; set; }
        public string ZatcaDeviceToken { get; set; }
        public DateTime RegistrationDate { get; set; }
        public string Status { get; set; }
        public string Message { get; set; }
    }

    public class InvoiceReportRequest
    {
        [Required]
        public string DeviceSerialNumber { get; set; }
        [Required]
        public string DocumentNumber { get; set; }
        [Required]
        public DateTime DocumentDate { get; set; }
        public DateTime DocumentIssueTime { get; set; } = DateTime.UtcNow;
        [Required]
        public string SellerName { get; set; }
        [Required]
        public string SellerVatNumber { get; set; }
        public string SellerStreetName { get; set; }
        public string SellerBuildingNumber { get; set; }
        public string SellerCityName { get; set; }
        public string SellerPostalCode { get; set; }
        public string SellerDistrictName { get; set; }
        public string SellerCountryCode { get; set; } = "SA";
        [Required]
        public string BuyerName { get; set; }
        [Required]
        public string BuyerVatNumber { get; set; }
        public string BuyerStreetName { get; set; }
        public string BuyerBuildingNumber { get; set; }
        public string BuyerCityName { get; set; }
        public string BuyerPostalCode { get; set; }
        public string BuyerDistrictName { get; set; }
        public string BuyerCountryCode { get; set; } = "SA";
        [Required]
        public decimal TotalAmount { get; set; }
        [Required]
        public decimal TotalWithoutVat { get; set; }
        [Required]
        public decimal VatAmount { get; set; }
        public decimal Discount { get; set; }
        [Required]
        public InvoiceType InvoiceType { get; set; }
        public InvoiceTransactionType TransactionType { get; set; } = InvoiceTransactionType.Standard;
        public string InvoiceCurrency { get; set; } = "SAR";
        public string PaymentMethod { get; set; }
        public DateTime? PaymentDueDate { get; set; }
        public string PreviousInvoiceHash { get; set; }
        public List<InvoiceLineItemRequest> LineItems { get; set; } = new List<InvoiceLineItemRequest>();
        public string DocumentXml { get; set; }
        public bool GenerateXml { get; set; } = false;
    }
    
    public class InvoiceLineItemRequest
    {
        public int LineNumber { get; set; }
        [Required]
        public string ItemName { get; set; }
        public string ItemDescription { get; set; }
        [Required]
        public decimal Quantity { get; set; }
        [Required]
        public string UnitOfMeasure { get; set; } = "EA";
        [Required]
        public decimal UnitPrice { get; set; }
        [Required]
        public decimal NetAmount { get; set; }
        [Required]
        public decimal VatRate { get; set; }
        [Required]
        public decimal VatAmount { get; set; }
        [Required]
        public decimal TotalAmount { get; set; }
        public decimal DiscountAmount { get; set; }
        public decimal DiscountPercentage { get; set; }
    }

    public class InvoiceReportResponse
    {
        public string ZatcaReportId { get; set; }
        public string Status { get; set; }
        public string QrCode { get; set; }
        public string ValidationResults { get; set; }
        public string ComplianceStatus { get; set; }
        public string Message { get; set; }
        public string InvoiceHash { get; set; }
        public ClearanceStatus ClearanceStatus { get; set; }
        public string UUID { get; set; }
        public List<ZatcaValidationWarning> ValidationWarnings { get; set; } = new List<ZatcaValidationWarning>();
        public string SignedXml { get; set; }
        public string SignedInvoiceBase64 { get; set; }
        public string EncodedInvoice { get; set; }
        public List<string> ClearedInvoiceXmlUrls { get; set; } = new List<string>();
    }

    public class CreditNoteReportRequest : InvoiceReportRequest
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public class DebitNoteReportRequest : InvoiceReportRequest
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public class SalesReturnReportRequest : InvoiceReportRequest
    {
        [Required]
        public string RelatedInvoiceNumber { get; set; }
    }

    public class AuthRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }

    public class AuthResponse
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
    }

    // Interface definitions
    public interface IDeviceService
    {
        Task<DeviceRegistrationResponse> RegisterDeviceAsync(DeviceRegistrationRequest request);
        Task<Device> GetDeviceBySerialNumberAsync(string serialNumber);
        Task<List<Device>> GetAllDevicesAsync();
        Task<bool> UpdateDeviceStatusAsync(string serialNumber, DeviceStatus status);
        Task<bool> GenerateCSRAsync(string serialNumber);
        Task<bool> RequestComplianceCertificateAsync(string serialNumber);
        Task<bool> RequestProductionCertificateAsync(string serialNumber, string otp);
        Task<bool> RenewCertificateAsync(string serialNumber);
        Task<string> GetCertificateDetailsAsync(string serialNumber);
    }

    public interface IZatcaService
    {
        Task<InvoiceReportResponse> ReportInvoiceAsync(InvoiceReportRequest request);
        Task<InvoiceReportResponse> ReportCreditNoteAsync(CreditNoteReportRequest request);
        Task<InvoiceReportResponse> ReportDebitNoteAsync(DebitNoteReportRequest request);
        Task<InvoiceReportResponse> ReportSalesReturnAsync(SalesReturnReportRequest request);
        Task<string> GenerateInvoiceXmlAsync(InvoiceReportRequest request);
        Task<string> ValidateInvoiceAsync(string invoiceXml, string deviceSerialNumber);
    }
    
    public interface IQRCodeService
    {
        Task<string> GenerateQrCodeAsync(string sellerName, string vatNumber, DateTime timestamp, decimal totalWithVat, decimal vatAmount, string invoiceHash, string signature);
        Task<string> GenerateQrCodeFromInvoiceAsync(string invoiceXml, string signature);
        Task<(string base64QR, string tlvQR)> EncodeQrCodeAsync(string sellerName, string vatNumber, DateTime timestamp, decimal totalWithVat, decimal vatAmount, string invoiceHash, string signature);
        byte[] GenerateTLVEncodedQR(Dictionary<int, string> qrData);
    }
    
    public interface IZatcaCryptographyService
    {
        Task<string> SignXmlAsync(string invoiceXml, string deviceSerialNumber);
        Task<string> GenerateInvoiceHashAsync(string xml);
        Task<string> GetDigitalSignatureAsync(string invoiceXml, string deviceSerialNumber);
        Task<string> CalculateInvoiceHashAsync(string canonicalXml);
        Task<bool> ValidateSignatureAsync(string signedXml, string certificateContent);
        Task<string> GenerateCSRAsync(string commonName, string organizationName, string organizationUnit, string countryCode);
        Task<(string certificateContent, string privateKeyContent)> ProcessSignedCertificateAsync(string csrContent, string signedCertificate);
    }
    
    public interface IXmlSchemaValidator
    {
        Task<bool> ValidateXmlAgainstSchemaAsync(string xml, string schemaFileName);
        Task<(bool isValid, List<string> errors)> ValidateUBLInvoiceAsync(string xml);
        Task<string> ConvertToUBLXmlAsync(InvoiceReportRequest request);
        string AddQRCodeToXml(string xml, string qrCode);
    }
    
    public interface IClearanceService
    {
        Task<InvoiceReportResponse> ClearInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber);
        Task<InvoiceReportResponse> ReportInvoiceAsync(string signedInvoiceXml, string deviceSerialNumber);
        Task<bool> CheckInvoiceComplianceStatusAsync(string uuid, string deviceSerialNumber);
        Task<string> GetClearedInvoiceAsync(string uuid, string deviceSerialNumber);
    }

    public interface IAuthService
    {
        Task<AuthResponse> AuthenticateAsync(AuthRequest request);
        Task<User> RegisterUserAsync(User user, string password);
        Task<User> GetUserByUsernameAsync(string username);
    }

Id))
            {
                return new DeviceRegistrationResponse
                {
                    Status = "Error",
                    Message = "Failed to register device with ZATCA"
                };
            }

            // Save device information to database
            var device = new Device
            {
                DeviceSerialNumber = request.DeviceSerialNumber,
                DeviceName = request.DeviceName,
                Model = request.Model,
                HardwareVersion = request.HardwareVersion,
                SoftwareVersion = request.SoftwareVersion,
                VatRegistrationNumber = request.VatRegistrationNumber,
                CompanyName = request.CompanyName,
                ZatcaDeviceId = zatcaResponse.ZatcaDeviceId,
                ZatcaDeviceToken = zatcaResponse.ZatcaDeviceToken,
                RegistrationDate = DateTime.UtcNow,
                LastCommunicationDate = DateTime.UtcNow,
                Status = DeviceStatus.Registered,
                CertificateContent = request.CertificateContent,
                PrivateKeyContent = request.PrivateKeyContent
            };

            _context.Devices.Add(device);
            await _context.SaveChangesAsync();

            return new DeviceRegistrationResponse
            {
                ZatcaDeviceId = zatcaResponse.ZatcaDeviceId,
                ZatcaDeviceToken = zatcaResponse.ZatcaDeviceToken,
                RegistrationDate = device.RegistrationDate.Value,
                Status = "Success",
                Message = "Device successfully registered with ZATCA"
            };
        }

        public async Task<string> GetCertificateDetailsAsync(string serialNumber)
        {
            var device = await _context.Devices
                .FirstOrDefaultAsync(d => d.DeviceSerialNumber == serialNumber);

            if (device == null || string.IsNullOrEmpty(device.CertificateContent))
            {
                return "No certificate information available";
            }

            try
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(device.CertificateContent));
                return $"Subject: {certificate.Subject}\n" +
                       $"Issuer: {certificate.Issuer}\n" +
                       $"Serial Number: {certificate.SerialNumber}\n" +
                       $"Not Before: {certificate.NotBefore}\n" +
                       $"Not After: {certificate.NotAfter}\n" +
                       $"Thumbprint: {certificate.Thumbprint}";
            }
            catch (Exception ex)
            {
                return $"Error parsing certificate: {ex.Message}";
            }
        }

        public async Task<Device> GetDeviceBySerialNumberAsync(string serialNumber)
        {
            return await _context.Devices
                .FirstOrDefaultAsync(d => d.DeviceSerialNumber == serialNumber);
        }

        public async Task<List<Device>> GetAllDevicesAsync()
        {
            return await _context.Devices.ToListAsync();
        }

        public async Task<bool> UpdateDeviceStatusAsync(string serialNumber, DeviceStatus status)
        {
            var device = await _context.Devices
                .FirstOrDefaultAsync(d => d.DeviceSerialNumber == serialNumber);

            if (device == null)
            {
                return false;
            }

            device.Status = status;
            device.LastCommunicationDate = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }
    }

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

        public ZatcaService(
            ApplicationDbContext context,
            IHttpClientFactory httpClientFactory,
            IDeviceService deviceService,
            IConfiguration configuration,
            IZatcaCryptographyService cryptoService,
            IQRCodeService qrCodeService,
            IXmlSchemaValidator xmlValidator,
            IClearanceService clearanceService)
        {
            _context = context;
            _httpClientFactory = httpClientFactory;
            _deviceService = deviceService;
            _configuration = configuration;
            _cryptoService = cryptoService;
            _qrCodeService = qrCodeService;
            _xmlValidator = xmlValidator;
            _clearanceService = clearanceService;
        }

        public async Task<string> GenerateInvoiceXmlAsync(InvoiceReportRequest request)
        {
            // Generate UBL 2.1 XML from the request data
            return await _xmlValidator.ConvertToUBLXmlAsync(request);
        }
        
        public async Task<InvoiceReportResponse> ReportInvoiceAsync(InvoiceReportRequest request)
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

            string invoiceXml;
            // Generate or use provided invoice XML
            if (request.GenerateXml || string.IsNullOrEmpty(request.DocumentXml))
            {
                invoiceXml = await GenerateInvoiceXmlAsync(request);
            }
            else
            {
                invoiceXml = request.DocumentXml;
            }

            // Validate the XML against UBL 2.1 schema and ZATCA business rules
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

            // Generate hash for the invoice
            var invoiceHash = await _cryptoService.GenerateInvoiceHashAsync(invoiceXml);
            
            // Generate digital signature
            var signature = await _cryptoService.GetDigitalSignatureAsync(invoiceXml, request.DeviceSerialNumber);
            
            // Generate QR code with TLV format required by ZATCA
            var (base64QR, tlvQR) = await _qrCodeService.EncodeQrCodeAsync(
                request.SellerName,
                request.SellerVatNumber,
                request.DocumentIssueTime,
                request.TotalAmount + request.VatAmount,
                request.VatAmount,
                invoiceHash,
                signature);
            
            // Add QR code to the XML document
            var xmlWithQR = _xmlValidator.AddQRCodeToXml(invoiceXml, base64QR);
            
            // Sign the invoice XML using the device's certificate and private key
            var signedXml = await _cryptoService.SignXmlAsync(xmlWithQR, request.DeviceSerialNumber);
            if (string.IsNullOrEmpty(signedXml))
            {
                return new InvoiceReportResponse
                {
                    Status = "Error",
                    Message = "Failed to sign invoice XML"
                };
            }
            
            // Handle clearance or reporting based on invoice type
            InvoiceReportResponse zatcaResponse;
            
            // B2B standard invoices require clearance with ZATCA
            if (request.InvoiceType == InvoiceType.Standard && 
                (request.TransactionType == InvoiceTransactionType.Standard || 
                 request.TransactionType == InvoiceTransactionType.CreditNote ||
                 request.TransactionType == InvoiceTransactionType.DebitNote))
            {
                zatcaResponse = await _clearanceService.ClearInvoiceAsync(signedXml, request.DeviceSerialNumber);
            }
            else // Simplified invoices use reporting
            {
                zatcaResponse = await _clearanceService.ReportInvoiceAsync(signedXml, request.DeviceSerialNumber);
            }

            // Create UUID if not provided by ZATCA
            var uuid = zatcaResponse.UUID ?? Guid.NewGuid().ToString();
            
            // Save the report to database
            var report = new InvoiceReport
            {
                DocumentNumber = request.DocumentNumber,
                DocumentDate = request.DocumentDate,
                DocumentIssueTime = request.DocumentIssueTime,
                SellerName = request.SellerName,
                SellerVatNumber = request.SellerVatNumber,
                SellerStreetName = request.SellerStreetName,
                SellerBuildingNumber = request.SellerBuildingNumber,
                SellerCityName = request.SellerCityName,
                SellerPostalCode = request.SellerPostalCode,
                SellerDistrictName = request.SellerDistrictName,
                SellerCountryCode = request.SellerCountryCode,
                BuyerName = request.BuyerName,
                BuyerVatNumber = request.BuyerVatNumber,
                BuyerStreetName = request.BuyerStreetName,
                BuyerBuildingNumber = request.BuyerBuildingNumber,
                BuyerCityName = request.BuyerCityName,
                BuyerPostalCode = request.BuyerPostalCode,
                BuyerDistrictName = request.BuyerDistrictName,
                BuyerCountryCode = request.BuyerCountryCode,
                TotalAmount = request.TotalAmount,
                VatAmount = request.VatAmount,
                TotalWithVat = request.TotalAmount + request.VatAmount,
                TotalWithoutVat = request.TotalWithoutVat,
                Discount = request.Discount,
                DocumentUUID = uuid,
                PIH = request.PreviousInvoiceHash,
                DocumentHash = invoiceHash,
                DocumentXml = invoiceXml,
                SignedDocumentXml = signedXml,
                EmbeddedQRCode = base64QR,
                ZatcaResponse = JsonSerializer.Serialize(zatcaResponse),
                ZatcaReportingStatus = zatcaResponse.Status,
                ZatcaValidationResults = zatcaResponse.ValidationResults,
                ZatcaComplianceStatus = zatcaResponse.ComplianceStatus,
                ValidationWarnings = zatcaResponse.ValidationWarnings,
                ZatcaQrCode = base64QR,
                ZatcaReportId = zatcaResponse.ZatcaReportId,
                ReportingDate = DateTime.UtcNow,
                ClearanceDate = zatcaResponse.ClearanceStatus == ClearanceStatus.Cleared ? DateTime.UtcNow : null,
                ClearanceStatus = zatcaResponse.ClearanceStatus,
                DeviceSerialNumber = request.DeviceSerialNumber,
                InvoiceType = request.InvoiceType,
                TransactionType = request.TransactionType,
                InvoiceCurrency = request.InvoiceCurrency,
                PaymentMethod = request.PaymentMethod,
                PaymentDueDate = request.PaymentDueDate
            };

            // Add line items
            if (request.LineItems != null && request.LineItems.Count > 0)
            {
                foreach (var item in request.LineItems)
                {
                    report.LineItems.Add(new InvoiceLineItem
                    {
                        LineNumber = item.LineNumber,
                        ItemName = item.ItemName,
                        ItemDescription = item.ItemDescription,
                        Quantity = item.Quantity,
                        UnitOfMeasure = item.UnitOfMeasure,
                        UnitPrice = item.UnitPrice,
                        NetAmount = item.NetAmount,
                        VatRate = item.VatRate,
                        VatAmount = item.VatAmount,
                        TotalAmount = item.TotalAmount,
                        DiscountAmount = item.DiscountAmount,
                        DiscountPercentage = item.DiscountPercentage
                    });
                }
            }

            _context.InvoiceReports.Add(report);
            await _context.SaveChangesAsync();

            // Set additional response information
            zatcaResponse.QrCode = base64QR;
            zatcaResponse.InvoiceHash = invoiceHash;
            zatcaResponse.UUID = uuid;
            zatcaResponse.SignedXml = signedXml;

            return zatcaResponse;
        }

ZatcaComplianceStatus = baseResponse.ComplianceStatus,
                    ReportingDate = DateTime.UtcNow,
                    DeviceSerialNumber = request.DeviceSerialNumber,
                    InvoiceType = request.InvoiceType
                };

                _context.CreditNoteReports.Add(report);
                await _context.SaveChangesAsync();
            }

            return baseResponse;
        }

        public async Task<InvoiceReportResponse> ReportDebitNoteAsync(DebitNoteReportRequest request)
        {
            // Similar implementation as ReportInvoiceAsync but for debit notes
            var baseResponse = await ReportInvoiceAsync(request);
            
            if (baseResponse.Status == "Success")
            {
                var report = new DebitNoteReport
                {
                    DocumentNumber = request.DocumentNumber,
                    DocumentDate = request.DocumentDate,
                    SellerName = request.SellerName,
                    SellerVatNumber = request.SellerVatNumber,
                    BuyerName = request.BuyerName,
                    BuyerVatNumber = request.BuyerVatNumber,
                    TotalAmount = request.TotalAmount,
                    VatAmount = request.VatAmount,
                    DocumentXml = request.DocumentXml,
                    RelatedInvoiceNumber = request.RelatedInvoiceNumber,
                    ZatcaReportId = baseResponse.ZatcaReportId,
                    ZatcaReportingStatus = baseResponse.Status,
                    ZatcaQrCode = baseResponse.QrCode,
                    ZatcaValidationResults = baseResponse.ValidationResults,
                    ZatcaComplianceStatus = baseResponse.ComplianceStatus,
                    ReportingDate = DateTime.UtcNow,
                    DeviceSerialNumber = request.DeviceSerialNumber,
                    InvoiceType = request.InvoiceType
                };

                _context.DebitNoteReports.Add(report);
                await _context.SaveChangesAsync();
            }

            return baseResponse;
        }

        public async Task<InvoiceReportResponse> ReportSalesReturnAsync(SalesReturnReportRequest request)
        {
            // Similar implementation as ReportInvoiceAsync but for sales returns
            var baseResponse = await ReportInvoiceAsync(request);
            
            if (baseResponse.Status == "Success")
            {
                var report = new SalesReturnReport
                {
                    DocumentNumber = request.DocumentNumber,
                    DocumentDate = request.DocumentDate,
                    SellerName = request.SellerName,
                    SellerVatNumber = request.SellerVatNumber,
                    BuyerName = request.BuyerName,
                    BuyerVatNumber = request.BuyerVatNumber,
                    TotalAmount = request.TotalAmount,
                    VatAmount = request.VatAmount,
                    DocumentXml = request.DocumentXml,
                    RelatedInvoiceNumber = request.RelatedInvoiceNumber,
                    ZatcaReportId = baseResponse.ZatcaReportId,
                    ZatcaReportingStatus = baseResponse.Status,
                    ZatcaQrCode = baseResponse.QrCode,
                    ZatcaValidationResults = baseResponse.ValidationResults,
                    ZatcaComplianceStatus = baseResponse.ComplianceStatus,
                    ReportingDate = DateTime.UtcNow,
                    DeviceSerialNumber = request.DeviceSerialNumber,
                    InvoiceType = request.InvoiceType
                };

                _context.SalesReturnReports.Add(report);
                await _context.SaveChangesAsync();
            }

            return baseResponse;
        }

        public async Task<string> GenerateQrCodeAsync(string invoiceXml, string deviceSerialNumber)
        {
            // In a real implementation, this would extract the required data from the XML
            // and generate a Base64-encoded QR code for ZATCA compliance
            // This is a placeholder implementation
            return await Task.FromResult(Convert.ToBase64String(Encoding.UTF8.GetBytes("QR Code placeholder")));
        }

        public async Task<string> SignXmlAsync(string invoiceXml, string deviceSerialNumber)
        {
            var device = await _deviceService.GetDeviceBySerialNumberAsync(deviceSerialNumber);
            if (device == null || string.IsNullOrEmpty(device.CertificateContent) || 
                string.IsNullOrEmpty(device.PrivateKeyContent))
            {
                return null;
            }

            // In a real implementation, this would:
            // 1. Load the certificate and private key from the device record
            // 2. Use them to sign the XML according to ZATCA requirements
            // 3. Return the signed XML

            // This is a placeholder implementation
            return await Task.FromResult(invoiceXml);
        }

        public async Task<string> ValidateInvoiceAsync(string invoiceXml, string deviceSerialNumber)
        {
            // In a real implementation, this would validate the invoice XML against ZATCA requirements
            // This is a placeholder implementation
            return await Task.FromResult("Validation successful");
        }

        private async Task<InvoiceReportResponse> ReportToZatcaAsync(string signedXml, Device device)
        {
            // In a real implementation, this would make an API call to ZATCA to report the invoice
            // This is a placeholder implementation
            return await Task.FromResult(new InvoiceReportResponse
            {
                ZatcaReportId = Guid.NewGuid().ToString(),
                Status = "Success",
                QrCode = Convert.ToBase64String(Encoding.UTF8.GetBytes("QR Code placeholder")),
                ValidationResults = "Validation successful",
                ComplianceStatus = "Compliant",
                Message = "Invoice reported successfully"
            });
        }
    }

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

        public async Task<User> RegisterUserAsync(User user, string password)
        {
            if (await _context.Users.AnyAsync(u => u.Username == user.Username))
            