using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Xml;

namespace ZatcaPosSystem
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            // Setup Host
            using var host = CreateHostBuilder(args).Build();
            
            // Create root command
            var rootCommand = new RootCommand("ZATCA POS System for testing ZATCA Phase 2 API implementation");

            // Register Command - Register a new device with ZATCA
            var registerCommand = new Command("register", "Register a new device with ZATCA");
            registerCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--deviceName", "Device Name") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--model", "Device Model") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--vatNumber", "VAT Registration Number") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--companyName", "Company Name") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--crnNumber", "Commercial Registration Number") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--streetName", "Street Name") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--buildingNumber", "Building Number") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--cityName", "City Name") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--districtName", "District Name") { IsRequired = true });
            registerCommand.AddOption(new Option<string>("--postalCode", "Postal Code") { IsRequired = true });
            registerCommand.Handler = CommandHandler.Create<RegisterDeviceOptions, IHost>(RegisterDeviceHandler);
            rootCommand.Add(registerCommand);

            // Get CSR Command - Generate a CSR for a device
            var generateCsrCommand = new Command("generatecsr", "Generate a CSR for a device");
            generateCsrCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            generateCsrCommand.Handler = CommandHandler.Create<string, IHost>(GenerateCsrHandler);
            rootCommand.Add(generateCsrCommand);

            // Request Compliance Certificate Command
            var requestComplianceCertCommand = new Command("compliance", "Request a compliance certificate");
            requestComplianceCertCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            requestComplianceCertCommand.Handler = CommandHandler.Create<string, IHost>(RequestComplianceCertificateHandler);
            rootCommand.Add(requestComplianceCertCommand);

            // Request Production Certificate Command
            var requestProductionCertCommand = new Command("production", "Request a production certificate");
            requestProductionCertCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            requestProductionCertCommand.AddOption(new Option<string>("--otp", "One Time Password") { IsRequired = true });
            requestProductionCertCommand.Handler = CommandHandler.Create<RequestProductionCertOptions, IHost>(RequestProductionCertificateHandler);
            rootCommand.Add(requestProductionCertCommand);

            // Create Invoice Command
            var createInvoiceCommand = new Command("invoice", "Create and report a new invoice");
            createInvoiceCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<string>("--invoiceNumber", "Invoice Number") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<string>("--buyerName", "Buyer Name") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<string>("--buyerVat", "Buyer VAT Number") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<decimal>("--totalAmount", "Total Amount without VAT") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<decimal>("--vatRate", "VAT Rate in percentage") { IsRequired = true });
            createInvoiceCommand.AddOption(new Option<string>("--type", "Invoice Type (standard/simplified)") { IsRequired = true });
            createInvoiceCommand.Handler = CommandHandler.Create<CreateInvoiceOptions, IHost>(CreateInvoiceHandler);
            rootCommand.Add(createInvoiceCommand);

            // Create Credit Note Command
            var createCreditNoteCommand = new Command("creditnote", "Create and report a credit note");
            createCreditNoteCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<string>("--creditNoteNumber", "Credit Note Number") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<string>("--relatedInvoice", "Related Invoice Number") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<string>("--buyerName", "Buyer Name") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<string>("--buyerVat", "Buyer VAT Number") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<decimal>("--totalAmount", "Total Amount without VAT") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<decimal>("--vatRate", "VAT Rate in percentage") { IsRequired = true });
            createCreditNoteCommand.AddOption(new Option<string>("--type", "Invoice Type (standard/simplified)") { IsRequired = true });
            createCreditNoteCommand.Handler = CommandHandler.Create<CreateCreditNoteOptions, IHost>(CreateCreditNoteHandler);
            rootCommand.Add(createCreditNoteCommand);

            // Check Status Command
            var checkStatusCommand = new Command("check", "Check the compliance status of an invoice");
            checkStatusCommand.AddOption(new Option<string>("--serialNumber", "Device Serial Number") { IsRequired = true });
            checkStatusCommand.AddOption(new Option<string>("--uuid", "Invoice UUID") { IsRequired = true });
            checkStatusCommand.Handler = CommandHandler.Create<CheckStatusOptions, IHost>(CheckStatusHandler);
            rootCommand.Add(checkStatusCommand);

            // List Devices Command
            var listDevicesCommand = new Command("devices", "List all registered devices");
            listDevicesCommand.Handler = CommandHandler.Create<IHost>(ListDevicesHandler);
            rootCommand.Add(listDevicesCommand);

            // Login Command
            var loginCommand = new Command("login", "Authenticate with the API");
            loginCommand.AddOption(new Option<string>("--username", "Username") { IsRequired = true });
            loginCommand.AddOption(new Option<string>("--password", "Password") { IsRequired = true });
            loginCommand.Handler = CommandHandler.Create<LoginOptions, IHost>(LoginHandler);
            rootCommand.Add(loginCommand);

            return await rootCommand.InvokeAsync(args);
        }

        private static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostContext, config) =>
                {
                    config.AddJsonFile("appsettings.json", optional: false);
                    config.AddJsonFile($"appsettings.{hostContext.HostingEnvironment.EnvironmentName}.json", optional: true);
                    config.AddEnvironmentVariables();
                    config.AddCommandLine(args);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHttpClient<IZatcaApiClient, ZatcaApiClient>(client =>
                    {
                        client.BaseAddress = new Uri(hostContext.Configuration["ZatcaApi:BaseUrl"]);
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    });
                    
                    services.AddSingleton<ITokenService, TokenService>();
                    services.AddTransient<IZatcaService, ZatcaService>();
                });

        // Handler for registering a device
        private static async Task<int> RegisterDeviceHandler(RegisterDeviceOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Registering device {DeviceSerialNumber}...", options.SerialNumber);
            
            try
            {
                var result = await zatcaService.RegisterDeviceAsync(new DeviceRegistrationRequest
                {
                    DeviceSerialNumber = options.SerialNumber,
                    DeviceName = options.DeviceName,
                    Model = options.Model,
                    VatRegistrationNumber = options.VatNumber,
                    CompanyName = options.CompanyName,
                    CommercialRegistrationNumber = options.CrnNumber,
                    StreetName = options.StreetName,
                    BuildingNumber = options.BuildingNumber,
                    CityName = options.CityName,
                    DistrictName = options.DistrictName,
                    PostalCode = options.PostalCode,
                    CountryCode = "SA"
                });

                if (result.Status == "Success")
                {
                    logger.LogInformation("Device registered successfully. Device ID: {DeviceId}", result.ZatcaDeviceId);
                    logger.LogInformation("Registration Date: {RegistrationDate}", result.RegistrationDate);
                    logger.LogInformation("Next step: Generate CSR using the 'generatecsr' command");
                    return 0;
                }
                else
                {
                    logger.LogError("Device registration failed: {Message}", result.Message);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error registering device");
                return 1;
            }
        }

        // Handler for generating a CSR
        private static async Task<int> GenerateCsrHandler(string serialNumber, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Generating CSR for device {DeviceSerialNumber}...", serialNumber);
            
            try
            {
                var result = await zatcaService.GenerateCSRAsync(serialNumber);
                
                if (result)
                {
                    logger.LogInformation("CSR generated successfully");
                    logger.LogInformation("Next step: Request compliance certificate using the 'compliance' command");
                    return 0;
                }
                else
                {
                    logger.LogError("CSR generation failed");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error generating CSR");
                return 1;
            }
        }

        // Handler for requesting a compliance certificate
        private static async Task<int> RequestComplianceCertificateHandler(string serialNumber, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Requesting compliance certificate for device {DeviceSerialNumber}...", serialNumber);
            
            try
            {
                var result = await zatcaService.RequestComplianceCertificateAsync(serialNumber);
                
                if (result)
                {
                    logger.LogInformation("Compliance certificate requested successfully");
                    logger.LogInformation("Next steps:");
                    logger.LogInformation("1. Login to the ZATCA portal and generate an OTP");
                    logger.LogInformation("2. Request production certificate using the 'production' command with the OTP");
                    return 0;
                }
                else
                {
                    logger.LogError("Compliance certificate request failed");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error requesting compliance certificate");
                return 1;
            }
        }

        // Handler for requesting a production certificate
        private static async Task<int> RequestProductionCertificateHandler(RequestProductionCertOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Requesting production certificate for device {DeviceSerialNumber}...", options.SerialNumber);
            
            try
            {
                var result = await zatcaService.RequestProductionCertificateAsync(options.SerialNumber, options.Otp);
                
                if (result)
                {
                    logger.LogInformation("Production certificate requested successfully");
                    logger.LogInformation("Device is now ready to issue invoices");
                    return 0;
                }
                else
                {
                    logger.LogError("Production certificate request failed");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error requesting production certificate");
                return 1;
            }
        }

        // Handler for creating an invoice
        private static async Task<int> CreateInvoiceHandler(CreateInvoiceOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Creating invoice {InvoiceNumber} for device {DeviceSerialNumber}...", options.InvoiceNumber, options.SerialNumber);
            
            try
            {
                // Get device information to populate seller details
                var device = await zatcaService.GetDeviceAsync(options.SerialNumber);
                if (device == null)
                {
                    logger.LogError("Device {DeviceSerialNumber} not found", options.SerialNumber);
                    return 1;
                }

                // Calculate VAT amount
                var vatAmount = options.TotalAmount * (options.VatRate / 100m);
                var totalWithVat = options.TotalAmount + vatAmount;
                
                // Create a sample line item
                var lineItems = new List<InvoiceLineItemRequest>
                {
                    new InvoiceLineItemRequest
                    {
                        LineNumber = 1,
                        ItemName = "Sample Product",
                        ItemDescription = "Sample product description",
                        Quantity = 1,
                        UnitOfMeasure = "EA",
                        UnitPrice = options.TotalAmount,
                        NetAmount = options.TotalAmount,
                        VatRate = options.VatRate,
                        VatAmount = vatAmount,
                        TotalAmount = totalWithVat
                    }
                };
                
                // Determine invoice type
                var invoiceType = options.Type.ToLower() == "standard" ? InvoiceType.Standard : InvoiceType.Simplified;

                var result = await zatcaService.ReportInvoiceAsync(new InvoiceReportRequest
                {
                    DeviceSerialNumber = options.SerialNumber,
                    DocumentNumber = options.InvoiceNumber,
                    DocumentDate = DateTime.Now,
                    DocumentIssueTime = DateTime.Now,
                    SellerName = device.CompanyName,
                    SellerVatNumber = device.VatRegistrationNumber,
                    SellerStreetName = device.StreetName,
                    SellerBuildingNumber = device.BuildingNumber,
                    SellerCityName = device.CityName,
                    SellerPostalCode = device.PostalCode,
                    SellerDistrictName = device.DistrictName,
                    SellerCountryCode = "SA",
                    BuyerName = options.BuyerName,
                    BuyerVatNumber = options.BuyerVat,
                    TotalAmount = options.TotalAmount,
                    TotalWithoutVat = options.TotalAmount,
                    VatAmount = vatAmount,
                    InvoiceType = invoiceType,
                    LineItems = lineItems,
                    GenerateXml = true
                });

                if (result.Status == "Success")
                {
                    logger.LogInformation("Invoice created and reported successfully");
                    logger.LogInformation("Invoice UUID: {UUID}", result.UUID);
                    logger.LogInformation("QR Code: {QRCode}", result.QrCode);
                    
                    if (result.ClearanceStatus == ClearanceStatus.Cleared)
                    {
                        logger.LogInformation("Invoice was cleared successfully by ZATCA");
                    }
                    else if (result.ClearanceStatus == ClearanceStatus.Pending)
                    {
                        logger.LogInformation("Invoice is in pending status. Check status using the 'check' command with the UUID");
                    }
                    else
                    {
                        logger.LogWarning("Invoice clearance status: {Status}", result.ClearanceStatus);
                    }
                    
                    if (result.ValidationWarnings.Count > 0)
                    {
                        logger.LogWarning("Validation warnings:");
                        foreach (var warning in result.ValidationWarnings)
                        {
                            logger.LogWarning("- {Code}: {Message} ({Status})", warning.Code, warning.Message, warning.Status);
                        }
                    }
                    
                    return 0;
                }
                else
                {
                    logger.LogError("Invoice creation failed: {Message}", result.Message);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error creating invoice");
                return 1;
            }
        }

        // Handler for creating a credit note
        private static async Task<int> CreateCreditNoteHandler(CreateCreditNoteOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Creating credit note {CreditNoteNumber} for device {DeviceSerialNumber}...", options.CreditNoteNumber, options.SerialNumber);
            
            try
            {
                // Get device information to populate seller details
                var device = await zatcaService.GetDeviceAsync(options.SerialNumber);
                if (device == null)
                {
                    logger.LogError("Device {DeviceSerialNumber} not found", options.SerialNumber);
                    return 1;
                }

                // Calculate VAT amount
                var vatAmount = options.TotalAmount * (options.VatRate / 100m);
                var totalWithVat = options.TotalAmount + vatAmount;
                
                // Create a sample line item
                var lineItems = new List<InvoiceLineItemRequest>
                {
                    new InvoiceLineItemRequest
                    {
                        LineNumber = 1,
                        ItemName = "Returned Product",
                        ItemDescription = "Product return - credit note",
                        Quantity = 1,
                        UnitOfMeasure = "EA",
                        UnitPrice = options.TotalAmount,
                        NetAmount = options.TotalAmount,
                        VatRate = options.VatRate,
                        VatAmount = vatAmount,
                        TotalAmount = totalWithVat
                    }
                };
                
                // Determine invoice type
                var invoiceType = options.Type.ToLower() == "standard" ? InvoiceType.Standard : InvoiceType.Simplified;

                var result = await zatcaService.ReportCreditNoteAsync(new CreditNoteReportRequest
                {
                    DeviceSerialNumber = options.SerialNumber,
                    DocumentNumber = options.CreditNoteNumber,
                    DocumentDate = DateTime.Now,
                    DocumentIssueTime = DateTime.Now,
                    SellerName = device.CompanyName,
                    SellerVatNumber = device.VatRegistrationNumber,
                    SellerStreetName = device.StreetName,
                    SellerBuildingNumber = device.BuildingNumber,
                    SellerCityName = device.CityName,
                    SellerPostalCode = device.PostalCode,
                    SellerDistrictName = device.DistrictName,
                    SellerCountryCode = "SA",
                    BuyerName = options.BuyerName,
                    BuyerVatNumber = options.BuyerVat,
                    TotalAmount = options.TotalAmount,
                    TotalWithoutVat = options.TotalAmount,
                    VatAmount = vatAmount,
                    InvoiceType = invoiceType,
                    LineItems = lineItems,
                    RelatedInvoiceNumber = options.RelatedInvoice,
                    GenerateXml = true
                });

                if (result.Status == "Success")
                {
                    logger.LogInformation("Credit Note created and reported successfully");
                    logger.LogInformation("Credit Note UUID: {UUID}", result.UUID);
                    logger.LogInformation("QR Code: {QRCode}", result.QrCode);
                    
                    if (result.ClearanceStatus == ClearanceStatus.Cleared)
                    {
                        logger.LogInformation("Credit Note was cleared successfully by ZATCA");
                    }
                    else if (result.ClearanceStatus == ClearanceStatus.Pending)
                    {
                        logger.LogInformation("Credit Note is in pending status. Check status using the 'check' command with the UUID");
                    }
                    else
                    {
                        logger.LogWarning("Credit Note clearance status: {Status}", result.ClearanceStatus);
                    }
                    
                    if (result.ValidationWarnings.Count > 0)
                    {
                        logger.LogWarning("Validation warnings:");
                        foreach (var warning in result.ValidationWarnings)
                        {
                            logger.LogWarning("- {Code}: {Message} ({Status})", warning.Code, warning.Message, warning.Status);
                        }
                    }
                    
                    return 0;
                }
                else
                {
                    logger.LogError("Credit Note creation failed: {Message}", result.Message);
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error creating credit note");
                return 1;
            }
        }

        // Handler for checking status
        private static async Task<int> CheckStatusHandler(CheckStatusOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Checking status for invoice UUID {UUID}...", options.Uuid);
            
            try
            {
                var result = await zatcaService.CheckInvoiceComplianceStatusAsync(options.Uuid, options.SerialNumber);
                
                if (result)
                {
                    logger.LogInformation("Invoice compliance status check successful");
                    logger.LogInformation("Invoice is COMPLIANT");
                    
                    // Try to get the cleared invoice
                    var clearedInvoice = await zatcaService.GetClearedInvoiceAsync(options.Uuid, options.SerialNumber);
                    if (!string.IsNullOrEmpty(clearedInvoice))
                    {
                        logger.LogInformation("Retrieved cleared invoice XML successfully");
                    }
                    
                    return 0;
                }
                else
                {
                    logger.LogError("Invoice is NOT COMPLIANT or status check failed");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error checking invoice status");
                return 1;
            }
        }

        // Handler for listing devices
        private static async Task<int> ListDevicesHandler(IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var zatcaService = host.Services.GetRequiredService<IZatcaService>();

            logger.LogInformation("Listing registered devices...");
            
            try
            {
                var devices = await zatcaService.GetAllDevicesAsync();
                
                if (devices != null && devices.Count > 0)
                {
                    logger.LogInformation("Found {Count} devices:", devices.Count);
                    
                    foreach (var device in devices)
                    {
                        logger.LogInformation("Device: {SerialNumber}", device.DeviceSerialNumber);
                        logger.LogInformation("  Name: {Name}", device.DeviceName);
                        logger.LogInformation("  Status: {Status}", device.Status);
                        logger.LogInformation("  Company: {Company}", device.CompanyName);
                        logger.LogInformation("  VAT: {VatNumber}", device.VatRegistrationNumber);
                        logger.LogInformation("  Registration Date: {Date}", device.RegistrationDate);
                        logger.LogInformation("  Certificate Expiry: {Date}", device.CertificateExpiryDate);
                        logger.LogInformation("  Certificate Type: {Type}", device.CertificateType);
                        logger.LogInformation("------------------------------------------");
                    }
                    
                    return 0;
                }
                else
                {
                    logger.LogInformation("No devices found");
                    return 0;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error listing devices");
                return 1;
            }
        }

        // Handler for login
        private static async Task<int> LoginHandler(LoginOptions options, IHost host)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            var tokenService = host.Services.GetRequiredService<ITokenService>();

            logger.LogInformation("Logging in as {Username}...", options.Username);
            
            try
            {
                var result = await tokenService.LoginAsync(options.Username, options.Password);
                
                if (result != null)
                {
                    logger.LogInformation("Login successful");
                    logger.LogInformation("Token: {Token}", result.Token);
                    logger.LogInformation("Expiration: {Expiration}", result.Expiration);
                    logger.LogInformation("Role: {Role}", result.Role);
                    
                    // Save token to settings file
                    var config = host.Services.GetRequiredService<IConfiguration>();
                    var configRoot = (IConfigurationRoot)config;
                    var filePath = "appsettings.json";
                    
                    // Read existing JSON
                    var json = File.ReadAllText(filePath);
                    var jsonObj = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    
                    // Update Auth section
                    var authObj = new Dictionary<string, object>
                    {
                        { "Token", result.Token },
                        { "Expiration", result.Expiration.ToString("o") },
                        { "Username", options.Username }
                    };
                    
                    jsonObj["Auth"] = authObj;
                    
                    // Write back to the file
                    var options1 = new JsonSerializerOptions { WriteIndented = true };
                    var updatedJson = JsonSerializer.Serialize(jsonObj, options1);
                    File.WriteAllText(filePath, updatedJson);
                    
                    logger.LogInformation("Auth token saved to appsettings.json");
                    return 0;
                }
                else
                {
                    logger.LogError("Login failed");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error logging in");
                return 1;
            }
        }
    }

    // Command-line options classes
    public class RegisterDeviceOptions
    {
        public string SerialNumber { get; set; }
        public string DeviceName { get; set; }
        public string Model { get; set; }
        public string VatNumber { get; set; }
        public string CompanyName { get; set; }
        public string CrnNumber { get; set; }
        public string StreetName { get; set; }
        public string BuildingNumber { get; set; }
        public string CityName { get; set; }
        public string DistrictName { get; set; }
        public string PostalCode { get; set; }
    }

    public class RequestProductionCertOptions
    {
        public string SerialNumber { get; set; }
        public string Otp { get; set; }
    }

    public class CreateInvoiceOptions
    {
        public string SerialNumber { get; set; }
        public string InvoiceNumber { get; set; }
        public string BuyerName { get; set; }
        public string BuyerVat { get; set; }
        public decimal TotalAmount { get; set; }
        public decimal VatRate { get; set; }
        public string Type { get; set; }
    }

    public class CreateCreditNoteOptions
    {
        public string SerialNumber { get; set; }
        public string CreditNoteNumber { get; set; }
        public string RelatedInvoice { get; set; }
        public string BuyerName { get; set; }
        public string BuyerVat { get; set; }
        public decimal TotalAmount { get; set; }
        public decimal VatRate { get; set; }
        public string Type { get; set; }
    }

    public class CheckStatusOptions
    {
        public string SerialNumber { get; set; }
        public string Uuid { get; set; }
    }

    public class LoginOptions
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    // Model classes
    public enum InvoiceType
    {
        Standard,
        Simplified
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
    
    public class Device
    {
        public int Id { get; set; }
        public string DeviceSerialNumber { get; set; }
        public string DeviceName { get; set; }
        public string Model { get; set; }
        public string HardwareVersion { get; set; }
        public string SoftwareVersion { get; set; }
        public string ZatcaDeviceId { get; set; }
        public string ZatcaDeviceToken { get; set; }
        public DateTime? RegistrationDate { get; set; }
        public DateTime? LastCommunicationDate { get; set; }
        public DeviceStatus Status { get; set; }
        public string VatRegistrationNumber { get; set; }
        public string CompanyName { get; set; }
        public string CommercialRegistrationNumber { get; set; }
        public string StreetName { get; set; }
        public string BuildingNumber { get; set; }
        public string CityName { get; set; }
        public string DistrictName { get; set; }
        public string PostalCode { get; set; }
        public string CountryCode { get; set; }
        public string CertificateSerialNumber { get; set; }
        public DateTime? CertificateExpiryDate { get; set; }
        public ZatcaCertificateType CertificateType { get; set; }
    }
    
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
    
    public class ZatcaValidationWarning
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public string Category { get; set; }
        public string Status { get; set; }
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
    
    // Interfaces
    public interface IZatcaApiClient
    {
        Task<T> GetAsync<T>(string endpoint);
        Task<T> PostAsync<T>(string endpoint, object data);
        Task<T> PutAsync<T>(string endpoint, object data);
        Task<bool> DeleteAsync(string endpoint);
    }

    public interface ITokenService
    {
        Task<AuthResponse> LoginAsync(string username, string password);
        string GetToken();
        bool IsTokenValid();
    }
    
    // Implementation Classes
    public class ZatcaApiClient : IZatcaApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly ITokenService _tokenService;
        private readonly ILogger<ZatcaApiClient> _logger;

        public ZatcaApiClient(HttpClient httpClient, ITokenService tokenService, ILogger<ZatcaApiClient> logger)
        {
            _httpClient = httpClient;
            _tokenService = tokenService;
            _logger = logger;
        }

        public async Task<T> GetAsync<T>(string endpoint)
        {
            try
            {
                // Add auth token if available
                AddAuthorizationHeader();
                
                var response = await _httpClient.GetAsync(endpoint);
                response.EnsureSuccessStatusCode();
                
                var content = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(content, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GET request to {Endpoint}", endpoint);
                throw;
            }
        }

        public async Task<T> PostAsync<T>(string endpoint, object data)
        {
            try
            {
                // Add auth token if available
                AddAuthorizationHeader();
                
                var json = JsonSerializer.Serialize(data);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync(endpoint, content);
                response.EnsureSuccessStatusCode();
                
                var responseContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in POST request to {Endpoint}", endpoint);
                throw;
            }
        }

        public async Task<T> PutAsync<T>(string endpoint, object data)
        {
            try
            {
                // Add auth token if available
                AddAuthorizationHeader();
                
                var json = JsonSerializer.Serialize(data);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PutAsync(endpoint, content);
                response.EnsureSuccessStatusCode();
                
                var responseContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in PUT request to {Endpoint}", endpoint);
                throw;
            }
        }

        public async Task<bool> DeleteAsync(string endpoint)
        {
            try
            {
                // Add auth token if available
                AddAuthorizationHeader();
                
                var response = await _httpClient.DeleteAsync(endpoint);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in DELETE request to {Endpoint}", endpoint);
                throw;
            }
        }
        
        private void AddAuthorizationHeader()
        {
            var token = _tokenService.GetToken();
            if (!string.IsNullOrEmpty(token))
            {
                // Remove any existing Authorization header
                if (_httpClient.DefaultRequestHeaders.Contains("Authorization"))
                {
                    _httpClient.DefaultRequestHeaders.Remove("Authorization");
                }
                
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            }
        }
    }
    
    public class TokenService : ITokenService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TokenService> _logger;

        public TokenService(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<TokenService> logger)
        {
            _httpClient = httpClientFactory.CreateClient("ZatcaApi");
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<AuthResponse> LoginAsync(string username, string password)
        {
            try
            {
                var loginData = new AuthRequest
                {
                    Username = username,
                    Password = password
                };
                
                var json = JsonSerializer.Serialize(loginData);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync("api/auth/login", content);
                response.EnsureSuccessStatusCode();
                
                var responseContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<AuthResponse>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return null;
            }
        }

        public string GetToken()
        {
            var token = _configuration["Auth:Token"];
            return token;
        }

        public bool IsTokenValid()
        {
            var expirationStr = _configuration["Auth:Expiration"];
            if (string.IsNullOrEmpty(expirationStr))
            {
                return false;
            }
            
            if (DateTime.TryParse(expirationStr, out var expiration))
            {
                return expiration > DateTime.UtcNow;
            }
            
            return false;
        }
    }
    
    public class ZatcaService : IZatcaService
    {
        private readonly IZatcaApiClient _apiClient;
        private readonly ILogger<ZatcaService> _logger;

        public ZatcaService(IZatcaApiClient apiClient, ILogger<ZatcaService> logger)
        {
            _apiClient = apiClient;
            _logger = logger;
        }

        public async Task<DeviceRegistrationResponse> RegisterDeviceAsync(DeviceRegistrationRequest request)
        {
            try
            {
                return await _apiClient.PostAsync<DeviceRegistrationResponse>("api/devices/register", request);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering device");
                throw;
            }
        }

        public async Task<bool> GenerateCSRAsync(string serialNumber)
        {
            try
            {
                var endpoint = $"api/devices/{serialNumber}/generatecsr";
                var response = await _apiClient.PostAsync<Dictionary<string, object>>(endpoint, null);
                return response != null && response.ContainsKey("message");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating CSR");
                return false;
            }
        }

        public async Task<bool> RequestComplianceCertificateAsync(string serialNumber)
        {
            try
            {
                var endpoint = $"api/devices/{serialNumber}/compliancecertificate";
                var response = await _apiClient.PostAsync<Dictionary<string, object>>(endpoint, null);
                return response != null && response.ContainsKey("message");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting compliance certificate");
                return false;
            }
        }

        public async Task<bool> RequestProductionCertificateAsync(string serialNumber, string otp)
        {
            try
            {
                var endpoint = $"api/devices/{serialNumber}/productioncertificate";
                var response = await _apiClient.PostAsync<Dictionary<string, object>>(endpoint, otp);
                return response != null && response.ContainsKey("message");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting production certificate");
                return false;
            }
        }

        public async Task<InvoiceReportResponse> ReportInvoiceAsync(InvoiceReportRequest request)
        {
            try
            {
                return await _apiClient.PostAsync<InvoiceReportResponse>("api/invoices/report", request);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reporting invoice");
                throw;
            }
        }

        public async Task<InvoiceReportResponse> ReportCreditNoteAsync(CreditNoteReportRequest request)
        {
            try
            {
                return await _apiClient.PostAsync<InvoiceReportResponse>("api/invoices/creditnote", request);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reporting credit note");
                throw;
            }
        }

        public async Task<InvoiceReportResponse> ReportDebitNoteAsync(DebitNoteReportRequest request)
        {
            try
            {
                return await _apiClient.PostAsync<InvoiceReportResponse>("api/invoices/debitnote", request);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reporting debit note");
                throw;
            }
        }

        public async Task<InvoiceReportResponse> ReportSalesReturnAsync(SalesReturnReportRequest request)
        {
            try
            {
                return await _apiClient.PostAsync<InvoiceReportResponse>("api/invoices/salesreturn", request);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reporting sales return");
                throw;
            }
        }

        public async Task<bool> CheckInvoiceComplianceStatusAsync(string uuid, string deviceSerialNumber)
        {
            try
            {
                var data = new
                {
                    DeviceSerialNumber = deviceSerialNumber,
                    Uuid = uuid
                };
                
                var response = await _apiClient.PostAsync<Dictionary<string, object>>("api/invoices/status", data);
                return response != null && response.ContainsKey("status") && response["status"].ToString() == "Compliant";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking invoice status");
                return false;
            }
        }

        public async Task<string> GetClearedInvoiceAsync(string uuid, string deviceSerialNumber)
        {
            try
            {
                var data = new
                {
                    DeviceSerialNumber = deviceSerialNumber,
                    Uuid = uuid
                };
                
                var response = await _apiClient.PostAsync<Dictionary<string, object>>("api/invoices/cleared", data);
                if (response != null && response.ContainsKey("clearedInvoice"))
                {
                    return response["clearedInvoice"].ToString();
                }
                
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting cleared invoice");
                return null;
            }
        }

        public async Task<Device> GetDeviceAsync(string serialNumber)
        {
            try
            {
                return await _apiClient.GetAsync<Device>($"api/devices/{serialNumber}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting device");
                return null;
            }
        }

        public async Task<List<Device>> GetAllDevicesAsync()
        {
            try
            {
                return await _apiClient.GetAsync<List<Device>>("api/devices");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all devices");
                return new List<Device>();
            }
        }
    }

    public interface IZatcaService
    {
        Task<DeviceRegistrationResponse> RegisterDeviceAsync(DeviceRegistrationRequest request);
        Task<bool> GenerateCSRAsync(string serialNumber);
        Task<bool> RequestComplianceCertificateAsync(string serialNumber);
        Task<bool> RequestProductionCertificateAsync(string serialNumber, string otp);
        Task<InvoiceReportResponse> ReportInvoiceAsync(InvoiceReportRequest request);
        Task<InvoiceReportResponse> ReportCreditNoteAsync(CreditNoteReportRequest request);
        Task<InvoiceReportResponse> ReportDebitNoteAsync(DebitNoteReportRequest request);
        Task<InvoiceReportResponse> ReportSalesReturnAsync(SalesReturnReportRequest request);
        Task<bool> CheckInvoiceComplianceStatusAsync(string uuid, string deviceSerialNumber);
        Task<string> GetClearedInvoiceAsync(string uuid, string deviceSerialNumber);
        Task<Device> GetDeviceAsync(string serialNumber);
        Task<List<Device>> GetAllDevicesAsync();