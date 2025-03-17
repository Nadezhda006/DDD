using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Microsoft.Win32;

class BackgroundMinerScanner
{
    static readonly string[] minerProcesses =
    {
        "xmrig", "svchosts", "winlogui", "system64", "taskhost", "miner", "cpu-miner", "mshelper", "winserv", "powershell_miner"
    };

    static readonly string[] minerDirectories =
    {
        @"C:\Users\Public\Libraries",
        @"C:\ProgramData",
        @"C:\Windows\Temp",
        @"C:\Users\" + Environment.UserName + @"\AppData\Roaming",
        @"C:\Users\" + Environment.UserName + @"\AppData\Local\Temp",
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Users\" + Environment.UserName + @"\AppData\Local"
    };

    static readonly string[] registryKeys =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    };

    static readonly string[] trustedPublishers =
{
    // Core Operating Systems & Tech Giants
    "Microsoft Corporation",
    "Apple Inc.",
    "Google LLC",
    "Canonical Ltd.",   // Ubuntu Linux
    "Red Hat, Inc.",    // RHEL Linux
    "IBM Corporation",
    "Oracle Corporation",
    "SAP SE",

    // Major Hardware Vendors
    "Intel Corporation",
    "NVIDIA Corporation",
    "Advanced Micro Devices, Inc.",  // AMD
    "ASUSTek COMPUTER INC.",         // ASUS
    "Dell Inc.",
    "Hewlett-Packard",               // HP
    "HP Inc.",
    "Lenovo",
    "Toshiba Corporation",
    "Gigabyte Technology Co., Ltd.",  // Gigabyte BIOS & tools
    "Micro-Star International Co., Ltd.",  // MSI (GPU/Motherboard tools)
    "Samsung Electronics Co., Ltd.",  // Samsung software
    "Sony Corporation",
    "Seagate Technology LLC",
    "Western Digital Technologies, Inc.",
    "Crucial Technology (Micron)",
    "Corsair Components, Inc.",
    "EVGA Corporation",
    "ZOTAC International Limited",
    "Acer Incorporated",
    "Alienware Corporation",
    "Razer Inc.",
    "SteelSeries ApS",
    "Logitech Inc.",
    "TP-Link Technologies Co., Ltd.",
    "NETGEAR Inc.",
    "D-Link Corporation",
    "Broadcom Inc.",
    "Realtek Semiconductor Corp.",
    "Qualcomm Technologies, Inc.",
    "Intel Mobile Communications",
    "Nokia Corporation",
    "HUAWEI Technologies Co., Ltd.",
    
    // Networking & Security
    "Cisco Systems, Inc.",
    "VMware, Inc.",
    "Palo Alto Networks, Inc.",  // Security company
    "ESET, spol. s r.o.",        // ESET Antivirus
    "Bitdefender SRL",           // Bitdefender Antivirus
    "Kaspersky Lab",             // Kaspersky Antivirus
    "Malwarebytes Inc.",         // Malwarebytes Anti-Malware
    "Avast Software s.r.o.",
    "AVG Technologies",
    "McAfee, LLC",
    "NortonLifeLock Inc.",
    "Sophos Ltd.",
    "Trend Micro Incorporated",
    "Fortinet, Inc.",

    // Cloud & Software Development (including C#/.NET)
    "Microsoft Corporation",   // .NET, C#, Visual Studio
    "JetBrains s.r.o.",        // Rider (C# IDE), IntelliJ, PyCharm, etc.
    "GitHub, Inc.",
    "GitLab B.V.",
    "Docker Inc.",
    "MongoDB, Inc.",
    "Atlassian Pty Ltd",       // Jira, Trello, Bitbucket
    "Red Hat, Inc.",
    "Canonical Ltd.",
    "Apache Software Foundation",
    "Node.js Foundation",
    "Python Software Foundation",
    "The Eclipse Foundation",
    "Rust Foundation",
    "The Linux Foundation",
    "Unity Technologies ApS",  // Unity game engine
    "Roblox Corporation",      // Roblox Studio & Client
    
    // Web Browsers & Online Services
    "Mozilla Corporation",          // Firefox
    "Opera Software ASA",
    "Brave Software, Inc.",
    "Vivaldi Technologies AS",
    "Dropbox, Inc.",
    "Box, Inc.",
    "Slack Technologies, LLC",
    "Zoom Video Communications, Inc.",
    "Cisco WebEx LLC",
    "RingCentral, Inc.",
    "Twilio Inc.",
    "Cloudflare, Inc.",
    
    // Productivity & Business Software
    "Adobe Systems Incorporated",  // Photoshop, Acrobat
    "Autodesk, Inc.",              // AutoCAD
    "Corel Corporation",
    "The MathWorks, Inc.",
    "Wolfram Research, Inc.",
    "Foxit Software Incorporated",
    "Nuance Communications, Inc.",
    "Parallels International GmbH",
    "Citrix Systems, Inc.",
    "VMware, Inc.",
    "Salesforce.com, Inc.",
    "Intuit Inc.",                 // QuickBooks, TurboTax
    "Xero Limited",
    
    // Gaming & Entertainment (Including Roblox)
    "Valve Corporation",           // Steam
    "Epic Games, Inc.",            // Epic Launcher
    "Ubisoft Entertainment",       // Ubisoft Connect
    "Activision Blizzard, Inc.",   // Battle.net
    "Electronic Arts Inc.",        // EA App
    "Riot Games, Inc.",            // League of Legends, Valorant
    "Take-Two Interactive Software, Inc.",
    "Rockstar Games, Inc.",
    "Bethesda Softworks LLC",
    "CD Projekt S.A.",
    "GOG Sp. z o.o.",
    "Square Enix Holdings Co., Ltd.",
    "Capcom Co., Ltd.",
    "SEGA Corporation",
    "Bandai Namco Entertainment Inc.",
    "Konami Digital Entertainment",
    "2K Games, Inc.",
    "Warner Bros. Interactive Entertainment",
    "Sony Interactive Entertainment LLC",
    "Nintendo Co., Ltd.",
    "Roblox Corporation",          // Roblox Studio, Roblox Client
    
    // Financial & Other
    "PayPal, Inc.",
    "Visa Inc.",
    "Mastercard International Incorporated",
    "American Express Company",
    "Discover Financial Services",
    "Stripe, Inc."
};



    static string logFile = @"C:\Temp\MinerScanner.log";

    static void Main()
    {
        WriteLog("Miner scanner started. Running in background...");
        while (true)
        {
            ScanAndTerminateMiners();
            ScanAndDeleteMinerFiles();
            ScanAndRemoveRegistryEntries();
            ScanForHighCPUProcesses();

            WriteLog("Scan completed. Sleeping for 5 minutes...");
            Thread.Sleep(TimeSpan.FromMinutes(5));
        }
    }

    static void ScanAndTerminateMiners()
    {
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                string exePath = process.MainModule.FileName;
                bool isTrusted = IsFileSignedAndTrusted(exePath);

                if (minerProcesses.Any(miner => process.ProcessName.IndexOf(miner, StringComparison.OrdinalIgnoreCase) >= 0) || !isTrusted)
                {
                    WriteLog($"⚠️ Suspicious process detected: {process.ProcessName} | Trusted: {isTrusted}");
                    Console.Write($"Do you want to terminate this process?: {process.ProcessName} (y/n) : ");
                    string input = Console.ReadLine();
                    if (input == "y")
                    {
                        process.Kill();
                        WriteLog("Process terminated.");
                    }
                    else
                    {
                        break;
                    }

                }
            }
            catch (Exception ex)
            {
                WriteLog($"Error handling process {process.ProcessName}: {ex.Message}");
            }
        }
    }

    static void ScanAndDeleteMinerFiles()
    {
        foreach (var directory in minerDirectories)
        {
            if (Directory.Exists(directory))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(directory))
                    {
                        if (minerProcesses.Any(miner => Path.GetFileName(file).IndexOf(miner, StringComparison.OrdinalIgnoreCase) >= 0) || !IsFileSignedAndTrusted(file))
                        {
                            WriteLog($"Suspicious file found: {file}");
                            Console.Write($"Do you want to delete this file?: {file} (y/n) : ");
                            string input = Console.ReadLine();
                            if (input == "y")
                            {
                                File.Delete(file);
                                WriteLog("File deleted.");
                            }
                            else
                            {
                                break;
                            }

                        }

                    }
                }
                catch (Exception ex)
                {
                    WriteLog($"Error scanning {directory}: {ex.Message}");
                }
            }
        }
    }

    static void ScanAndRemoveRegistryEntries()
    {
        foreach (var keyPath in registryKeys)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyPath, writable: true))
                {
                    if (key != null)
                    {
                        foreach (var miner in minerProcesses)
                        {
                            if (key.GetValueNames().Any(valueName => valueName.IndexOf(miner, StringComparison.OrdinalIgnoreCase) >= 0))
                            {
                                WriteLog($"⚠️ Suspicious registry entry found in {keyPath}: {miner}");
                                Console.Write($"Do you want to remove registry entry?: {miner} (y/n) : ");
                                string input = Console.ReadLine();
                                if (input == "y")
                                {
                                    key.DeleteValue(miner);
                                    WriteLog("Registry entry removed.");
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"❌ Error scanning registry key {keyPath}: {ex.Message}");
            }
        }
    }

    static void ScanForHighCPUProcesses()
    {
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                using (PerformanceCounter pc = new PerformanceCounter("Process", "% Processor Time", process.ProcessName, true))
                {
                    float cpuUsage = pc.NextValue();
                    Thread.Sleep(500);
                    cpuUsage = pc.NextValue();

                    if (cpuUsage > 40 && !IsFileSignedAndTrusted(process.MainModule.FileName))
                    {
                        WriteLog($"⚠ High CPU usage detected: {process.ProcessName} ({cpuUsage}% CPU) - Unsigned process");
                        Console.Write($"Do you want to kill this process?: {process.ProcessName} (y/n) : ");
                        string input = Console.ReadLine();
                        if (input == "y")
                        {
                            process.Kill();
                            WriteLog("❌ High CPU process terminated.");
                        }
                        else
                        {
                            break;
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"❌ Error checking CPU usage for {process.ProcessName}: {ex.Message}");
            }
        }
    }

    static bool IsFileSignedAndTrusted(string filePath)
    {
        try
        {
            X509Certificate2 cert = new X509Certificate2(filePath);
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            bool isValid = chain.Build(cert);
            string issuer = cert.Subject;

            if (!isValid)
            {
                return false; // Signature is invalid
            }

            // Check if the issuer is a trusted vendor
            foreach (var trusted in trustedPublishers)
            {
                if (issuer.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                {
                    return true; // It's a trusted program it is NOT getting deleteed
                }
            }

            return false; // Signed, but from an unknown publisher
        }
        catch
        {
            return false; // Unsigned file
        }
    }

    static void WriteLog(string message)
    {
        string logMessage = $"{DateTime.Now}: {message}";
        File.AppendAllText(logFile, logMessage + Environment.NewLine);
    }
}
