using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using VirusTotalNet;
using VirusTotalNet.Objects;
using VirusTotalNet.Results;

namespace VirusTotalScanner
{
    public partial class MainWindow : Window
    {
        private readonly ScanViewModel _scanViewModel;

        public MainWindow()
        {
            InitializeComponent();

            // Initialize VirusTotal API with your API key
            _scanViewModel = new ScanViewModel("6323038d131b7632d7e66df82fac6eacbd88cc10cf2042a246273c1eb8c3fa4e");
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            // Read IP addresses from file on C drive and remove duplicates
            List<string> ipAddresses = ReadUniqueIPAddressesFromFile("ip_list.txt");

            // Initialize progress to 0%
            ScanProgressBar.Value = 0;

            // Scan IP addresses
            List<ScanResult> results = await _scanViewModel.ScanIPAddresses(ipAddresses);

            // Update flagged IPs
            _scanViewModel.UpdateFlaggedIPs(results);

            // Save results to CSV on C drive
            _scanViewModel.SaveResultsToCsv(results, "C:\\scan_results.csv");

            // Save results to HTML on C drive
            _scanViewModel.SaveResultsToHtml(results, "C:\\scan_results.html");

            // Display results
            DisplayResults(results);
        }

        private List<string> ReadUniqueIPAddressesFromFile(string filePath)
        {
            List<string> ipAddresses = new List<string>();

            try
            {
                string fullPath = Path.Combine("C:\\", filePath); // Assuming filePath is just the file name
                string[] lines = File.ReadAllLines(fullPath);

                // Use a HashSet to store unique IP addresses
                HashSet<string> uniqueIPs = new HashSet<string>();

                foreach (string line in lines)
                {
                    // Remove leading and trailing whitespaces, and convert to lowercase
                    string ip = line.Trim().ToLower();

                    // Add only unique IP addresses to the HashSet
                    if (!uniqueIPs.Contains(ip))
                    {
                        uniqueIPs.Add(ip);
                    }
                }

                // Convert the HashSet back to a List
                ipAddresses.AddRange(uniqueIPs);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading IP list from file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            return ipAddresses;
        }

        private async void DisplayResults(List<ScanResult> results)
        {
            ResultsTextBox.Text = ""; // Clear existing results

            for (int i = 0; i < results.Count; i++)
            {
                var result = results[i];

                if (result.Report != null)
                {
                    ResultsTextBox.Text += $"IP: {result.IPAddress} - {i + 1}/{results.Count} ({((i + 1) * 100 / results.Count)}%)\n";
                    ResultsTextBox.Text += $"Scan Date: {result.Report.ScanDate}\n";
                    ResultsTextBox.Text += $"Positives: {result.Report.Positives}/{result.Report.Total}\n";
                    ResultsTextBox.Text += $"Scan Result: {result.Report.VerboseMsg}\n\n";
                }
                else if (!string.IsNullOrEmpty(result.Error))
                {
                    if (result.Error.Contains("4 requests per minute limit"))
                    {
                        ResultsTextBox.Text += $"Error scanning IP {result.IPAddress}: Rate limit exceeded. Please wait and try again.\n\n";
                    }
                    else
                    {
                        ResultsTextBox.Text += $"Error scanning IP {result.IPAddress}: {result.Error}\n\n";
                    }
                }

                // Update the UI asynchronously
                await Task.Delay(1500); // Adjust delay time as needed for live update speed
            }
        }
    }

    public class ScanViewModel
    {
        private readonly VirusTotal _virusTotal;

        public ScanViewModel(string apiKey)
        {
            _virusTotal = new VirusTotal(apiKey);
        }

        public async Task<List<ScanResult>> ScanIPAddresses(List<string> ipAddresses)
        {
            List<ScanResult> results = new List<ScanResult>();

            // Read IPs to exclude from "Exclude_this.txt" file
            List<string> excludedIPs = ReadIPAddressesFromFile("Exclude_this.txt");

            // Read IPs to exclude from "green_list.txt" file
            List<string> greenListIPs = ReadIPAddressesFromFile("green_list.txt");

            // Read IPs to exclude from "red_list.txt" file
            List<string> redListIPs = ReadIPAddressesFromFile("red_list.txt");

            foreach (var ip in ipAddresses)
            {
                // Check if the IP is in the excluded list
                if (excludedIPs.Contains(ip))
                {
                    results.Add(new ScanResult { IPAddress = ip, Error = "Excluded from scanning." });
                    continue; // Skip scanning this IP
                }

                // Check if the IP is in the green list or red list
                if (greenListIPs.Contains(ip))
                {
                    results.Add(new ScanResult { IPAddress = ip, Error = "Excluded (green list)." });
                    continue; // Skip scanning this IP
                }

                if (redListIPs.Contains(ip))
                {
                    results.Add(new ScanResult { IPAddress = ip, Error = "Excluded (red list)." });
                    continue; // Skip scanning this IP
                }

                bool retry = false;
                int retryCount = 0;

                do
                {
                    try
                    {
                        var report = await _virusTotal.GetUrlReportAsync(ip);
                        results.Add(new ScanResult { IPAddress = ip, Report = report });

                        // Update progress bar
                        int progress = (results.Count * 100 / ipAddresses.Count);
                        UpdateProgress(progress);

                        retry = false; // Set retry to false to exit the retry loop
                    }
                    catch (Exception ex)
                    {
                        if (ex.Message.Contains("4 requests per minute limit"))
                        {
                            retry = true; // Set retry to true to retry scanning the same IP
                            retryCount++;

                            // Delay before retrying to avoid immediate rate limit issues
                            await Task.Delay(62000); // 62 seconds delay before retrying
                        }
                        else
                        {
                            results.Add(new ScanResult { IPAddress = ip, Error = ex.Message });
                            retry = false; // Set retry to false to exit the retry loop
                        }
                    }
                } while (retry && retryCount < 3); // Retry up to 3 times

                if (retry && retryCount >= 3)
                {
                    results.Add(new ScanResult { IPAddress = ip, Error = "Exceeded retry attempts." });
                }
            }

            return results;
        }

        public void UpdateFlaggedIPs(List<ScanResult> results)
        {
            List<string> greenList = new List<string>();
            List<string> redList = new List<string>();

            foreach (var result in results)
            {
                if (result.Report != null && result.Report.Positives == 0)
                {
                    // Check if the detected engines are 90, 91, or 92
                    if (result.Report.Total == 90 || result.Report.Total == 91 || result.Report.Total == 92)
                    {
                        greenList.Add(result.IPAddress);
                    }
                    else
                    {
                        redList.Add(result.IPAddress);
                    }
                }
                else if (result.Report != null && result.Report.Positives > 0)
                {
                    redList.Add(result.IPAddress); // Add to red list if positives are detected
                }
            }

            // Update green_list.txt
            UpdateListFile("green_list.txt", greenList);

            // Update red_list.txt
            UpdateListFile("red_list.txt", redList);
        }

        private List<string> ReadIPAddressesFromFile(string filePath)
        {
            List<string> ipAddresses = new List<string>();

            try
            {
                string fullPath = Path.Combine("C:\\", filePath); // Assuming filePath is just the file name
                string[] lines = File.ReadAllLines(fullPath);

                // Use a HashSet to store unique IP addresses
                HashSet<string> uniqueIPs = new HashSet<string>();

                foreach (string line in lines)
                {
                    // Remove leading and trailing whitespaces, and convert to lowercase
                    string ip = line.Trim().ToLower();

                    // Add only unique IP addresses to the HashSet
                    if (!uniqueIPs.Contains(ip))
                    {
                        uniqueIPs.Add(ip);
                    }
                }

                // Convert the HashSet back to a List
                ipAddresses.AddRange(uniqueIPs);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error reading IP list from file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            return ipAddresses;
        }

        private void UpdateListFile(string filePath, List<string> ipAddresses)
        {
            try
            {
                string fullPath = Path.Combine("C:\\", filePath);
                File.WriteAllLines(fullPath, ipAddresses);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error updating list file {filePath}: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateProgress(int progress)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                MainWindow mainWindow = (MainWindow)Application.Current.MainWindow;
                mainWindow.ScanProgressBar.Value = progress;
            });
        }

        public void SaveResultsToCsv(List<ScanResult> results, string filePath)
        {
            StringBuilder csvContent = new StringBuilder();
            csvContent.AppendLine("IP Address,Scan Date,Positives/Total,Scan Result");

            foreach (var result in results)
            {
                if (result.Report != null)
                {
                    csvContent.AppendLine($"{result.IPAddress},{result.Report.ScanDate},{result.Report.Positives}/{result.Report.Total},{result.Report.VerboseMsg}");
                }
                else if (!string.IsNullOrEmpty(result.Error))
                {
                    csvContent.AppendLine($"{result.IPAddress},Error,{result.Error}");
                }
            }

            File.WriteAllText(filePath, csvContent.ToString());
        }

        public void SaveResultsToHtml(List<ScanResult> results, string filePath)
        {
            StringBuilder htmlContent = new StringBuilder();
            htmlContent.AppendLine("<html><body><table border='1'><tr><th>IP Address</th><th>Scan Date</th><th>Positives/Total</th><th>Scan Result</th></tr>");

            foreach (var result in results)
            {
                if (result.Report != null)
                {
                    htmlContent.AppendLine($"<tr><td>{result.IPAddress}</td><td>{result.Report.ScanDate}</td><td>{result.Report.Positives}/{result.Report.Total}</td><td>{result.Report.VerboseMsg}</td></tr>");
                }
                else if (!string.IsNullOrEmpty(result.Error))
                {
                    htmlContent.AppendLine($"<tr><td>{result.IPAddress}</td><td>Error</td><td colspan='2'>{result.Error}</td></tr>");
                }
            }

            htmlContent.AppendLine("</table></body></html>");

            File.WriteAllText(filePath, htmlContent.ToString());
        }
    }

    public class ScanResult
    {
        public string IPAddress { get; set; }
        public UrlReport Report { get; set; }
        public string Error { get; set; }
    }
}
