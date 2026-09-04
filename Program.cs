using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

var options = CliOptions.Parse(args);
if (options.ShowVersion)
{
    var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown";
    Console.WriteLine($"DotnetAuditLite {version}");
    return 0;
}

if (options.ShowHelp)
{
    CliOptions.PrintHelp();
    return 0;
}

var root = Path.GetFullPath(options.Path);
if (!Directory.Exists(root))
{
    Console.Error.WriteLine($"Directory not found: {root}");
    return 2;
}

var reportPath = Path.GetFullPath(
    Path.IsPathRooted(options.Output)
        ? options.Output
        : Path.Combine(Environment.CurrentDirectory, options.Output));

var scanner = new PreflightScanner(root);
var report = await scanner.ScanAsync(options.StaticOnly);
Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
await File.WriteAllTextAsync(reportPath, report.ToMarkdown(), new UTF8Encoding(false));
if (!string.IsNullOrWhiteSpace(options.SarifOutput))
{
    var sarifPath = Path.GetFullPath(
        Path.IsPathRooted(options.SarifOutput)
            ? options.SarifOutput
            : Path.Combine(Environment.CurrentDirectory, options.SarifOutput));
    Directory.CreateDirectory(Path.GetDirectoryName(sarifPath)!);
    await File.WriteAllTextAsync(sarifPath, report.ToSarif(), new UTF8Encoding(false));
    Console.WriteLine($"SARIF report written to {sarifPath}");
}

Console.WriteLine($"Preflight report written to {reportPath}");
Console.WriteLine($"Projects: {report.Projects.Count}; findings: {report.Findings.Count}; commands: {report.Commands.Count}");
return report.Commands.Any(command => command.ExitCode is not 0 and not null) ? 1 : 0;

internal sealed record CliOptions(
    string Path,
    string Output,
    string? SarifOutput,
    bool StaticOnly,
    bool ShowHelp,
    bool ShowVersion)
{
    public static CliOptions Parse(string[] args)
    {
        var path = ".";
        var output = "dotnet-preflight-report.md";
        string? sarifOutput = null;
        var staticOnly = false;
        var showHelp = false;
        var showVersion = false;

        for (var index = 0; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--path" when index + 1 < args.Length:
                    path = args[++index];
                    break;
                case "--output" when index + 1 < args.Length:
                    output = args[++index];
                    break;
                case "--sarif" when index + 1 < args.Length:
                    sarifOutput = args[++index];
                    break;
                case "--static-only":
                    staticOnly = true;
                    break;
                case "-h":
                case "--help":
                    showHelp = true;
                    break;
                case "--version":
                    showVersion = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown or incomplete argument: {args[index]}");
            }
        }

        return new CliOptions(path, output, sarifOutput, staticOnly, showHelp, showVersion);
    }

    public static void PrintHelp()
    {
        Console.WriteLine(
            """
            DotnetAudit Lite — local .NET repository preflight

            Usage:
              dotnet-audit-lite [options]

            Options:
              --path <directory>  Repository to inspect. Default: current directory.
              --output <file>     Markdown report path. Default: dotnet-preflight-report.md.
              --sarif <file>      Also write a SARIF 2.1.0 report for optional code-scanning upload.
              --static-only       Skip build, test and vulnerable-package commands.
              --version           Show the installed tool version.
              -h, --help          Show help.
            """);
    }
}

internal sealed class PreflightScanner
{
    private static readonly HashSet<string> ExcludedDirectories =
        new(StringComparer.OrdinalIgnoreCase) { ".git", ".vs", "bin", "obj", "node_modules", "packages" };

    private static readonly Regex SecretAssignment = new(
        @"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[""']?(?!\s*(null|false|true|change[-_ ]?me|example|demo|fake|placeholder))\S{8,}",
        RegexOptions.Compiled);

    private readonly string _root;

    public PreflightScanner(string root) => _root = root;

    public async Task<PreflightReport> ScanAsync(bool staticOnly)
    {
        var projects = DiscoverFiles("*.csproj")
            .Select(ReadProject)
            .OrderBy(project => project.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var findings = new List<Finding>();
        AddRepositoryFindings(projects, findings);
        AddSecretFindings(findings);

        var commands = new List<CommandResult>();
        if (!staticOnly)
        {
            var target = DiscoverFiles("*.sln").FirstOrDefault()
                         ?? projects.FirstOrDefault()?.AbsolutePath;

            if (target is not null)
            {
                commands.Add(await RunDotnetAsync($"build \"{target}\" --configuration Release", TimeSpan.FromMinutes(5)));
                commands.Add(await RunDotnetAsync($"test \"{target}\" --configuration Release --no-build", TimeSpan.FromMinutes(5)));
                commands.Add(await RunDotnetAsync(
                    $"list \"{target}\" package --vulnerable --include-transitive --source https://api.nuget.org/v3/index.json",
                    TimeSpan.FromMinutes(3)));
            }
            else
            {
                findings.Add(new Finding("High", "No .NET project or solution found", "No buildable target was discovered."));
            }
        }

        return new PreflightReport(_root, DateTimeOffset.Now, staticOnly, projects, findings, commands);
    }

    private ProjectInfo ReadProject(string path)
    {
        try
        {
            var document = XDocument.Load(path);
            var frameworks = document.Descendants()
                .Where(element => element.Name.LocalName is "TargetFramework" or "TargetFrameworks")
                .SelectMany(element => element.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (frameworks.Count == 0)
            {
                var legacyFramework = ReadProperty(document, "TargetFrameworkVersion");
                if (legacyFramework.StartsWith("v", StringComparison.OrdinalIgnoreCase))
                {
                    frameworks.Add("net" + legacyFramework[1..].Replace(".", string.Empty, StringComparison.Ordinal));
                }
            }

            var nullable = ReadProperty(document, "Nullable");
            var warningsAsErrors = ReadProperty(document, "TreatWarningsAsErrors");
            return new ProjectInfo(
                Relative(path),
                path,
                frameworks.Count == 0 ? ["unknown"] : frameworks,
                nullable,
                warningsAsErrors);
        }
        catch (Exception exception)
        {
            return new ProjectInfo(Relative(path), path, ["unreadable"], $"error: {exception.Message}", "unknown");
        }
    }

    private void AddRepositoryFindings(IReadOnlyCollection<ProjectInfo> projects, ICollection<Finding> findings)
    {
        if (projects.Count == 0)
        {
            findings.Add(new Finding("High", "No project files found", "No *.csproj files were discovered."));
            return;
        }

        foreach (var project in projects)
        {
            foreach (var framework in project.Frameworks)
            {
                var lifecycle = FrameworkLifecycle.Describe(framework, DateOnly.FromDateTime(DateTime.UtcNow));
                findings.Add(new Finding(lifecycle.Severity, $"{framework}: {lifecycle.Status}", project.Path));
            }

            if (!string.Equals(project.Nullable, "enable", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding("Medium", "Nullable reference types are not explicitly enabled", project.Path));
            }

            if (!string.Equals(project.WarningsAsErrors, "true", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding("Low", "Warnings are not explicitly treated as errors", project.Path));
            }
        }

        if (!DiscoverFiles("*.yml", ".github/workflows").Any() &&
            !DiscoverFiles("*.yaml", ".github/workflows").Any() &&
            !File.Exists(Path.Combine(_root, "azure-pipelines.yml")))
        {
            findings.Add(new Finding("Medium", "No common CI workflow detected", "Checked GitHub Actions and Azure Pipelines."));
        }

        if (!DiscoverFiles("Dockerfile").Any() && !DiscoverFiles("docker-compose*.yml").Any())
        {
            findings.Add(new Finding("Info", "No Docker assets detected", "This may be intentional for desktop or library projects."));
        }

        var sourceText = ReadSourceCorpus();
        if (!sourceText.Contains("AddHealthChecks", StringComparison.Ordinal) &&
            !sourceText.Contains("MapHealthChecks", StringComparison.Ordinal))
        {
            findings.Add(new Finding("Medium", "No health-check wiring detected", "Search did not find AddHealthChecks or MapHealthChecks."));
        }

        if (!sourceText.Contains("AddOpenTelemetry", StringComparison.Ordinal) &&
            !sourceText.Contains("OpenTelemetry", StringComparison.Ordinal))
        {
            findings.Add(new Finding("Medium", "No OpenTelemetry wiring detected", "Search did not find OpenTelemetry setup."));
        }
    }

    private void AddSecretFindings(ICollection<Finding> findings)
    {
        foreach (var file in DiscoverFiles("*.*").Where(IsTextCandidate))
        {
            var fileName = Path.GetFileName(file);
            if (fileName.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding("High", "Sensitive-looking file is tracked in the scan scope", Relative(file)));
                continue;
            }

            try
            {
                var lineNumber = 0;
                foreach (var line in File.ReadLines(file))
                {
                    lineNumber++;
                    if (SecretAssignment.IsMatch(line))
                    {
                        findings.Add(new Finding(
                            "High",
                            "Possible hard-coded secret assignment",
                            $"{Relative(file)}:{lineNumber}. Value intentionally omitted."));
                    }
                }
            }
            catch
            {
                // A preflight should continue when a text-like file is unreadable.
            }
        }
    }

    private string ReadSourceCorpus()
    {
        var builder = new StringBuilder();
        foreach (var file in DiscoverFiles("*.cs").Take(5_000))
        {
            try
            {
                builder.AppendLine(File.ReadAllText(file));
            }
            catch
            {
                // Best-effort static signal only.
            }
        }

        return builder.ToString();
    }

    private async Task<CommandResult> RunDotnetAsync(string arguments, TimeSpan timeout)
    {
        var startInfo = new ProcessStartInfo("dotnet", arguments)
        {
            WorkingDirectory = _root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return new CommandResult($"dotnet {arguments}", null, "Process could not be started.", false);
        }

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);

        try
        {
            await process.WaitForExitAsync(cancellation.Token);
            var combined = string.Join(Environment.NewLine, await outputTask, await errorTask).Trim();
            return new CommandResult($"dotnet {arguments}", process.ExitCode, Truncate(combined), false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // The process may already have exited.
            }

            return new CommandResult($"dotnet {arguments}", null, $"Timed out after {timeout.TotalMinutes:0.#} minutes.", true);
        }
    }

    private IEnumerable<string> DiscoverFiles(string pattern, string? relativeDirectory = null)
    {
        var start = relativeDirectory is null ? _root : Path.Combine(_root, relativeDirectory);
        if (!Directory.Exists(start))
        {
            return [];
        }

        return Directory.EnumerateFiles(start, pattern, SearchOption.AllDirectories)
            .Where(path => !path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => ExcludedDirectories.Contains(segment)));
    }

    private static bool IsTextCandidate(string path)
    {
        var extension = Path.GetExtension(path);
        return extension is ".cs" or ".csproj" or ".props" or ".targets" or ".json" or ".xml"
            or ".config" or ".yml" or ".yaml" or ".env" or ".md" or ".ps1" or ".sh";
    }

    private string Relative(string path) => Path.GetRelativePath(_root, path).Replace('\\', '/');

    private static string ReadProperty(XContainer document, string property) =>
        document.Descendants().FirstOrDefault(element => element.Name.LocalName == property)?.Value.Trim() ?? "not set";

    private static string Truncate(string value)
    {
        const int maxLength = 12_000;
        return value.Length <= maxLength ? value : value[..maxLength] + Environment.NewLine + "[output truncated]";
    }
}

internal static class FrameworkLifecycle
{
    private static readonly Dictionary<int, DateOnly> EndOfSupport = new()
    {
        [8] = new DateOnly(2026, 11, 10),
        [9] = new DateOnly(2026, 11, 10),
        [10] = new DateOnly(2028, 11, 14)
    };

    public static (string Severity, string Status) Describe(string targetFramework, DateOnly today)
    {
        if (Regex.IsMatch(targetFramework, @"^net4\d{2}$", RegexOptions.IgnoreCase))
        {
            return ("Medium", ".NET Framework target: assess modernization and OS lifecycle separately");
        }

        var match = Regex.Match(targetFramework, @"^net(?<major>\d+)(?:\.\d+)?$", RegexOptions.IgnoreCase);
        if (!match.Success || !int.TryParse(match.Groups["major"].Value, out var major))
        {
            return ("Info", "support status not inferred automatically");
        }

        if (!EndOfSupport.TryGetValue(major, out var end))
        {
            return major < 8
                ? ("High", "out of support")
                : ("Info", "support date is not embedded; verify against Microsoft policy");
        }

        if (today > end)
        {
            return ("High", $"out of support since {end:yyyy-MM-dd}");
        }

        var days = end.DayNumber - today.DayNumber;
        return days <= 180
            ? ("Medium", $"supported until {end:yyyy-MM-dd}; migration window is under six months")
            : ("Info", $"supported until {end:yyyy-MM-dd}");
    }
}

internal sealed record ProjectInfo(
    string Path,
    string AbsolutePath,
    IReadOnlyList<string> Frameworks,
    string Nullable,
    string WarningsAsErrors);

internal sealed record Finding(string Severity, string Title, string Evidence);

internal sealed record CommandResult(string Command, int? ExitCode, string Output, bool TimedOut);

internal sealed record PreflightReport(
    string Root,
    DateTimeOffset GeneratedAt,
    bool StaticOnly,
    IReadOnlyList<ProjectInfo> Projects,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<CommandResult> Commands)
{
    public string ToMarkdown()
    {
        var builder = new StringBuilder();
        builder.AppendLine("# DotnetAudit Lite — preflight report");
        builder.AppendLine();
        builder.AppendLine($"> Generated locally on `{GeneratedAt:yyyy-MM-dd HH:mm zzz}`. Source code was not uploaded by this tool.");
        builder.AppendLine();
        builder.AppendLine($"- Repository: `{Root}`");
        builder.AppendLine($"- Mode: `{(StaticOnly ? "static-only" : "static + build/test/package audit")}`");
        builder.AppendLine($"- Projects: `{Projects.Count}`");
        builder.AppendLine($"- Findings: `{Findings.Count}`");
        builder.AppendLine();
        builder.AppendLine("This is an automated pre-check, not a security audit, penetration test, or guarantee that every defect was found.");
        builder.AppendLine();
        builder.AppendLine("## Projects");
        builder.AppendLine();
        builder.AppendLine("| Project | Target frameworks | Nullable | Warnings as errors |");
        builder.AppendLine("|---|---|---|---|");
        foreach (var project in Projects)
        {
            builder.AppendLine($"| `{Escape(project.Path)}` | `{Escape(string.Join(", ", project.Frameworks))}` | `{Escape(project.Nullable)}` | `{Escape(project.WarningsAsErrors)}` |");
        }

        builder.AppendLine();
        builder.AppendLine("## Findings");
        builder.AppendLine();
        builder.AppendLine("| Severity | Finding | Evidence |");
        builder.AppendLine("|---|---|---|");
        foreach (var finding in Findings.OrderBy(finding => SeverityOrder(finding.Severity)))
        {
            builder.AppendLine($"| {Escape(finding.Severity)} | {Escape(finding.Title)} | {Escape(finding.Evidence)} |");
        }

        if (Commands.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("## Executed checks");
            builder.AppendLine();
            foreach (var command in Commands)
            {
                builder.AppendLine($"### `{Escape(command.Command)}`");
                builder.AppendLine();
                builder.AppendLine($"Exit code: `{command.ExitCode?.ToString() ?? "not available"}`{(command.TimedOut ? " (timeout)" : string.Empty)}");
                builder.AppendLine();
                builder.AppendLine("```text");
                builder.AppendLine(command.Output.Replace("```", "` ` `", StringComparison.Ordinal));
                builder.AppendLine("```");
                builder.AppendLine();
            }
        }

        builder.AppendLine("## Recommended next step");
        builder.AppendLine();
        builder.AppendLine("Review the highest-severity items, confirm false positives, then scope one paid diagnosis, modernization assessment, reliability review, or full audit if human interpretation is required.");
        return builder.ToString();
    }

    public string ToSarif()
    {
        var distinctRules = Findings
            .GroupBy(finding => RuleId(finding.Title), StringComparer.Ordinal)
            .Select(group => new
            {
                id = group.Key,
                name = group.Key,
                shortDescription = new { text = group.First().Title },
                help = new
                {
                    text = "Review the evidence, confirm false positives and apply a repository-specific remediation.",
                    markdown = "Review the evidence, confirm false positives and apply a repository-specific remediation."
                }
            })
            .ToArray();

        var fallbackLocation = Projects.FirstOrDefault()?.Path ?? "README.md";
        var results = Findings.Select(finding =>
        {
            var location = ParseLocation(finding.Evidence);
            return new
            {
                ruleId = RuleId(finding.Title),
                level = SarifLevel(finding.Severity),
                message = new { text = $"{finding.Title}. Evidence: {finding.Evidence}" },
                locations = new object[]
                {
                    new
                    {
                        physicalLocation = new
                        {
                            artifactLocation = new { uri = location?.Path ?? fallbackLocation },
                            region = location?.Line is null ? null : new { startLine = location.Value.Line }
                        }
                    }
                }
            };
        }).ToArray();

        var sarif = new
        {
            version = "2.1.0",
            schema = "https://json.schemastore.org/sarif-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "DotnetAudit Lite",
                            informationUri = "https://github.com/Dalkory/DotnetAuditLite",
                            semanticVersion = "1.0.1",
                            rules = distinctRules
                        }
                    },
                    results
                }
            }
        };

        return JsonSerializer.Serialize(
            sarif,
            new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            })
            .Replace("\"schema\":", "\"$schema\":", StringComparison.Ordinal);
    }

    private static string Escape(string value) => value.Replace("|", "\\|", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    private static string RuleId(string title)
    {
        var normalized = Regex.Replace(title.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
        return string.IsNullOrWhiteSpace(normalized) ? "dotnet-preflight-finding" : $"dotnet-preflight-{normalized}";
    }

    private static string SarifLevel(string severity) => severity switch
    {
        "High" => "error",
        "Medium" => "warning",
        _ => "note"
    };

    private static (string Path, int? Line)? ParseLocation(string evidence)
    {
        var match = Regex.Match(evidence, @"^(?<path>[^:\r\n]+(?:/[^:\r\n]+)*)(?::(?<line>\d+))?");
        if (!match.Success)
        {
            return null;
        }

        var path = match.Groups["path"].Value.Replace('\\', '/');
        if (path.Contains(' ') && !path.Contains('/'))
        {
            return null;
        }

        return (
            path,
            int.TryParse(match.Groups["line"].Value, out var line) ? line : null);
    }

    private static int SeverityOrder(string severity) => severity switch
    {
        "High" => 0,
        "Medium" => 1,
        "Low" => 2,
        _ => 3
    };
}
