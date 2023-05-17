using System.Collections.Generic;
using System.IO;
using FileMode = System.IO.FileMode;

using Nuke.Common;
using Nuke.Common.CI.GitHubActions;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.GitVersion;
using Nuke.Common.Tools.ILRepack;
using Nuke.Common.Tools.NuGet;
using Nuke.Common.Utilities.Collections;
using Nuke.Common.Git;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.IO.PathConstruction;
using static Nuke.Common.Tools.DotNet.DotNetTasks;
using static Nuke.Common.Tools.ILRepack.ILRepackTasks;
using static Nuke.Common.Tools.NuGet.NuGetTasks;
using Project = Nuke.Common.ProjectModel.Project;

using NuGet.Packaging;
using NuGet.Packaging.Core;
using NuGet.Versioning;
using NuGet.Frameworks;
using Manifest = NuGet.Packaging.Manifest;

[GitHubActions(
    name: "cicd",
    GitHubActionsImage.WindowsLatest,
    FetchDepth = 0,
    OnPullRequestBranches = new[] { "main", },
    OnPushBranches = new[] { "main", "develop" },
    InvokedTargets = new[] { nameof(PublishNugetsGithub) },
    ImportSecrets = new[] { nameof(CertificateGenNugetApiKey) },
    EnableGitHubToken = true,
    PublishArtifacts = true,
    CacheKeyFiles = new[] { "global.json", "./**.csproj" }
)]
class Build : NukeBuild
{
    [Solution] readonly Solution Solution;

    [Nuke.Common.Parameter][Secret] readonly string CertificateGenNugetApiKey;

    [GitRepository] readonly GitRepository Repository;

    [GitVersion(UpdateAssemblyInfo = true, UpdateBuildNumber = true, NoFetch = true)]
    readonly GitVersion GitVersion;

    string Version => GitVersion.NuGetVersionV2;

    [Nuke.Common.Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
    readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    readonly string CoreProjectName = "CertificateGen";

    AbsolutePath CoreDirectory => RootDirectory / CoreProjectName;

    string username = "amescodes";
    RepositoryMetadata RepoMetadata => new RepositoryMetadata("git", @$"https://github.com/{username}/CertificateGen", GitVersion.BranchName, GitVersion.Sha);
    AbsolutePath NugetOutputDirectory => RootDirectory / "nuget";
    string[] NugetArtifacts => new string[] { NugetOutputDirectory / "*.nupkg", NugetOutputDirectory / "*.snupkg" };

    public static int Main() => Execute<Build>(x => x.Compile);

    Target _Clean => _ => _
        .Before(Restore)
        .Executes(() =>
        {
            CoreDirectory.GlobDirectories("*bin", "**/obj").ForEach(DeleteDirectory);
            EnsureCleanDirectory(NugetOutputDirectory);
        });

    Target Restore => _ => _
        .Executes(() =>
        {
            DotNetRestore(_ => _
                .SetProjectFile(Solution));
        });

    Target Compile => _ => _
        .DependsOn(Restore)
        .Executes(() =>
        {
            Project synapseCore = Solution.GetProject(CoreProjectName);
            DotNetBuild(_ => _
                .SetProjectFile(synapseCore)
                .SetVersion(Version)
                .SetConfiguration(Configuration)
                .SetSynapseBuildProperties());
        });

    Target Pack => _ => _
        .DependsOn(Compile)
        .Consumes(Compile)
        .Executes(() =>
        {
            AbsolutePath coreBuildDir = (AbsolutePath)CoreDirectory / $"bin/{Configuration}";
            //File.Copy(IconPath, coreBuildDir / IconFileName, true);

            ManifestMetadata coreNugetPackageMetadata = new ManifestMetadata()
            {
                Id = CoreProjectName,
                Description = "Core package for gRPSynapse library. This gRPSynapse package should be loaded into any shared projects between the client project and the Revit (or other) project.",
                Version = NuGetVersion.Parse(Version), // sets during pack
                //Icon = IconFileName,
                Repository = RepoMetadata,
            };
            coreNugetPackageMetadata.SetCommonNugetProperties();

            Manifest coreNuspecFile = NuGet.Packaging.Manifest.Create(coreNugetPackageMetadata);
            coreNuspecFile.Files.Add(new ManifestFile() { Source = $"{CoreProjectName}.dll", Target = "lib/netstandard2.0" });
            coreNuspecFile.Files.Add(new ManifestFile() { Source = $"{CoreProjectName}.pdb", Target = "lib/netstandard2.0" });

            //coreNuspecFile.Files.Add(new ManifestFile() { Source = IconFileName, Target = "." });

            AbsolutePath coreNuspecFilePath = coreBuildDir / $"{CoreProjectName}.nuspec";
            using (Stream nuspecStream = new FileStream(coreNuspecFilePath, FileMode.Create, FileAccess.Write))
            {
                coreNuspecFile.Save(nuspecStream);
            }

            Directory.CreateDirectory(NugetOutputDirectory);
            NuGetPack(_ => _
                .SetTargetPath(coreNuspecFilePath)
                .SetBasePath(coreBuildDir)
                .SetVersion(Version)
                .SetSynapsePackProperties(Configuration, NugetOutputDirectory));
        });


    Target PublishNugetsGithub => _ => _
        .Requires(() => IsLocalBuild == false)
        .DependsOn(Pack)
        .Consumes(Pack)
        .Executes(() =>
        {
            if (Repository.IsOnMainBranch()) // main branch pushes to nuget
            {
                GlobFiles(NugetOutputDirectory, "*.nupkg")
                .ForEach(x =>
                {
                    DotNetNuGetPush(_ => _
                        .SetTargetPath(x)
                        .SetNoSymbols(false)
                        .SetSource("nuget.org")
                        .SetApiKey(CertificateGenNugetApiKey)
                    );
                });
            }

            string sourceName = "github";
            DotNetNuGetAddSource(_ => _
                .SetUsername(username)
                .SetPassword(GitHubActions.Instance.Token)
                .SetStorePasswordInClearText(true)
                .SetName(sourceName)
                .SetSource($"https://nuget.pkg.github.com/{username}/index.json")
            );

            GlobFiles(NugetOutputDirectory, "*.nupkg")
                .ForEach(x =>
                {
                    DotNetNuGetPush(_ => _
                        .SetTargetPath(x)
                        .SetNoSymbols(false)
                        .SetSource(sourceName)
                        .SetApiKey(GitHubActions.Instance.Token)
                    );
                });
        });

    // core dependency version
    static PackageDependencyGroup[] MakeNuGetDependencyGroup()
    {
        PackageDependency unmanagedExportDep = new PackageDependency("Revit.Async", new VersionRange(NuGetVersion.Parse("2.0.1")));
        NuGetFramework targetFramework = NuGetFramework.Parse("net461", new DefaultFrameworkNameProvider());
        PackageDependencyGroup packageDependencyGroup = new PackageDependencyGroup(targetFramework, new List<PackageDependency>() { unmanagedExportDep });
        return new[] { packageDependencyGroup };
    }

    void MergeDllsWithILRepack()
    {
        AbsolutePath buildDir = (AbsolutePath)CoreDirectory / $"bin/{Configuration}";
        AbsolutePath dllFile = buildDir / $"{CoreProjectName}.dll";
        string[] inputAssemblies = new string[]
        {
            dllFile,
            buildDir / "gRPSynapse.Grpc.dll",
            buildDir / "Grpc.Core.dll",
            buildDir / "Grpc.Core.Api.dll",
        };

        ILRepack(_ => _
                .SetAssemblies(inputAssemblies)
                .SetLib(buildDir)
                .SetVersion(GitVersion.AssemblySemFileVer)
                .SetOutput(dllFile)
                .SetCopyAttributes(true)
                .SetUnion(true)
                .SetAllowMultiple(true)
                .SetParallel(false)
                .SetVerbose(true)
                .SetLogFile(buildDir / "log_ilrepack.txt")
        );

        // delete everything but synapse revit dll
        string[] files = Directory.GetFiles(buildDir);
        foreach (string filePath in files)
        {
            if (!File.Exists(filePath) ||
                filePath.Equals(dllFile) ||
                filePath.EndsWith($"{CoreProjectName}.pdb"))
            {
                continue;
            }

            File.Delete(filePath);
        }
    }
    
}

public static class BuildExtensions
{
    public static ManifestMetadata SetCommonNugetProperties(this ManifestMetadata nugetPackageMetadata)
    {
        nugetPackageMetadata.Authors = new[] { "ames codes" };
        nugetPackageMetadata.Tags = "revit grpc ipc synapse";
        nugetPackageMetadata.Copyright = "Copyright � 2022-23 ames codes";

        return nugetPackageMetadata;
    }

    public static DotNetBuildSettings SetSynapseBuildProperties(this DotNetBuildSettings settings)
    {
        return settings
            .SetNoRestore(true)
            .SetProperties(new Dictionary<string, object>()
            {
                    { "AppendTargetFrameworkToOutputPath", false },
                    { "AppendRuntimeIdentifierToOutputPath", false },
                    { "ResolveAssemblyWarnOrErrorOnTargetArchitectureMismatch", "None" },
            });
    }

    public static NuGetPackSettings SetSynapsePackProperties(this NuGetPackSettings settings, string configuration,
        string outputDirectory)
    {
        return settings
            .SetConfiguration(configuration)
            .SetBuild(false)
            .SetIncludeReferencedProjects(true)
            .SetSymbols(true)
            .SetSymbolPackageFormat(NuGetSymbolPackageFormat.snupkg)
            .SetOutputDirectory(outputDirectory);
    }
}
