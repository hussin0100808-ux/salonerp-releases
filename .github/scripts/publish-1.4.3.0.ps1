#requires -Version 7.2
[CmdletBinding(DefaultParameterSetName='Publish')]
param(
    [Parameter(Mandatory,ParameterSetName='Publish')][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory,ParameterSetName='Local')][string]$VerifyLocalDirectory,
    [Parameter(ParameterSetName='Local')][string]$ResultPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repository = 'hussin0100808-ux/salonerp-releases'
$Tag = 'v1.4.3.0'
$ReleaseTitle = 'Q Salon 1.4.3.0'
$ReleaseBase = "https://github.com/$Repository/releases/download/$Tag"
$ApiBase = "https://api.github.com/repos/$Repository"
$Assets = @(
    @{ Name='SalonERP-1.4.3.0.zip'; Size=3807234L; Sha256='05746afe204a3e2a5d210f9e4fd14e5b75b3ae07567293486a6e44c8dd5f9c1c'; Type='application/zip' },
    @{ Name='SalonERP-Database-1.4.3.0.zip'; Size=3124L; Sha256='acae1a42ef4d9e996c99c033f46adf287e98f77236636ab8b2ad84c7e82d62c9'; Type='application/zip' },
    @{ Name='latest.json'; Size=4077L; Sha256='a3dc3765ec91c74ed60d9ccdd678b2fffda4af3bed1201f864a056bd2764ae3b'; Type='application/json' }
)
$Notes = @{ Name='RELEASE-NOTES.txt'; Size=1117L; Sha256='899d2cecb8b02b33cf5279e9f37c04a8dd1c5c068bd172863227b559d923af8b' }
$PublicModulus = '83nNeRC/f32HNU2hhrORgYgqjMrJNLjuLHZJrMJFjADjA/4P7x9pYZGpt7mCPYv5ADAZq5QlObcKd1g4uD4fXSy3WnGbHX0sfSYI5sZm1F8p8t+TU/K+1mCJVW5SOjRJBM6b5U/rNGrOZBxVzG0z+fkLU5VM4IP+w1lnleNiTVijqFRLcJQbCPUQqJ4qny5G/xXB0ShHSSGqACiUNGwF8yNUz4GK/gO7VHIRG/MF96YNAJlPS1yWbPY2K93E/569BGn4j9ZI07KYBvOY+OZ6B22krwIhDqnGfS9B4DjfjbZCBvpAkBbvSiLm4Az5vvBmRl41UY/DRii6zTJiPprhlZh5bBhU/jR/flb8NfB4BhMp0x3ZPFjrr5yRHTEsixHVVueWr+QMKq8BKexsCadOgih3LhvU3G6Z3otCJKBfJPU2ouAQv2xON0hHVdGl3nwkk8+gxqhiwTo33t+FKxhVVs/bZdAevwvJ/Symsk8OK1RfydBQE3DdjdYezkDYMGlV'
$Checks = [Collections.Generic.List[string]]::new()
$ReleaseId = 0L
$PublishAttempted = $false
$Published = $false
$Http = $null

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Validation failed: $Message" }
    [void]$Checks.Add($Message)
}
function Hash-Stream([IO.Stream]$Stream) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($hasher.ComputeHash($Stream)).ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
function Test-File([string]$Path, $Expected) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert (-not $item.PSIsContainer -and $item.Length -eq $Expected.Size) "Size: $($Expected.Name)"
    Assert ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ieq $Expected.Sha256) "SHA256: $($Expected.Name)"
}
function Test-Zip([string]$Path, [object[]]$Records, [string[]]$AllowedPaths) {
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        Assert ($archive.Entries.Count -eq $AllowedPaths.Count -and $Records.Count -eq $AllowedPaths.Count) "Exact ZIP inventory: $([IO.Path]::GetFileName($Path))"
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            Assert ($AllowedPaths -ccontains $entry.FullName -and $seen.Add($entry.FullName)) "Allowlisted unique ZIP entry: $($entry.FullName)"
            $record = @($Records | Where-Object { $_.Path -ceq $entry.FullName })
            Assert ($record.Count -eq 1 -and $entry.Length -eq [long]$record[0].Size -and $entry.Length -le 10000000) "Declared ZIP length: $($entry.FullName)"
            Assert ((([uint32]$entry.ExternalAttributes -shr 16) -band 0xF000) -ne 0xA000) "No symbolic link: $($entry.FullName)"
            $stream = $entry.Open()
            try { Assert ((Hash-Stream $stream) -ceq $record[0].Sha256.ToLowerInvariant()) "ZIP content digest: $($entry.FullName)" }
            finally { $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
}
function Test-Inputs([string]$Directory) {
    foreach ($expected in @($Assets) + @($Notes)) { Test-File (Join-Path $Directory $expected.Name) $expected }
    $utf8 = [Text.UTF8Encoding]::new($false,$true)
    $envelope = $utf8.GetString([IO.File]::ReadAllBytes((Join-Path $Directory 'latest.json'))).TrimStart([char]0xFEFF) | ConvertFrom-Json
    $payload = [Convert]::FromBase64String($envelope.Payload)
    $signature = [Convert]::FromBase64String($envelope.Signature)
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $parameters = [Security.Cryptography.RSAParameters]::new()
        $parameters.Modulus = [Convert]::FromBase64String($PublicModulus)
        $parameters.Exponent = [Convert]::FromBase64String('AQAB')
        $rsa.ImportParameters($parameters)
        Assert ($rsa.VerifyData($payload,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'Publisher RSA-SHA256 signature'
    } finally { $rsa.Dispose() }
    $manifest = $utf8.GetString($payload) | ConvertFrom-Json
    Assert ($manifest.Format -eq 2 -and $manifest.Product -ceq 'SalonERP' -and $manifest.Version -ceq '1.4.3.0') 'Manifest identity and format'
    Assert ($manifest.RequiredSchema -eq 35 -and $manifest.MaximumSchema -eq 35) 'Application requires schema 35'
    Assert ($manifest.PackageUrl -ceq "$ReleaseBase/$($Assets[0].Name)" -and $manifest.PackageSha256 -ieq $Assets[0].Sha256 -and $manifest.PackageSize -eq $Assets[0].Size) 'Signed application URL, length and digest'
    $database = $manifest.DatabasePackage
    Assert ($database.PackageUrl -ceq "$ReleaseBase/$($Assets[1].Name)" -and $database.Sha256 -ieq $Assets[1].Sha256 -and $database.Size -eq $Assets[1].Size) 'Signed database URL, length and digest'
    Assert ($database.FromSchema -eq 33 -and $database.ToSchema -eq 35 -and $database.Files.Count -eq 2) 'Supported database migration range 33 to 35'
    Assert ($database.Files[0].Path -ceq 'Database/034_SqlHostClock.sql' -and $database.Files[0].FromSchema -eq 33 -and $database.Files[0].ToSchema -eq 34) 'Migration 034 order and boundary'
    Assert ($database.Files[1].Path -ceq 'Database/035_UpdateAuthorization.sql' -and $database.Files[1].FromSchema -eq 34 -and $database.Files[1].ToSchema -eq 35) 'Migration 035 order and boundary'
    $appNames = @('SalonERP.Desktop.exe','SalonERP.Application.dll','SalonERP.Data.dll','SalonERP.Domain.dll','SalonERP.Infrastructure.dll','SalonERP.Accounting.dll','SalonERP.Licensing.dll','SalonERP.Reporting.dll','SalonERP.Updater.exe','Assets/SalonTaskbar.ico','Assets/SalonAppIcon.ico')
    Test-Zip (Join-Path $Directory $Assets[0].Name) $manifest.Files $appNames
    Test-Zip (Join-Path $Directory $Assets[1].Name) $database.Files @('Database/034_SqlHostClock.sql','Database/035_UpdateAuthorization.sql')
    return $utf8.GetString([IO.File]::ReadAllBytes((Join-Path $Directory $Notes.Name))).TrimStart([char]0xFEFF).TrimEnd()
}
function New-Request([string]$Method,[string]$Url,[bool]$Authenticated,[string]$Accept) {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),$Url)
    $request.Headers.UserAgent.ParseAdd('QSalon-Verified-Release-Publisher/1.4.3.0')
    [void]$request.Headers.TryAddWithoutValidation('Accept',$Accept)
    if ($Authenticated) {
        $uri = [Uri]$Url
        Assert ($uri.Scheme -ceq 'https' -and $uri.Host -in @('api.github.com','uploads.github.com')) 'Credential destination allowlist'
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$env:GITHUB_TOKEN)
        [void]$request.Headers.TryAddWithoutValidation('X-GitHub-Api-Version','2022-11-28')
    }
    return $request
}
function Read-JsonResponse($Response,[string]$Phase) {
    if (-not $Response.IsSuccessStatusCode) { throw "$Phase failed with HTTP $([int]$Response.StatusCode); no response body or credentials logged." }
    $contentLength = $Response.Content.Headers.ContentLength
    Assert ($null -eq $contentLength -or $contentLength -le 2000000) "Bounded JSON response: $Phase"
    $inputStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $memory = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(65536)
        while (($read = $inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($memory.Length + $read -gt 2000000) { throw 'GitHub JSON response exceeded its reviewed limit.' }
            $memory.Write($buffer,0,$read)
        }
        return [Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json -Depth 30
    } finally { $inputStream.Dispose(); $memory.Dispose() }
}
function Invoke-Api([string]$Method,[string]$Path,$Body=$null,[switch]$Allow404) {
    Assert ($Path.StartsWith('/') -and -not $Path.Contains('..')) 'Scoped API path'
    $request = New-Request $Method ($ApiBase + $Path) $true 'application/vnd.github+json'
    $response = $null
    try {
        if ($null -ne $Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 15 -Compress),[Text.Encoding]::UTF8,'application/json') }
        $response = $Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($Allow404 -and [int]$response.StatusCode -eq 404) { return $null }
        return Read-JsonResponse $response "$Method $Path"
    } finally { if ($null -ne $response) { $response.Dispose() }; $request.Dispose() }
}
function Save-Response($Response,[string]$Destination,[long]$ExpectedLength) {
    Assert ([int]$Response.StatusCode -eq 200) 'Binary download returns HTTP 200'
    Assert ($null -eq $Response.Content.Headers.ContentLength -or $Response.Content.Headers.ContentLength -eq $ExpectedLength) 'Download declared length'
    $inputStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $outputStream = [IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while (($read = $inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $ExpectedLength) { throw 'Download exceeded the reviewed length.' }
            $outputStream.Write($buffer,0,$read)
        }
        Assert ($total -eq $ExpectedLength) 'Download actual length'
    } finally { $outputStream.Dispose(); $inputStream.Dispose() }
}
function Download-Raw($Expected,[string]$Directory) {
    $url = "https://raw.githubusercontent.com/$Repository/$SourceCommit/release-inputs/1.4.3.0/$($Expected.Name)"
    $request = New-Request 'GET' $url $false 'application/octet-stream'
    $response = $null
    try {
        $response = $Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        Save-Response $response (Join-Path $Directory $Expected.Name) $Expected.Size
    } finally { if ($null -ne $response) { $response.Dispose() }; $request.Dispose() }
}
function Assert-SourceRef {
    $main = Invoke-Api 'GET' '/git/ref/heads/main'
    Assert ($main.object.type -ceq 'commit' -and $main.object.sha -ceq $SourceCommit) 'Main still points at the reviewed source commit'
    $tagRef = Invoke-Api 'GET' "/git/ref/tags/$Tag" -Allow404
    if ($null -ne $tagRef) {
        $target = $tagRef.object
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        for ($depth=0; $target.type -ceq 'tag' -and $depth -lt 4; $depth++) {
            Assert ($target.sha -cmatch '^[0-9a-f]{40}$' -and $seen.Add([string]$target.sha)) 'Bounded annotated tag resolution'
            $tagObject = Invoke-Api 'GET' "/git/tags/$($target.sha)"
            $target = $tagObject.object
        }
        Assert ($target.type -ceq 'commit' -and $target.sha -ceq $SourceCommit) 'Existing release tag resolves to the reviewed source commit'
    }
}
function Find-Release {
    $matches = [Collections.Generic.List[object]]::new()
    for ($page=1; $page -le 10; $page++) {
        $items = @(Invoke-Api 'GET' "/releases?per_page=100&page=$page")
        foreach ($item in $items) { if ($item.tag_name -ceq $Tag) { [void]$matches.Add($item) } }
        if ($items.Count -lt 100) { break }
        if ($page -eq 10) { throw 'Release listing exceeded the bounded scan; no mutation performed.' }
    }
    Assert ($matches.Count -le 1) 'At most one release for this tag'
    if ($matches.Count -eq 0) { return $null }
    return $matches[0]
}
function Get-Assets([long]$Id) { return @(Invoke-Api 'GET' "/releases/$Id/assets?per_page=100") }
function Test-AssetMetadata($Asset,$Expected) {
    Assert ($Asset.id -gt 0 -and $Asset.name -ceq $Expected.Name -and $Asset.state -ceq 'uploaded') "Remote asset identity: $($Expected.Name)"
    Assert ($Asset.size -eq $Expected.Size -and $Asset.digest -ceq "sha256:$($Expected.Sha256)") "Remote asset size and server digest: $($Expected.Name)"
}
function Test-AssetSet([object[]]$Remote,[bool]$Complete) {
    Assert ($Remote.Count -le 3 -and (-not $Complete -or $Remote.Count -eq 3)) 'Exact bounded release asset count'
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($asset in $Remote) {
        $expected = @($Assets | Where-Object { $_.Name -ceq $asset.name })
        Assert ($expected.Count -eq 1 -and $seen.Add([string]$asset.name)) 'Remote asset name is unique and allowlisted'
        Test-AssetMetadata $asset $expected[0]
    }
}
function Test-RemoteAsset($Asset,$Expected,[string]$Directory) {
    Test-AssetMetadata $Asset $Expected
    $request = New-Request 'GET' "$ApiBase/releases/assets/$($Asset.id)" $true 'application/octet-stream'
    $response = $null
    $redirectRequest = $null
    try {
        $response = $Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ([int]$response.StatusCode -in @(302,307)) {
            $destination = $response.Headers.Location
            Assert ($null -ne $destination -and $destination.IsAbsoluteUri -and $destination.Scheme -ceq 'https' -and $destination.Port -eq 443 -and [string]::IsNullOrEmpty($destination.UserInfo) -and $destination.Host -in @('release-assets.githubusercontent.com','objects.githubusercontent.com')) 'GitHub asset redirect host allowlist'
            $response.Dispose()
            $response = $null
            # Never forward GITHUB_TOKEN to the signed asset-storage URL.
            $redirectRequest = New-Request 'GET' $destination.AbsoluteUri $false 'application/octet-stream'
            $response = $Http.SendAsync($redirectRequest,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        }
        $local = Join-Path $Directory ("verified-" + [Guid]::NewGuid().ToString('N') + '-' + $Expected.Name)
        Save-Response $response $local $Expected.Size
        Test-File $local $Expected
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $redirectRequest) { $redirectRequest.Dispose() }
        $request.Dispose()
    }
}
function Upload-Asset([long]$Id,$Expected,[string]$Directory) {
    $url = "https://uploads.github.com/repos/$Repository/releases/$Id/assets?name=$([Uri]::EscapeDataString($Expected.Name))"
    $request = New-Request 'POST' $url $true 'application/vnd.github+json'
    $response = $null
    $stream = [IO.File]::OpenRead((Join-Path $Directory $Expected.Name))
    try {
        $request.Content = [Net.Http.StreamContent]::new($stream)
        $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new($Expected.Type)
        $request.Content.Headers.ContentLength = $Expected.Size
        $response = $Http.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        return Read-JsonResponse $response "Upload $($Expected.Name)"
    } finally { if ($null -ne $response) { $response.Dispose() }; $request.Dispose(); $stream.Dispose() }
}
function Test-ReleaseIdentity($Release,[string]$Body) {
    Assert ($Release.id -gt 0 -and $Release.tag_name -ceq $Tag -and $Release.name -ceq $ReleaseTitle -and -not $Release.prerelease) 'Release identity, title and channel'
    Assert ([string]$Release.body -ceq $Body) 'Release notes exactly match the reviewed text'
}
function Write-Result([string]$Status) {
    $result = [ordered]@{ Passed=$true; Status=$Status; Version='1.4.3.0'; Repository=$Repository; Tag=$Tag; ReleaseId=$ReleaseId; SourceCommit=$SourceCommit; Published=$Published; Checks=$Checks.Count; Assertions=$Checks.ToArray(); Assets=$Assets; Utc=[DateTime]::UtcNow.ToString('o') }
    if ($ResultPath) {
        $json = $result | ConvertTo-Json -Depth 10
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $file = [IO.File]::Open($ResultPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $file.Write($bytes,0,$bytes.Length) } finally { $file.Dispose() }
    }
    Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
}
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if ($PSCmdlet.ParameterSetName -ceq 'Local') {
        $null = Test-Inputs ([IO.Path]::GetFullPath($VerifyLocalDirectory))
        Write-Result 'LocalVerificationOnly'
        return
    }
    Assert ($env:GITHUB_ACTIONS -ceq 'true' -and $env:GITHUB_REPOSITORY -ceq $Repository -and $env:GITHUB_REF -ceq 'refs/heads/main') 'Only the intended GitHub Actions repository and branch may publish'
    Assert ($SourceCommit -ceq $env:GITHUB_SHA -and -not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) 'Exact triggering commit and job token present'
    Assert (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) 'Ephemeral runner directory available'
    $work = Join-Path $env:RUNNER_TEMP ('qsalon-publish-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($work)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $Http = [Net.Http.HttpClient]::new($handler)
    $Http.Timeout = [TimeSpan]::FromMinutes(3)
    foreach ($expected in @($Assets) + @($Notes)) { Download-Raw $expected $work }
    $releaseBody = Test-Inputs $work
    $release = Find-Release
    if ($null -ne $release -and -not $release.draft) {
        # A published release is immutable for this workflow. Never edit or replace it.
        $ReleaseId = [long]$release.id
        Test-ReleaseIdentity $release $releaseBody
        $remote = @(Get-Assets $ReleaseId)
        Test-AssetSet $remote $true
        foreach ($expected in $Assets) { Test-RemoteAsset (@($remote | Where-Object { $_.name -ceq $expected.Name })[0]) $expected $work }
        $Published = $true
        Write-Result 'AlreadyPublishedVerifiedNoChanges'
        return
    }
    Assert-SourceRef
    if ($null -eq $release) {
        $release = Invoke-Api 'POST' '/releases' @{ tag_name=$Tag; target_commitish=$SourceCommit; name=$ReleaseTitle; body=$releaseBody; draft=$true; prerelease=$false }
    }
    $ReleaseId = [long]$release.id
    Test-ReleaseIdentity $release $releaseBody
    Assert ($release.draft -and $release.target_commitish -ceq $SourceCommit) 'Only the matching draft at this exact commit can be resumed'
    $remote = @(Get-Assets $ReleaseId)
    Test-AssetSet $remote $false
    foreach ($expected in $Assets) {
        $existing = @($remote | Where-Object { $_.name -ceq $expected.Name })
        if ($existing.Count -eq 0) { $asset = Upload-Asset $ReleaseId $expected $work }
        else { $asset = $existing[0] }
        Test-RemoteAsset $asset $expected $work
    }
    $remote = @(Get-Assets $ReleaseId)
    Test-AssetSet $remote $true
    Assert-SourceRef
    $release = Invoke-Api 'GET' "/releases/$ReleaseId"
    Test-ReleaseIdentity $release $releaseBody
    Assert ($release.draft -and $release.target_commitish -ceq $SourceCommit) 'Draft remains unchanged immediately before publication'
    $PublishAttempted = $true
    $release = Invoke-Api 'PATCH' "/releases/$ReleaseId" @{ draft=$false; make_latest='true' }
    Assert (-not $release.draft) 'Release publication acknowledged'
    $Published = $true
    $release = Invoke-Api 'GET' "/releases/$ReleaseId"
    Test-ReleaseIdentity $release $releaseBody
    Assert (-not $release.draft) 'Published state read back'
    Test-AssetSet @(Get-Assets $ReleaseId) $true
    $latest = Invoke-Api 'GET' '/releases/latest'
    Assert ($latest.id -eq $ReleaseId -and -not $latest.draft) 'New release is the latest published release'
    Write-Result 'PublishedAndVerified'
} catch {
    # Do not expose HTTP exception objects/headers, token, or signed redirect URLs.
    $state = if ($PublishAttempted) { 'Publication was attempted; review the release state before retrying. No rollback or deletion was performed.' } elseif ($ReleaseId -gt 0) { 'The existing release state is preserved for review/resume. No existing assets were replaced.' } else { 'Publication was not attempted.' }
    $safeReason = if ($_.Exception.Message.StartsWith('Validation failed:') -or $_.Exception.Message.StartsWith('Download exceeded') -or $_.Exception.Message.StartsWith('Release listing exceeded')) { $_.Exception.Message } else { $_.Exception.GetType().FullName }
    Write-Error ("Q Salon release verification/publishing stopped. ReleaseId=$ReleaseId. $state Reason: $safeReason") -ErrorAction Continue
    exit 1
} finally { if ($null -ne $Http) { $Http.Dispose() } }