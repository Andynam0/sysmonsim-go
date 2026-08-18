param(
    [string]$ProjectPath = (Join-Path $PSScriptRoot "."),
    [string]$DefaultOwner = "your-github-owner"
)

$ErrorActionPreference = "Stop"
$script:GitExe = $null

function Read-Answer {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )
    if ([string]::IsNullOrWhiteSpace($Default)) {
        return Read-Host $Prompt
    }
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value
}

function Confirm-Step {
    param([string]$Prompt)
    $answer = Read-Host "$Prompt [y/N]"
    return $answer -match '^(y|yes)$'
}

function Find-OpenSshTool {
    param([string]$ToolName)

    $candidates = @(
        (Join-Path $env:WINDIR "System32\OpenSSH\$ToolName"),
        (Join-Path $env:WINDIR "Sysnative\OpenSSH\$ToolName")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $cmd = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

function Find-GitTool {
    $candidates = @(
        (Join-Path ${env:ProgramFiles} "Git\cmd\git.exe"),
        (Join-Path ${env:ProgramFiles} "Git\bin\git.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Git\cmd\git.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Git\bin\git.exe")
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $cmd = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

function Invoke-Git {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    if (-not $script:GitExe) {
        $script:GitExe = Find-GitTool
    }
    if (-not $script:GitExe) {
        throw "Could not find git.exe. Install Git for Windows or add git to PATH."
    }

    & $script:GitExe @Arguments
}

function Ensure-SshKey {
    $sshDir = Join-Path $HOME ".ssh"
    $privateKey = Join-Path $sshDir "id_ed25519"
    $publicKey = "$privateKey.pub"

    if (-not (Test-Path $publicKey)) {
        Write-Host "No SSH public key found at $publicKey" -ForegroundColor Yellow
        if (-not (Confirm-Step "Generate a new ed25519 SSH key now?")) {
            throw "An SSH public key is required for SSH-based git pushes."
        }

        New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
        $email = Read-Answer -Prompt "Email label for the SSH key comment" -Default ""
        $sshKeygen = Find-OpenSshTool -ToolName "ssh-keygen.exe"
        if (-not $sshKeygen) {
            throw "Could not find ssh-keygen.exe. Install the Windows OpenSSH Client feature or add ssh-keygen to PATH."
        }
        & $sshKeygen -t ed25519 -C $email -f $privateKey | Out-Host
    }

    return $publicKey
}

function Show-PublicKeyInstructions {
    param([string]$PublicKeyPath)

    Write-Host ""
    Write-Host "Add this SSH public key to GitHub:" -ForegroundColor Green
    Write-Host "GitHub -> Settings -> SSH and GPG keys -> New SSH key" -ForegroundColor Green
    Write-Host ""
    Get-Content $PublicKeyPath
    Write-Host ""
}

function Ensure-GitIdentity {
    $name = Invoke-Git config --global user.name 2>$null
    $email = Invoke-Git config --global user.email 2>$null

    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = Read-Answer -Prompt "Git user.name" -Default ""
        Invoke-Git config --global user.name $name
    }
    if ([string]::IsNullOrWhiteSpace($email)) {
        $email = Read-Answer -Prompt "Git user.email" -Default ""
        if (-not [string]::IsNullOrWhiteSpace($email)) {
            Invoke-Git config --global user.email $email
        }
    }
}

function Ensure-GitRepo {
    param([string]$Path)

    Push-Location $Path
    try {
        if (-not (Test-Path (Join-Path $Path ".git"))) {
            Invoke-Git init -b main
        }
    } finally {
        Pop-Location
    }
}

function Ensure-Gitignore {
    param([string]$Path)

    $gitignorePath = Join-Path $Path ".gitignore"
    $desired = @(
        "bin/",
        "*.exe",
        "*.dll",
        "*.test",
        "*.out",
        ".DS_Store"
    )

    if (-not (Test-Path $gitignorePath)) {
        Set-Content -Path $gitignorePath -Value ($desired -join [Environment]::NewLine)
        return
    }

    $current = Get-Content $gitignorePath
    $missing = $desired | Where-Object { $_ -notin $current }
    if ($missing) {
        Add-Content -Path $gitignorePath -Value ([Environment]::NewLine + ($missing -join [Environment]::NewLine))
    }
}

function Commit-CurrentState {
    param([string]$Path)

    Push-Location $Path
    try {
        Invoke-Git add .
        Invoke-Git diff --cached --quiet
        if ($LASTEXITCODE -ne 0) {
            $message = Read-Answer -Prompt "Initial commit message" -Default "Initial sysmonsim-go import"
            Invoke-Git commit -m $message
        } else {
            Write-Host "No staged changes to commit." -ForegroundColor Yellow
        }
    } finally {
        Pop-Location
    }
}

function Set-Remote {
    param(
        [string]$Path,
        [string]$RemoteUrl
    )

    Push-Location $Path
    try {
        $existing = Invoke-Git remote get-url origin 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($existing)) {
            if (Confirm-Step "Remote 'origin' exists ($existing). Replace it?") {
                Invoke-Git remote set-url origin $RemoteUrl
            }
        } else {
            Invoke-Git remote add origin $RemoteUrl
        }
    } finally {
        Pop-Location
    }
}

function Try-CreateGitHubRepo {
    param(
        [string]$Owner,
        [string]$RepoName,
        [string]$Visibility,
        [string]$Path
    )

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        Write-Host "GitHub CLI 'gh' not found. Skipping repo creation." -ForegroundColor Yellow
        return $false
    }

    gh auth status *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "GitHub CLI is not authenticated. Run 'gh auth login' later if you want automatic repo creation." -ForegroundColor Yellow
        return $false
    }

    Push-Location $Path
    try {
        gh repo create "$Owner/$RepoName" "--$Visibility" --source . --remote origin --push=$false
        return ($LASTEXITCODE -eq 0)
    } finally {
        Pop-Location
    }
}

Write-Host "GitHub setup helper for sysmonsim-go" -ForegroundColor Green
Write-Host "Project path: $ProjectPath"
Write-Host ""

$publicKeyPath = Ensure-SshKey
Show-PublicKeyInstructions -PublicKeyPath $publicKeyPath

if (-not (Confirm-Step "Have you added that key to GitHub already?")) {
    Write-Host "Add the key first, then rerun this script." -ForegroundColor Yellow
    exit 0
}

$owner = Read-Answer -Prompt "GitHub owner or org" -Default $DefaultOwner
$repoName = Read-Answer -Prompt "Repository name" -Default "sysmonsim-go"
$visibility = Read-Answer -Prompt "Visibility (public/private)" -Default "private"

Ensure-GitRepo -Path $ProjectPath
Ensure-GitIdentity
Ensure-Gitignore -Path $ProjectPath

$remoteUrl = "git@github.com:$owner/$repoName.git"
$created = $false

if (Confirm-Step "Try creating the GitHub repo with 'gh' if available?") {
    $created = Try-CreateGitHubRepo -Owner $owner -RepoName $repoName -Visibility $visibility -Path $ProjectPath
}

Set-Remote -Path $ProjectPath -RemoteUrl $remoteUrl
Commit-CurrentState -Path $ProjectPath

Write-Host ""
Write-Host "Next commands:" -ForegroundColor Green
Write-Host "  cd `"$ProjectPath`""
Write-Host "  git remote -v"
if ($created) {
    Write-Host "  git push -u origin main"
} else {
    Write-Host "  Create the empty repo on GitHub if needed, then run:"
    Write-Host "  git push -u origin main"
}
