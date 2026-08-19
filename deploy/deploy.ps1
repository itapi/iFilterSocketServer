<#
.SYNOPSIS
  Deploy the committed tree to one of the two socket-server instances.

.DESCRIPTION
  This repo runs TWICE on the same VPS -- once per product. Nothing in server.js
  is product-specific, so both instances run identical code and differ only in
  their (gitignored, server-side) .env: instance name, port, JWT secret and CORS
  origins.

  They cannot be one process. `sessions` and `screenSessions` are keyed on
  clientId alone, and clientId is `client_unique_id`, an int(11) from each
  product's own clients table -- both sequences start at 1, so iShield client 42
  and iFilter client 42 would share the room `session:42`. The screen relay is a
  blind passthrough with no product check.

  Ships `git archive <ref>` -- the committed tree, not the working copy. Two
  consequences worth knowing:

    * Uncommitted edits are NOT deployed. Commit first. This is deliberate:
      what runs on the server is always a commit you can point at. The two
      installers in this estate were both found serving a working-tree snapshot
      that matched no commit in their repository.
    * Line endings are normalised to LF by git archive regardless of what the
      Windows working copy looks like.

  A code change therefore reaches both products as TWO deploys of ONE commit --
  deliberately, so an iShield change never restarts the process serving ~1,000
  iFilter devices. Deploy -Target ishield first (4-5 devices), verify, then
  -Target ifilter.

.PARAMETER Target
  Which instance to deploy to: ifilter or ishield. Required -- there is no
  default, because defaulting would eventually restart the wrong one.

.PARAMETER Ref
  Commit-ish to deploy. Defaults to HEAD.

.PARAMETER Force
  Deploy even if the working tree has uncommitted changes.

.EXAMPLE
  .\deploy\deploy.ps1 -Target ishield
  .\deploy\deploy.ps1 -Target ifilter -Ref v1.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ifilter', 'ishield')]
    [string] $Target,

    [string] $Ref = 'HEAD',
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

# ---- the two instances ----------------------------------------------------
# AppDir for iFilter keeps its 2026-07 name: the PM2 app was created against
# that path and renaming it would orphan the entry `pm2 save` restores on boot.
# The iShield one follows the /var/www convention the rest of the estate uses.
$Instances = @{
    ifilter = @{
        AppDir   = '/var/www/iFilterSocketServer'
        Pm2App   = 'ifilter-socket'
        SmokeUrl = 'https://socket.ikosher.me/health'
    }
    ishield = @{
        AppDir   = '/var/www/ishield-socket'
        Pm2App   = 'ishield-socket'
        SmokeUrl = 'https://ishield-socket.ikosher.me/health'
    }
}

$SshHost = 'root@srv1708204.hstgr.cloud'
$SshKey  = "$HOME\.ssh\id_ed25519_ifilter_dashboard"
# --------------------------------------------------------------------------

$inst     = $Instances[$Target]
$AppDir   = $inst.AppDir
$Pm2App   = $inst.Pm2App
$SmokeUrl = $inst.SmokeUrl

$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
    $dirty = git status --porcelain
    if ($dirty -and -not $Force) {
        Write-Host "Working tree has uncommitted changes:" -ForegroundColor Yellow
        $dirty | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" }
        Write-Host ""
        Write-Host "Those will NOT be deployed -- only committed work is." -ForegroundColor Yellow
        Write-Host "Commit them, or re-run with -Force to deploy HEAD anyway."
        exit 1
    }

    $sha     = (git rev-parse --short $Ref).Trim()
    $subject = (git log -1 --format=%s $Ref).Trim()
    Write-Host "Deploying $sha  $subject" -ForegroundColor Cyan
    Write-Host "        -> $Target  ($Pm2App)  $SshHost : $AppDir"

    $tar = Join-Path $env:TEMP "deploy-socket-$Target-$sha.tar"
    git archive --format=tar -o $tar $Ref
    if ($LASTEXITCODE -ne 0) { throw "git archive failed" }
    Write-Host ("        tar: {0:N0} KB" -f ((Get-Item $tar).Length / 1KB))

    $remoteTar = "/tmp/$(Split-Path $tar -Leaf)"
    & scp -q -i $SshKey $tar "${SshHost}:$remoteTar"
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }
    Remove-Item $tar -Force

    # remote-deploy.sh is copied up rather than piped to `bash -s`: piping it
    # through PowerShell prepends a UTF-8 BOM, which bash then tries to execute
    # as the first command. It ships from the WORKING COPY, which is why this
    # repo carries a .gitattributes pinning *.sh to LF -- a CRLF checkout would
    # hand bash a shebang ending in \r.
    $remoteSh = "/tmp/remote-deploy-socket-$sha.sh"
    & scp -q -i $SshKey (Join-Path $PSScriptRoot 'remote-deploy.sh') "${SshHost}:$remoteSh"
    if ($LASTEXITCODE -ne 0) { throw "scp of remote-deploy.sh failed" }

    $env_line = "APP_DIR='$AppDir' PM2_APP='$Pm2App' TARBALL='$remoteTar' SMOKE_URL='$SmokeUrl'"
    & ssh -i $SshKey $SshHost "$env_line bash $remoteSh; rc=`$?; rm -f $remoteSh; exit `$rc"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "DEPLOY FAILED (server rolled back if the swap had happened)" -ForegroundColor Red
        exit 1
    }
    Write-Host "Deployed $sha to $Target" -ForegroundColor Green
}
finally { Pop-Location }
