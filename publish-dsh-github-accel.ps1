# publish-dsh-github-accel.ps1
#
# Creates the GitHub repository for this plugin, commits and pushes it, and
# optionally publishes a Release with a prebuilt tarball. Driven by the GitHub
# REST API + git; no gh CLI needed.
#
# Written with ASCII-only comments and string literals on purpose: this box's
# default shell is PowerShell 5.1, which reads a BOM-less UTF-8 script as ANSI
# and would mangle any non-ASCII text that reaches a request body or a path.
# Chinese documentation lives in docs/PUBLISHING.md instead.
#
# Prerequisites:
#   1. A GitHub PAT with `repo` scope, in $env:GH_TOKEN (preferred) or -Token.
#   2. A network path to github.com / api.github.com.
#
# Usage:
#   $env:GH_TOKEN = 'github_pat_...'
#   .\publish-dsh-github-accel.ps1 -Step preflight
#   .\publish-dsh-github-accel.ps1 -Step repo
#   .\publish-dsh-github-accel.ps1 -Step release -Tag v0.2.0
#
#   # if github.com is not reachable directly, borrow the plugin's own proxy:
#   .\publish-dsh-github-accel.ps1 -Step repo -Proxy 'http://127.0.0.1:18999'
#
# -DryRun prints every request without sending it.

[CmdletBinding()]
param(
  [ValidateSet('preflight', 'repo', 'release')][string]$Step = 'preflight',
  [string]$Owner = 'qcsjjjjj',
  [string]$RepoName = 'dsh-github-accel',
  [string]$Version = '0.2.0',
  [string]$Token = $env:GH_TOKEN,
  [string]$SourceDir,
  [string]$Tag = 'v0.2.0',
  [string]$CommitMessage = 'dsh-github-accel 0.2.0',
  [string]$RepoDescription = 'GitHub accelerator for DSH: hosts takeover + per-domain loopback SNI passthrough (no TLS MITM, no certificate install), a local CONNECT proxy and a PAC fallback.',
  [string]$Topic = 'dsh-plugin',
  [string]$Proxy = '',
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Default to the repository this script lives in, so it works wherever it was cloned.
if (-not $SourceDir) { $SourceDir = $PSScriptRoot }
if (-not (Test-Path -LiteralPath (Join-Path $SourceDir 'package.json'))) {
  throw "SourceDir does not look like the plugin repo (no package.json): $SourceDir"
}

if ($Proxy) {
  $env:HTTPS_PROXY = $Proxy
  $env:HTTP_PROXY = $Proxy
}
$env:GIT_TERMINAL_PROMPT = '0'

$script:CallNo = 0
function Say([string]$m) { Write-Host $m }

function Api {
  param(
    [string]$Method, [string]$Path, [hashtable]$Body, [switch]$Raw,
    [string]$InFile, [string]$ContentType, [string]$FullUri
  )
  $script:CallNo++
  $uri = if ($FullUri) { $FullUri } else { "https://api.github.com$Path" }
  $headers = @{
    Authorization          = "Bearer $Token"
    Accept                 = 'application/vnd.github+json'
    'User-Agent'           = 'dsh-github-accel-publish'
    'X-GitHub-Api-Version' = '2022-11-28'
  }
  if ($DryRun) {
    Say ("  [dry-run] {0} {1}" -f $Method, $uri)
    return $null
  }
  $p = @{ Method = $Method; Uri = $uri; Headers = $headers; TimeoutSec = 60 }
  if ($Proxy) { $p.Proxy = $Proxy }
  if ($ContentType) { $p.ContentType = $ContentType }
  if ($InFile) { $p.InFile = $InFile }
  elseif ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 6) }
  if ($Raw) { return Invoke-WebRequest @p } else { return Invoke-RestMethod @p }
}

function Invoke-Git {
  param([string[]]$GitArgs, [string]$WorkDir)
  $cwd = (Get-Location).ProviderPath
  $eap = $ErrorActionPreference
  # git writes progress to stderr; PS 5.1 turns that into a terminating error
  # while $ErrorActionPreference is 'Stop'. Judge by exit code instead.
  $ErrorActionPreference = 'Continue'
  if ($WorkDir) { Set-Location -LiteralPath $WorkDir }
  $code = 0
  try {
    $out = & git @GitArgs 2>&1
    $code = $LASTEXITCODE
  }
  finally {
    Set-Location -LiteralPath $cwd
    $ErrorActionPreference = $eap
  }
  if ($code -ne 0) { throw ("git " + ($GitArgs -join ' ') + " failed:`n" + ($out -join "`n")) }
  return $out
}

# ---------------------------------------------------------------- preflight
function Step-Preflight {
  Say "== preflight =="
  Say ("  source dir : {0}" -f $SourceDir)
  if (-not $Token) { throw "No token. Set `$env:GH_TOKEN or pass -Token." }

  $me = Api -Method GET -Path '/user'
  if ($me) {
    Say ("  token user : {0}" -f $me.login)
    if ($me.login -ne $Owner) { Say ("  WARNING: token belongs to '{0}', but -Owner is '{1}'" -f $me.login, $Owner) }
  }

  $branch = (git -C $SourceDir branch --show-current) -join ''
  Say ("  git branch : {0}" -f $branch)
  $st = @(git -C $SourceDir status --porcelain)
  Say ("  uncommitted: {0}" -f $st.Count)

  $pkg = Get-Content -LiteralPath (Join-Path $SourceDir 'package.json') -Raw | ConvertFrom-Json
  Say ("  package    : {0}@{1}" -f $pkg.name, $pkg.version)
  if ($pkg.private -eq $true) { throw "package.json still has `"private`": true - it would block publishing." }
  if (-not $pkg.dsh.bundle.patch) { throw "package.json does not declare dsh.bundle.patch." }

  $leftover = Select-String -Path (Join-Path $SourceDir 'package.json') -Pattern 'OWNER' -ErrorAction SilentlyContinue
  Say ("  OWNER placeholders: {0}" -f (@($leftover).Count))
  Say ""
}

# ------------------------------------------------------- phase B: repo + push
function Step-Repo {
  Say "== repo: create, commit, push =="
  $repoPath = "/repos/$Owner/$RepoName"
  $exists = $null
  try { $exists = Api -Method GET -Path $repoPath } catch { $exists = $null }

  if ($exists) {
    Say ("  repo already exists: {0} (private={1})" -f $exists.full_name, $exists.private)
  }
  else {
    Say ("  creating {0}/{1} (public, no auto-init)" -f $Owner, $RepoName)
    Api -Method POST -Path '/user/repos' -Body @{
      name        = $RepoName
      description = $RepoDescription
      private     = $false
      has_issues  = $true
      auto_init   = $false
    } | Out-Null
  }

  # local identity for this repo only
  if (-not (git -C $SourceDir config user.name)) { git -C $SourceDir config user.name $Owner }
  if (-not (git -C $SourceDir config user.email)) { git -C $SourceDir config user.email "$Owner@users.noreply.github.com" }

  git -C $SourceDir add -A
  $dirty = @(git -C $SourceDir status --porcelain)
  if ($dirty.Count -gt 0) {
    Say ("  committing {0} change(s)" -f $dirty.Count)
    if (-not $DryRun) { Invoke-Git @('commit', '-m', $CommitMessage) -WorkDir $SourceDir | Out-Null }
  }
  else { Say "  nothing to commit" }

  # push with an ephemeral auth header: the token never lands in .git/config
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("x-access-token:$Token"))
  $remote = "https://github.com/$Owner/$RepoName.git"
  $remotes = @(git -C $SourceDir remote)
  if ($remotes -notcontains 'origin') { Invoke-Git @('remote', 'add', 'origin', $remote) -WorkDir $SourceDir | Out-Null }
  else { Invoke-Git @('remote', 'set-url', 'origin', $remote) -WorkDir $SourceDir | Out-Null }

  $branch = (git -C $SourceDir branch --show-current) -join ''
  if ($DryRun) { Say ("  [dry-run] git push -u origin {0}" -f $branch) }
  else {
    Invoke-Git @('-c', "http.extraheader=AUTHORIZATION: basic $b64", 'push', '-u', 'origin', $branch) -WorkDir $SourceDir | Out-Null
    Say ("  pushed {0}" -f $branch)
  }

  # the marketplace's CI requires this topic
  Api -Method PUT -Path "$repoPath/topics" -Body @{ names = @($Topic) } | Out-Null
  Say ("  topic set: {0}" -f $Topic)
  Say ("  repo URL : https://github.com/{0}/{1}" -f $Owner, $RepoName)
  Say ""
}

# ------------------------------------------------- phase C: release + tarball
function Step-Release {
  Say "== release: prebuilt tarball =="
  $expected = Join-Path $SourceDir ("{0}-{1}.tgz" -f $RepoName, $Version)
  $tgz = $null
  if (Test-Path -LiteralPath $expected) { $tgz = $expected }
  else {
    $cand = @(Get-ChildItem -LiteralPath $SourceDir -Filter '*.tgz')
    if ($cand.Count -eq 0) { throw "no .tgz in $SourceDir - run: npm pack" }
    $tgz = $cand[0].FullName
  }
  Say ("  tarball  : {0} ({1} bytes)" -f $tgz, (Get-Item -LiteralPath $tgz).Length)

  # the asset name must carry NO version: releases/latest/download/<name> is literal
  $assetName = "$RepoName.tgz"

  $rel = $null
  try { $rel = Api -Method GET -Path "/repos/$Owner/$RepoName/releases/tags/$Tag" } catch { $rel = $null }
  if (-not $rel) {
    Say ("  creating release {0}" -f $Tag)
    $rel = Api -Method POST -Path "/repos/$Owner/$RepoName/releases" -Body @{
      tag_name = $Tag
      name     = $Tag
      body     = 'Prebuilt tarball so the marketplace can install from a bundle instead of building from source.'
      draft    = $false
    }
  }
  else { Say ("  release {0} already exists (id {1})" -f $Tag, $rel.id) }

  if ($DryRun) { Say ("  [dry-run] upload asset {0}" -f $assetName); return }

  $assetUri = "https://uploads.github.com/repos/$Owner/$RepoName/releases/$($rel.id)/assets?name=$assetName"
  Api -Method POST -FullUri $assetUri -InFile $tgz -ContentType 'application/gzip' | Out-Null
  $url = "https://github.com/$Owner/$RepoName/releases/latest/download/$assetName"
  Say ("  asset uploaded: {0}" -f $url)

  try {
    $head = @{ Method = 'Head'; Uri = $url; TimeoutSec = 40 }
    if ($Proxy) { $head.Proxy = $Proxy }
    $r = Invoke-WebRequest @head
    Say ("  latest/download check: HTTP {0}" -f $r.StatusCode)
  }
  catch { Say ("  latest/download check FAILED: {0}" -f $_.Exception.Message) }
  Say ""
}

# ------------------------------------------------------------------- driver
Say ("dsh-github-accel publish driver - owner={0} repo={1} step={2}{3}" -f $Owner, $RepoName, $Step, $(if ($DryRun) { ' (DRY RUN)' } else { '' }))
if ($Proxy) { Say ("proxy: {0}" -f $Proxy) }
Say ""
switch ($Step) {
  'preflight' { Step-Preflight }
  'repo' { Step-Preflight; Step-Repo }
  'release' { Step-Preflight; Step-Release }
}
Say "done."
