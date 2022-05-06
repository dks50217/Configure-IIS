<#
.SYNOPSIS
  Setting iis via powershell remotely

.DESCRIPTION
  Setting iis via powershell remotely

.PARAMETER user
  Session AD User
  EX: Michael.Chang.MA
  
.PARAMETER password
  Session Password

.PARAMETER server
  Update Server
  EX: ptw-crm-25

.PARAMETER mailFrom
  Send Report Mail (From)
  EX: mail

.PARAMETER mailTo
  Send Report Mail (To)
  EX: mail,mail
#>

[CmdletBinding()]
Param(
    [Parameter(mandatory=$true)]
    [string]$user = "",
    [Parameter(mandatory=$true)]
    [string]$password = "",
    [Parameter(mandatory=$true)]
    [string]$server = "",
    [Parameter(mandatory=$true)]
    [string]$mailFrom = "",
    [Parameter(mandatory=$true)]
    [string]$mailTo = ""
)

if ((Get-Module "WebAdministration" -ErrorAction SilentlyContinue) -eq $null){
	Import-Module WebAdministration
}


function Set-Session
{
    $securePassword = ConvertTo-SecureString $password -AsPlainText -force
    $cred = New-Object System.Management.Automation.PsCredential("PEGA\$($user)",$securePassword)
    return New-PSSession -computername $server -credential $cred
}

# New Server Open IIS
function Init-IIS
{
  Enable-WindowsOptionalFeature -FeatureName IIS-ASPNET45,IIS-HttpRedirect,IIS-RequestMonitor,IIS-URLAuthorization,IIS-IPSecurity,IIS-ApplicationInit,IIS-BasicAuthentication,IIS-ManagementService,IIS-WindowsAuthentication -Online -All -NoRestart
  $count = (Get-WindowsOptionalFeature -Online -FeatureName '*IIS*').Count
  New-Object -TypeName PSCustomObject -Property @{count=$count;}
}

function Get-Applications
{
   $appList = Get-WebApplication |Select @{Name='Name';Expression={$_.Path.Trim('/')}} |Select -Expand Name
   New-Object -TypeName PSCustomObject -Property @{appList=$appList;}
}

function Create-New-Site
{
  param(
    [string]$basePath = "D:\CRM_Production_Services\CRM_Portal_WebForm\", 
    [string]$siteName, 
    [string]$siteFolder, 
    [string]$hostHeader, 
    [string]$ipAddress = "*", 
    [int]$port = 80, 
    [string]$netVersion = "4.0", 
    [boolean]$enable32Bit = $false, 
    [boolean]$classicPipelineMode = $false
  )

  # CREATES FOLDERS, APPLICATION POOLS, WEB SITES, BINDINGS, ETC.
  Import-Module WebAdministration;
    
   # IF WEBSITE FOLDER DOES NOT EXIST, CREATE IT.
  [boolean]$pathExists=Test-Path $basePath$siteFolder;
  if ($pathExists -eq $False)
  {
      Write-Host "Creating Folder: $basePath$siteFolder";
      New-Item $basePath$siteFolder -type directory -Verbose | Log-Action;   
  }

  Write-Host "Creating Application Pool: $siteName";
  New-WebAppPool -Name $siteName -Force;
  Set-ItemProperty IIS:\AppPools\$siteName managedRuntimeVersion v$netVersion -Force -Verbose | Log-Action; # SET THE .NET RUNTIME VERSION 
  if ($enable32Bit -eq $True)
  {
    Set-ItemProperty IIS:\AppPools\$siteName enable32BitAppOnWin64 true -Force -Verbose | Log-Action; # IF APPLICABLE, ENABLE 32 BIT APPLICATIONS
  }
  if ($classicPipelineMode -eq $True)
  {
    Set-ItemProperty IIS:\AppPools\$siteName managedPipelineMode 1 -Force -Verbose | Log-Action; # IF APPLICABLE, SET TO CLASSIC PIPELINE MODE
  }
  Set-ItemProperty IIS:\AppPools\$siteName passAnonymousToken true -Force -Verbose | Log-Action; 
  Write-Host "Creating Website: $siteName :$port"; 
  New-Website -Name $siteName -ApplicationPool $siteName -ipAddress $ipAddress -HostHeader $hostHeader -PhysicalPath $basePath$siteFolder -Port $port  -Force -Verbose | Log-Action; # CREATE THE SITE
}


function Create-New-Application
{
  param(
    [string]$appName,
    [string]$appFolder,
    [string]$appPool,
    [string]$siteName
  )

  if ( (Test-Path "IIS:\Sites\$siteName\$appName") -eq $false ) 
  {
		Write-Host "Physical Path: $appFolder"
		New-Item "IIS:\Sites\$siteName\$appName" -type Application -physicalpath $appFolder -ApplicationPool $appPool
		Write-Host "$appName created"
		#IIS:\>New-WebApplication -Name testApp -Site 'Default Web Site' -PhysicalPath c:\test -ApplicationPool DefaultAppPool
	} 
  else 
  {
		Write-Host "$appName already exists"
	}
}

function Remove-Application 
{ 	
  param(
    [string]$appName,
    [string]$siteName
  )
  
  if ( (Test-Path "IIS:\Sites\$siteName\$appName") -eq $true ) 
  {
		Remove-Item "IIS:\Sites\$siteName\$appName" -recurse
		Write-Host "$appName removed"
		#IIS:\>Remove-WebApplication -Name TestApp -Site "Default Web Site"
	}
}

function Set-AnonymousAuthentication 
{
  param(
    [string]$website,
    [string]$appName,
    [bool]$value
  )
  
  $anonAuth = Get-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -location "$website/$appName"
	if( $anonAuth.Value -eq $value ){
		Write-Host "$appName Anonymous Authentication is already $value"
	} else {
		Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $value -location "$website/$appName"
		Write-Host "Anonymous Authentication now $value on $appName"
	}
}

function Enable-FormsAuthentication
{
  param(
    [string]$website,
    [string]$appName
  )
  
  $config = (Get-WebConfiguration system.web/authentication "IIS:Sites\$website\$appName")
	$config.mode = "Forms"
	$config | Set-WebConfiguration system.web/authentication
}

function Set-AppPool
{
  param(
    [string]$website,
    [string]$appName
  )

  $webApp = Get-ItemProperty "IIS:\Sites\$website\$appName"
	if( $webApp.applicationPool -eq $appPool ){
		Write-Host "$appName Application Pools is already $appPool"
	} else {
		Set-ItemProperty "IIS:\Sites\$website\$appName" applicationPool $appPool
		Write-Host "Set $appName to Application Pool $appPool"
	}
}


# $session = Set-Session


# if ($session)
# {
#     invoke-command -session $session -scriptblock ${function:Get-Applications}

#     Remove-PSSession -Session $session

#     PAUSE
# }