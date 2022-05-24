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

.PARAMETER command
  command
  EX: AppPool/Site/Application

.PARAMETER action
  command
  EX: empty/0/1/2

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
    [string]$command = "",
    [Parameter(mandatory=$true)]
    [string]$action = "",
    [string]$param = "" #Json Format like {"siteName": "","appName":""}
)

# if ((Get-Module "WebAdministration" -ErrorAction SilentlyContinue) -eq $null){
# 	Import-Module WebAdministration
# }

function TestServerConnection([string] $server) 
{
    if (test-connection -ComputerName $server -Count 1 -ErrorAction SilentlyContinue ) 
    {
      return $true
    }
    else 
    {
      return $false
    }
}

function Set-Session
{
    $isSuccess = $false;
    $reason = "";
    
    try
    {
      $securePassword = ConvertTo-SecureString $password -AsPlainText -force
      $cred = New-Object System.Management.Automation.PsCredential("PEGA\$($user)",$securePassword)
      $session = New-PSSession -computername $server -credential $cred -EA Stop
      $isSuccess = $true
    }
    catch
    {
       Write-Host "An error occurred:"
       $reason = $_
    }

    $rtnObj = @{
      isSuccess = $isSuccess
      session = $session
      reason = $reason
    }

    return $rtnObj;
}

#ps4 may not work
function Get-AppPoolList
{
  Import-Module WebAdministration;
  $isSuccess = $false
  $reason = "";
   
  try 
  {
    $appPoolList = Get-IISAppPool | Select-Object Name,State,ManagedRuntimeVersion,ManagedPipelineMode,AutoStart,StartMode,Enable32BitAppOnWin64
    $isSuccess = $true;
  }
  catch 
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{appPoolList=$appPoolList;isSuccess=$isSuccess;reason=$reason}
}


function Get-Site-List
{
  Import-Module WebAdministration;
  
  $isSuccess = $false
  $reason = "";

  try 
  {
    $siteList = get-website | Select-Object id,name,state,applicationPool,physicalPath,bindings,enabledProtocols,serverAutoStart
    $isSuccess = $true;
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{siteList=$siteList;isSuccess=$isSuccess;reason=$reason}
}

function Get-Application-List
{
  param (
    [string]$siteName
  )

  Import-Module WebAdministration;

  $isSuccess = $false
  $reason = "";

  try 
  {
    $appList = Get-WebApplication -Site $siteName | Select-Object path,applicationPool,PhysicalPath

    #Get VirtualDirectory and save in list item
    foreach ($appItem in $appList)
    {
      $appName = $appItem.path.trim('/')
      $virtualList = Get-WebVirtualDirectory -Site $siteName -Application $appName | Select-Object path,physicalPath #get VirtualDirectory
      
      If ($virtualList)
      {
        If ($virtualList -is [System.Management.Automation.PSCustomObject])
        {
          $appItem | Add-Member -MemberType NoteProperty -Name "VirtualDiretoryPath" -Value ($virtualList | ConvertTo-Json) #add prop to list
        }
      }
    }
    
    $isSuccess = $true;
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{appList=$appList;isSuccess=$isSuccess;reason=$reason}
}

# New Server Open IIS
function Init-IIS
{
  Enable-WindowsOptionalFeature -FeatureName IIS-ASPNET45,IIS-HttpRedirect,IIS-RequestMonitor,IIS-URLAuthorization,IIS-IPSecurity,IIS-ApplicationInit,IIS-BasicAuthentication,IIS-ManagementService,IIS-WindowsAuthentication -Online -All -NoRestart
  $count = (Get-WindowsOptionalFeature -Online -FeatureName '*IIS*').Count
  New-Object -TypeName PSCustomObject -Property @{count=$count;}
}

function Remove-Pool()
{
  param (
    [string]$appPool
  )

  Import-Module WebAdministration;

  Remove-WebAppPool -Name $appPool
}


function Create-New-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [PSCustomObject]$bindList,
    [string]$netVersion, 
    [boolean]$enable32Bit, 
    [boolean]$classicPipelineMode
  )

  Import-Module WebAdministration;
  $isSuccess = $false
  $resultList = New-Object System.Collections.ArrayList
  $column1 = "action"
  $column2 = "isSuccess"
  $column3 = "message"
  
  [boolean]$pathExists=Test-Path $siteFolder;
  if ($pathExists -eq $False)
  {
      Write-Host "Creating Folder: $siteFolder";
      New-Item $siteFolder -type directory -Verbose;   
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
  New-Website -Name $siteName -ApplicationPool $appPool -ipAddress $ipAddress -HostHeader $hostHeader -PhysicalPath $siteFolder -Port $port  -Force -Verbose | Log-Action; # CREATE THE SITE
}

function Set-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [PSCustomObject]$bindList,
    [string]$netVersion, 
    [boolean]$enable32Bit, 
    [boolean]$classicPipelineMode,
    [bool]$isEnable
  )

  Import-Module WebAdministration

  $isSuccess = $false
  $resultList = New-Object System.Collections.ArrayList
  $column1 = "action"
  $column2 = "isSuccess"
  $column3 = "message"

  try
  {
    [boolean]$pathExists = Test-Path $siteFolder;
    $resultFolder = New-Object System.Object
    $resultFolder | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set Folder"
    if ($pathExists -eq $true)
    {
        Write-Host "Folder exits: $siteFolder";
        Set-ItemProperty "IIS:\Sites\$siteName" physicalPath $siteFolder -Verbose  
        $resultFolder | Add-Member -MemberType NoteProperty -Name $column2 -Value $true
    }
    else
    {
        $resultFolder | Add-Member -MemberType NoteProperty -Name $column2 -Value $false
        $resultFolder | Add-Member -MemberType NoteProperty -Name $column3 -Value "Folder not exits"
    }

    $resultList.Add($resultFolder)

    [boolean]$appPoolExists = Test-Path "IIS:\AppPools\$appPool";
    $resultappPool = New-Object System.Object
    $resultappPool | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set AppPool"
    if ($appPoolExists -eq $true)
    {
      Write-Host "AppPool exits: $appPool";
      Set-ItemProperty "IIS:\Sites\$siteName" applicationPool $appPool -Verbose
      $resultappPool | Add-Member -MemberType NoteProperty -Name $column2 -Value $true
    }
    else
    {
      $resultappPool | Add-Member -MemberType NoteProperty -Name $column2 -Value $false
      $resultappPool | Add-Member -MemberType NoteProperty -Name $column3 -Value "AppPool not exits"
    }

    $resultList.Add($resultappPool)

    #TODO CHECK CLR .NET VERSION
    $resultnetVersion = New-Object System.Object
    $resultnetVersion | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set CLR .NET"
    Set-ItemProperty "IIS:\Sites\$siteName" managedRuntimeVersion v$netVersion -Force -Verbose
    $resultnetVersion | Add-Member -MemberType NoteProperty -Name $column2 -Value $true
    $resultList.Add($resultnetVersion)

    $resultEnable32Bit = New-Object System.Object
    $resultEnable32Bit | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set 32 Bit"
    Set-ItemProperty "IIS:\Sites\$siteName" enable32BitAppOnWin64 $enable32Bit -Verbose
    $resultEnable32Bit | Add-Member -MemberType NoteProperty -Name $column2 -Value $true
    $resultList.Add($resultEnable32Bit)

    $resultPipelineMode = New-Object System.Object
    $resultPipelineMode | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set managedPipelineMode"
    Set-ItemProperty "IIS:\Sites\$siteName" managedPipelineMode $classicPipelineMode -Verbose
    $resultPipelineMode | Add-Member -MemberType NoteProperty -Name $column2 -Value $true
    $resultList.Add($resultPipelineMode)

    #Binding or remove all binding add new binding
    foreach ($bindItem in $bindList)
    {
      $fullInfo = "{0}:{1}:{2}" -f $bindItem.ipAddress, $bindItem.port, $bindItem.hostHeader

      if ($null -ne (Get-WebBinding | Where-Object {$_.bindinginformation -eq $fullInfo}))
      {
         Write-Host "Binding exits: $fullInfo";
      }
      else
      {
        Set-WebBinding -Name "IIS:\Sites\$siteName" -HostHeader $bindItem.hostHeader -BindingInformation $bindItem.ipAddress -PropertyName "Port" -Value $bindItem.$port
        $resultBinding = New-Object System.Object
        $resultBinding | Add-Member -MemberType NoteProperty -Name $column1 -Value "Set Binding"
      }
    }

    # $existBindingList = Get-WebBinding -Name $siteName | Select-Object bindingInformation
    # foreach ($exitItem in $existBindingList)
    # {
    #    $exitArray = $exitItem.bindingInformation.Split(":")
    #    $exitIP = $exitArray[0]
    #    $exitPort = $exitArray[1]
    #    $exitHeader = $exitArray[2]
    #    Get-WebBinding -Port $exitIP -Name $siteName | Remove-WebBinding
    # }

    if ($isEnable -eq $false)
    {
      Stop-WebSite -Name $siteName
    }

    $isSuccess = $true
  }
  catch
  {
     $isSuccess = $false
     $exceptionObj = New-Object System.Object
     $exceptionObj | Add-Member -MemberType NoteProperty -Name $column1 -Value "Exception"
     $exceptionObj | Add-Member -MemberType NoteProperty -Name $column2 -Value  $isSuccess
     $exceptionObj | Add-Member -MemberType NoteProperty -Name $column3 -Value  $_
     $resultList.Add($exceptionObj)
  }

  $resultJsonList = $resultList | ConvertTo-Json
  New-Object -TypeName PSCustomObject -Property @{resultList=$resultJsonList;isSuccess=$isSuccess}
}


function Remove-Site
{
  param(
    [string]$siteName
  )

  #Check Site Exists
  
  Remove-WebSite -Name $siteName
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

function Set-Application {
  param (
    [string]$appName,
    [string]$appFolder,
    [string]$appPool,
    [string]$siteName,
    [bool]$isAnonymous
  )

  #physicalPath
  Set-ItemProperty "IIS:\Sites\$siteName\$appName" -name physicalPath -value $appFolder

  #applicationPool
  Set-ItemProperty "IIS:\Sites\$siteName\$appName" -name applicationPool -value $appPool
  
  #Anonymous Authentication 
  $anonAuthFilter = "/system.WebServer/security/authentication/AnonymousAuthentication"
  $anonAuth = Get-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -location "IIS:\Sites\$website\$appName"
  if($anonAuth.Value -eq $isAnonymous)
  {
		Write-Host "$appName Anonymous Authentication is already $isAnonymous"
	}
  else 
  {
		Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $value -location "IIS:\Sites\$website\$appName"
		Write-Host "Anonymous Authentication now $value on $appName"
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

#CSharp CSHelper call Bridge test
# function CSharpBridgeTest {
#   Start-Sleep -Seconds 5
#   $jsonObject = "{output:{first:michael,last:chang},isSuccess:true,command:$command}";
#   return $jsonObject
# }

# $TestObj = CSharpBridgeTest;
# Write-Output $TestObj


function AppPoolMaintain ([PSCustomObject] $PSObject)
{
  $rtnObj = $null;

  $param = $PSObject.param;

  switch ($PSObject.action)
  {
      0 
      {
        $rtnObj =  invoke-command -session $PSObject.session -scriptblock ${function:Remove-Pool} -ArgumentList ($param.AppPool)
      }
      1 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-AppPool} -ArgumentList ($param.siteName,$param.appName)
      }
      2 
      { 
        #TODO Revise / Set?
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Get-AppPoolList}
      }
  }

  return $rtnObj;
}

function SiteMaintain ([PSCustomObject] $PSObject)
{
  $rtnObj = $null;

  $param = $PSObject.param;

  switch ($PSObject.action)
  {
      0 
      {
        $rtnObj =  invoke-command -session $PSObject.session -scriptblock ${function:Remove-Site} -ArgumentList ($param.siteName)
      }
      1 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Create-New-Site} -ArgumentList ($param.basePath,$param.siteName,$param.siteFolder,$param.hostHeader,$param.ipAddress,$param.port,$param.netVersion,$param.enable32Bit,$param.classicPipelineMode)
      }
      2 
      {
        $bindingList = $param.bindingList | ConvertFrom-Json
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-Site} -ArgumentList ($param.siteName,$param.siteFolder,$param.appPool,$bindingList,$param.netVersion,$param.enable32Bit,$param.classicPipelineMode,$param.isEnable)
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Get-Site-List}
      }
  }

  return $rtnObj;
}

function AppMaintain ([PSCustomObject] $PSObject)
{
  $rtnObj = $null;

  $param = $PSObject.param;

  switch ($PSObject.action)
  {
      0
      {
        $rtnObj =  invoke-command -session $PSObject.session -scriptblock ${function:Remove-Application} -ArgumentList ($param.appName,$param.$siteName)
      }
      1 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Create-New-Application} -ArgumentList ($param.appName,$param.appFolder,$param.appPool,$param.siteName)
      }
      2 
      { 
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-Application} -ArgumentList ($param.appName,$param.appFolder,$param.appPool,$param.siteName,$param.isAnonymous)
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Get-Application-List}
      }
  }

  return $rtnObj;
}

#test connect begin======================================================================================================
$eventPath = "output/{0}_{1}_{2}_{3}.json" -f $server,$command,$action,(Get-Date).ToString('yyyyMMddss')
$testConn = TestServerConnection($server)

if ($testConn -eq $false)
{
  $resultNOConnect = New-Object -TypeName PSCustomObject -Property @{isSuccess=$false;reason="$server not connect";} | ConvertTo-Json | Set-Content -Path $eventPath
  EXIT
}

$testSession = Set-Session

if ($testSession.isSuccess -eq $false)
{
  $resultNOSession = New-Object -TypeName PSCustomObject -Property @{isSuccess=$false;reason=$testSession.reason;} | ConvertTo-Json | Set-Content -Path $eventPath
  EXIT
}

#test connect end=======================================================================================================

$session = $testSession.session

if ($session)
{
    
  #create new object save params and action pass to local function
  $PSHash = @{
    server   = [string]$server
    action   = [int]$action
    param  = $param | ConvertFrom-Json
    session = $session
  }

  $PSObject = New-Object -TypeName PSObject -Property $PSHash
  
  $JsonObject = $null;
  
  switch ($command)
  {
      'AppPool'     { $JsonObject = AppPoolMaintain($PSObject) }
      'Site'        { $JsonObject = SiteMaintain($PSObject) }
      'Application' { $JsonObject = AppMaintain($PSObject) }
      default { $JsonObject = @{isSuccess=$false;reason="command $command not exist"}}
  }

  $RealJsonObject =  $JsonObject | ConvertTo-Json | Set-Content -Path $eventPath

  #Write-Host $RealJsonObject

  Remove-PSSession -Session $session

  EXIT
}