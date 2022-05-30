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

.PARAMETER param
  params
  EX: Json Format like {"siteName": "","appName":""}
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

# ConvertTo-Json -Depth Dic
[hashtable]$depthDictionary = [ordered]@{
  AppPool3 = 4;
  Site3 = 5;
  Application3 = 3;
}

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

function Get-AppPoolList
{
    
  $isSuccess = $false;
  $reason = "";
  $booleanOptions = {'N','Y'}
   
  Try 
  {
      
      Import-Module WebAdministration;
      
      $appPoolList = Get-ChildItem -Path IIS:\AppPools\  | Select-Object name, state, managedRuntimeVersion, managedPipelineMode,AutoStart,StartMode,Enable32BitAppOnWin64;
      
      #Get numberOfApplications
      foreach ($poolItem in $appPoolList)
      {
        $appPool = $poolItem.name;
        $numberOfApplications = (Get-WebConfigurationProperty "/system.applicationHost/sites/site/application[@applicationPool='$appPool']" "machine/webroot/apphost" -name path).Count
        $poolItem | Add-Member -MemberType NoteProperty -Name "appCount" -Value $numberOfApplications
      }

      #Get managedRuntimeVersion select option
      $runtimeOptions = $appPoolList | Group-Object -Property managedRuntimeVersion -NoElement | Select-Object @{l='label';e='Name'},@{l='value';e='Name'};

      #Get managedPipelineMode select option
      $pipelineOptions = $appPoolList | Group-Object -Property managedPipelineMode -NoElement | Select-Object @{l='label';e='Name'},@{l='value';e='Name'};

      #Get AutoStart select option
      $booleanOptions = @( @{ label="Y"; value="1";}, @{ label="N"; value="0"; } )

      $options = @{
        runtime = $runtimeOptions
        pipeline = $pipelineOptions
        boolean = $booleanOptions
      }

      $isSuccess = $true;
  }
  Catch 
  {
    Write-Host "An error occurred:";
    $reason = $_;
  }
  
  New-Object -TypeName PSCustomObject -Property @{appPoolList=$appPoolList;options=$options;isSuccess=$isSuccess;reason=$reason};
}

function Get-Site-List
{
  $isSuccess = $false
  $reason = "";

  try 
  {
    Import-Module WebAdministration; 
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

  $isSuccess = $false
  $reason = "";

  try 
  {
    Import-Module WebAdministration;
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
          $appItem | Add-Member -MemberType NoteProperty -Name "VirtualDiretoryPath" -Value $virtualList
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

function Remove-Pool
{
  param (
    [string]$appPool
  )

  $isSuccess = $false
  $reason = "";

  try 
  {
    Import-Module WebAdministration;
    $existAppCount = (Get-WebConfigurationProperty "/system.applicationHost/sites/site/application[@applicationPool='$appPool']" "machine/webroot/apphost" -name path).Count
    
    if ($existAppCount -eq 0)
    {
      $result = Remove-WebAppPool -Name $appPool
      $isSuccess = $true
    }
    else
    {
      $reason = "app exists count: $existAppCount , can't remove appPool"
    }
  }
  catch 
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

#get-website | Select-Object id,name,state,applicationPool,physicalPath,bindings,enabledProtocols,serverAutoStart
function Create-New-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [string]$autoStart,
    [string]$preload
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isFolderExist = $false
  $isAutoStart = $false
  $isPreLoad = $false
  $isAppPoolExist = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration;
    
    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";
    $isSiteExist = Test-Path "IIS:\AppPools\$siteName";
    $isFolderExist = Test-Path $siteFolder;

    if ($isAppPoolExist -eq $false)
    {
       $reason = $reason + "appPool: [$appPool] is not exist,"
    }

    if ($isSiteExist -eq $true)
    {
       $reason = $reason + "site: [$siteName] is exist,"
    }

    if ($isFolderExist -eq $false)
    {
      $reason = $reason + "siteFolder: [$siteFolder] is not exist,"
    }

    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($preload -eq "1" ) {$isPreLoad = $true};

    $readyCreate = ($isSiteExist -eq $false) -and ($isFolderExist -eq $true) -and ($isAppPoolExist -eq $true)

    if ($readyCreate)
    {
      $result = New-Website -Name $siteName -ApplicationPool $appPool -PhysicalPath $siteFolder
      Set-ItemProperty "IIS:\Sites\$siteName" serverAutoStart $isAutoStart
      Set-ItemProperty "IIS:\Sites\$siteName" applicationDefaults.preloadEnabled $isPreLoad
      $isSuccess = $true;
    }
    else
    {
      $reason = "create site: [$siteName] fail," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    Write-Host $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-WebBinding
{
  param(
    [string]$siteName,
    [string]$bindingJsonList
  )

  $isSuccess = $false;
  $reason = "";
  $result = New-Object -TypeName 'System.Collections.ArrayList';

  try
  {
    #Convert To PSObject
    $bindingList = $bindingJsonList | ConvertFrom-Json
     
    #Remove all
    $orgBindingList = Get-WebBinding $siteName |Select-Object -ExpandProperty bindingInformation

    foreach ($item in $orgBindingList)
    {
      $orgIP = $item.split(':')[0];
      Get-WebBinding -Port $orgIP -Name $siteName | Remove-WebBinding;
    }
    
    #Create all  
    foreach ($item in $bindingList)
    {
      $bindObject = [PSCustomObject]@{
        ip =$item.ip
        port = $item.port
        header = $item.header
      };
      New-WebBinding -Name $siteName -IPAddress $item.ip -Port $item.port -HostHeader $item.header  
      $result.Add($bindObject);
    }

    $isSuccess = $true;
  }
  catch
  {
    Write-Host "An error occurred:"
    Write-Host $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-Site
{
  param(
    [string]$siteName, 
    [string]$siteFolder,
    [string]$appPool,
    [string]$autoStart,
    [string]$preload
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isFolderExist = $false
  $isAutoStart = $false
  $isPreLoad = $false
  $isAppPoolExist = $false
  $reason = "";

  try
  {
     Import-Module WebAdministration

     $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";
     $isSiteExist = Test-Path "IIS:\Sites\$siteName";
     $isFolderExist = Test-Path $siteFolder;

    if ($isAppPoolExist -eq $false)
    {
       $reason = $reason + "appPool: [$appPool] is not exist,"
    }

    if ($isSiteExist -eq $false)
    {
       $reason = $reason + "site: [$siteName] is not exist,"
    }

    if ($isFolderExist -eq $false)
    {
      $reason = $reason + "siteFolder: [$siteFolder] is not exist,"
    }

    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($preload -eq "1" ) {$isPreLoad = $true};

    $readySet = ($isSiteExist -eq $true) -and ($isFolderExist -eq $true) -and ($isAppPoolExist -eq $true)
    
    if ($readySet)
    {
      Set-ItemProperty "IIS:\Sites\$siteName" ApplicationPool $appPool
      Set-ItemProperty "IIS:\Sites\$siteName" PhysicalPath $siteFolder
      Set-ItemProperty "IIS:\Sites\$siteName" serverAutoStart $isAutoStart
      Set-ItemProperty "IIS:\Sites\$siteName" applicationDefaults.preloadEnabled $isPreLoad
      $isSuccess = $true;
    }
    else
    {
      $reason = "set site: [$siteName] fail," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-WebVirtualDirectory 
{
    param (
      [string]$siteName,
      [string]$appName,
      [string]$dicJsonList
    )
  
    $isSuccess = $false
    $isSiteExist = $false
    $isAppExist = $false
    $isReadyCreate = $false;
    $result = New-Object -TypeName 'System.Collections.ArrayList';
  
    try
    {
      Import-Module WebAdministration
      $isSiteExist = Test-Path "IIS:\Sites\$siteName";
      $isAppExist = Test-Path "IIS:\Sites\$siteName\$appName";
  
       #Covert To PS Object
      $dicList = $dicJsonList | ConvertFrom-Json
  
      if ($isSiteExist -eq $false)
      {
        $reason = $reason + "site: [$siteName] not exists,"
      }
  
      if ($isAppExist -eq $false)
      {
        $reason = $reason + "app: [$appName] not exists,"
      }
  
      $isReadyCreate  = (($isSiteExist -eq $true) -and ($isAppExist -eq $true))
  
      # Remove all
      if ($isReadyCreate)
      {
        # Remove all
        $orgDCList = Get-WebVirtualDirectory -Site $siteName -Application $appName | Select-Object path,physicalPath
  
        foreach ($item in $orgDCList)
        {
          $dicPath = $item.path;
          Remove-Item "IIS:\Sites\$siteName\$appName\$dicPath" -Force -Recurse
          
          $vdRemoveObject = [PSCustomObject]@{
            success = $true
            type = 'remove'
            name = $item.name
            path = $item.path
          }

          $result.Add($vdRemoveObject)
        }
  
        # Create all
        foreach ($item in $dicList)
        {
            $isPathExist = Test-Path $item.path;
    
            $vdAddObject = [PSCustomObject]@{
              success = ''
              type = 'add'
              name = $item.name
              path = $item.path
            }
    
            if ($isPathExist)
            {
              New-WebVirtualDirectory -Site $siteName -Application $appName -Name $item.name -PhysicalPath $item.path
              $vdAddObject.success = $true;
            }
            else
            {
              $vdAddObject.success = $false;
            }
  
            $result.Add($vdAddObject)
        }
      }

      $isSuccess = $true;
    }
    catch
    {
      Write-Host "An error occurred:"
      $reason = $_
    }
  
    New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}


function Remove-Site
{
  param(
    [string]$siteName
  )

  $isSuccess = $false
  $isSiteExist = $false
  $existAppCount = 0
  $reason = "";

  try
  {
    Import-Module WebAdministration

    #Check Site Exists
    $isSiteExist = Test-Path "IIS:\Sites\$siteName"

    if ($isSiteExist -eq $false)
    {
      $reason = $reason + "site: [$siteName] not exists,"
    }

    if ($isSiteExist)
    {
        #Check Application Exists
        $existAppCount = (Get-ChildItem "IIS:\Sites\$siteName").count;
    }

    if ($existAppCount -gt 1)
    {
       $reason = $reason + "can't remove site: [$siteName], because app exists, count : [$existAppCount],"
    }

    $readyRemove = ($isSiteExist -eq $true) -and ($existAppCount -eq 1)

    if ($readyRemove)
    {
      $result = Remove-WebSite -Name $siteName
      $isSuccess = $true
    }
    else
    {
      $reason = "can't remove site: [$siteName]," + $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}


function Create-New-Application
{
  param(
    [string]$siteName,
    [string]$appName,
    [string]$appFolder,
    [string]$appPool,
    [string]$anonymous
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isAppExist = $false
  $isAppPoolExist = $false
  $isAnonymous = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration

    if ($anonymous -eq "1" ) {$isAnonymous = $true};

    #check site exists
    $isSiteExist = Test-Path "IIS:\Sites\$siteName"

    if ( $isSiteExist -eq $false)
    {
      $reason = $reason + "site: [$siteName] not exists,"
    }

    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";

    if ($isAppPoolExist -eq $false)
    {
      $reason = $reason + "AppPool: [$appPool] not exists,"
    }

    $isAppExist = Test-Path "IIS:\Sites\$siteName\$appName";

    if ($isAppExist -eq $true)
    { 
      $reason = $reason + "app: [$appName] already exists,"
    }

    if ($isSiteExist -eq $true -and $isAppPoolExist -eq $true -and $isAppExist -eq $false) 
    {
      New-Item "IIS:\Sites\$siteName\$appName" -type Application -physicalpath $appFolder -ApplicationPool $appPool
      $anonAuthFilter = "/system.WebServer/security/authentication/AnonymousAuthentication"
      Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $isAnonymous -location "IIS:\Sites\$website\$appName"
      $isSuccess = $true
    }
    else
    {
      $reason = "can not create app:[[$appName]," +  $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-Application 
{
  param (
    [string]$siteName,
    [string]$appName,
    [string]$appFolder,
    [string]$appPool,
    [string]$anonymous
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isAppExist = $false
  $isAppPoolExist = $false
  $isAnonymous = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration

    if ($anonymous -eq "1" ) {$isAnonymous = $true};

    $isSiteExist = Test-Path "IIS:\Sites\$siteName"

    if ($isSiteExist -eq $false)
    {
      $reason = $reason + "site: [$siteName] not exists,"
    }

    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool";

    if ($isAppPoolExist -eq $false)
    {
      $reason = $reason + "AppPool: [$appPool] not exists,"
    }

    $isAppExist = Test-Path "IIS:\Sites\$siteName\$appName";

    if ($isAppExist -eq $false)
    { 
      $reason = $reason + "app: [$appName] not exists,"
    }

    if ($isSiteExist -eq $true -and $isAppPoolExist -eq $true -and $isAppExist -eq $true) 
    {
      Set-ItemProperty "IIS:\Sites\$siteName\$appName" applicationPool $appPool
      Set-ItemProperty "IIS:\Sites\$siteName\$appName" physicalPath $appFolder
      $anonAuthFilter = "/system.WebServer/security/authentication/AnonymousAuthentication"
      Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $isAnonymous -location "IIS:\Sites\$website\$appName"
      $isSuccess = $true
    }
    else
    {
      $reason = "can not set app:[$appName]," +  $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}



function Remove-Application 
{ 	
  param(
    [string]$siteName,
    [string]$appName
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isAppExist = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration

    $isSiteExist = Test-Path "IIS:\Sites\$siteName"

    if ($isSiteExist -eq $false)
    {
      $reason = $reason + "site: [$siteName] not exists,"
    }

    $isAppExist = Test-Path "IIS:\Sites\$siteName\$appName";

    if ($isAppExist -eq $false)
    { 
      $reason = $reason + "app: [$appName] not exists,"
    }

    if ($isSiteExist -eq $true -and $isAppExist -eq $true) 
    {
      Remove-Item "IIS:\Sites\$siteName\$appName" -recurse
      $isSuccess = $true
    }
    else
    {
      $reason = "can not set app:[$appName]," +  $reason;
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
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

function Create-AppPool
{
  param(
    [string]$appPool,
    [string]$netVersion,
    [string]$managedpipelinemode,
    [string]$autoStart,
    [string]$enable32
  )

  $isSuccess = $false
  $isAppPoolExist = $true
  $isAutoStart = $false
  $isEnable32BitApp = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration;

    #check appPool exist
    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool"
    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($enable32 -eq "1" ) {$isEnable32BitApp = $true};
    
    if ($isAppPoolExist -eq $false)
    {
       New-WebAppPool -Name $appPool
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" managedRuntimeVersion $netVersion
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" managedpipelinemode $managedpipelinemode
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" autoStart $isAutoStart
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" enable32BitAppOnWin64 $isEnable32BitApp
       $result = Get-ChildItem -Path "IIS:\AppPools\$appPool" | Select-Object name, state, managedRuntimeVersion, managedPipelineMode,AutoStart,StartMode,Enable32BitAppOnWin64
       $isSuccess = $true
    }
    else
    {
      $reason = "can not create appPool, because appPool : [$appPool] is exists"
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
}

function Set-AppPool
{
  param(
    [string]$appPool,
    [string]$netVersion,
    [string]$managedpipelinemode,
    [string]$autoStart,
    [string]$enable32
  )

  $isSuccess = $false
  $isAppPoolExist = $false
  $isEnable32BitApp = $false
  $isAutoStart = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration;

    #Check appPool exists
    $isAppPoolExist = Test-Path "IIS:\AppPools\$appPool"
    if ($autoStart -eq "1" ) {$isAutoStart = $true};
    if ($enable32 -eq "1" ) {$isEnable32BitApp = $true};

    if ($isAppPoolExist -eq $true)
    {
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" managedRuntimeVersion $netVersion
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" managedpipelinemode $managedpipelinemode
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" autoStart $isAutoStart
       Set-ItemProperty -Path "IIS:\AppPools\$appPool" enable32BitAppOnWin64 $isEnable32BitApp
       $result = Get-ChildItem -Path "IIS:\AppPools\$appPool" | Select-Object name, state, managedRuntimeVersion, managedPipelineMode,AutoStart,StartMode,Enable32BitAppOnWin64
       $isSuccess = $true
    }
    else
    {
      $reason = "can not set appPool, because appPool : [$appPool] is not exists"
    }
  }
  catch
  {
    Write-Host "An error occurred:"
    $reason = $_
  }

  New-Object -TypeName PSCustomObject -Property @{result=$result;isSuccess=$isSuccess;reason=$reason}
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
        $rtnObj =  invoke-command -session $PSObject.session -scriptblock ${function:Remove-Pool} -ArgumentList ($param.appPool)
      }
      1 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Create-AppPool} -ArgumentList ($param.appPool,$param.netVersion,$param.managedpipelinemode,$param.autoStart,$param.enable32)
      }
      2 
      { 
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-AppPool} -ArgumentList ($param.appPool,$param.netVersion,$param.managedpipelinemode,$param.autoStart,$param.enable32)
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${functionGet-AppPoolList}
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
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Create-New-Site} -ArgumentList ($param.siteName,$param.siteFolder,$param.appPool,$param.autoStart,$param.preload)
      }
      2 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-Site} -ArgumentList ($param.siteName,$param.siteFolder,$param.appPool,$param.autoStart,$param.preload)
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Get-Site-List}
      }
      4 #Set Web Bind
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-WebBinding} -ArgumentList ($param.siteName,$param.bindingList)
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
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Remove-Application} -ArgumentList ($param.siteName, $param.appName)
      }
      1 
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Create-New-Application} -ArgumentList ($param.siteName,$param.appName,$param.appFolder,$param.appPool,$param.anonymous)
      }
      2 
      { 
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-Application} -ArgumentList ($param.siteName,$param.appName,$param.appFolder,$param.appPool,$param.anonymous)
      }
      3 #Get List
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Get-Application-List}
      }
      4 #Set WebVirtualDirectory
      {
        $rtnObj = invoke-command -session $PSObject.session -scriptblock ${function:Set-WebVirtualDirectory} -ArgumentList ($param.siteName, $param.appName, $param.dicList)
      }
  }

  return $rtnObj;
}

#test connect begin======================================================================================================
$eventPath = "output/{0}_{1}_{2}_{3}.json" -f $server,$command,$action,(Get-Date).ToString('yyyyMMddhhmmss')
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

  # Get ConvertJson level
  [int]$jsonDepth = 2;
  [string]$searchKey = "$command$action";
  $foundKeys = $depthDictionary.Keys | % { if($_.contains($searchKey)){$_}}

  if ($foundKeys)
  {
    $jsonDepth = $depthDictionary["$command$action"];
  }

  $RealJsonObject =  $JsonObject | ConvertTo-Json -Depth $jsonDepth | Set-Content -Encoding utf8 -Path $eventPath

  #Write-Host $RealJsonObject

  Remove-PSSession -Session $session

  EXIT
}