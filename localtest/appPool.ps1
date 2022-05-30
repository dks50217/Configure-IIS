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

  Write-Host $result
  Write-Host $reason
}


#Create-AppPool "michaelPool" "v4.0" "Integrated" "1" "1"
#Set-AppPool "michaelPool" "v4.0" "Integrated" "0" "0"
#Remove-Pool "michaelPool"