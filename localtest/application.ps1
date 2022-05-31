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
  $isPathExist = $false
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

    $isPathExist = Test-Path $appFolder

    if ($isAppExist -eq $false)
    { 
      $reason = $reason + "appFolder: [$appFolder] not exists,"
    }

    if ($isSiteExist -eq $true -and $isAppPoolExist -eq $true -and $isAppExist -eq $false -and $isPathExist -eq $true) 
    {
      New-Item "IIS:\Sites\$siteName\$appName" -type Application -physicalpath $appFolder -ApplicationPool $appPool
      $anonAuthFilter = "/system.WebServer/security/authentication/AnonymousAuthentication"
      Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $isAnonymous -location "IIS:\Sites\$website\$appName"
      $isSuccess = $true
    }
    else
    {
      $reason = "can not create app:[$appName]," +  $reason;
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
    [string]$anonymous,
    [string]$formsAuth
  )

  $isSuccess = $false
  $isSiteExist = $false
  $isAppExist = $false
  $isAppPoolExist = $false
  $isPathExist = $false
  $isAnonymous = $false
  $isFormsAuth = $false
  $reason = "";

  try
  {
    Import-Module WebAdministration

    if ($anonymous -eq "1" ) {$isAnonymous = $true};
    if ($formsAuth -eq "1" ) {$isFormsAuth = $true};

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

    $isPathExist = Test-Path $appFolder

    if ($isPathExist -eq $false)
    { 
      $reason = $reason + "appFolder: [$appFolder] not exists,"
    }

    if ($isSiteExist -eq $true -and $isAppPoolExist -eq $true -and $isAppExist -eq $true -and $isPathExist -eq $true) 
    {
      Set-ItemProperty "IIS:\Sites\$siteName\$appName" applicationPool $appPool
      Set-ItemProperty "IIS:\Sites\$siteName\$appName" physicalPath $appFolder
      $anonAuthFilter = "/system.WebServer/security/authentication/AnonymousAuthentication"
      Set-WebConfigurationProperty -filter $anonAuthFilter -name Enabled -value $isAnonymous -location "IIS:\Sites\$website\$appName"
      Set-WebConfiguration "system.web/authentication" Enabled -value $isFormsAuth
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

#$dicJsonList = "[{'name':'test12','path':'D:\\Demo_Web\\RASA'},{'name':'test22','path':'D:\\Demo_Web\\markdown'}]"
#$dicJsonList = "[]"
#Set-WebVirtualDirectory "Default Web Site" "testapp" $dicJsonList

#Create-New-Application "Default Web Site" "testapp2" "D:\Demo_Web\cardSample" "michaelPool" "1"
Set-Application "Default Web Site" "testapp" "D:\Demo_Web\Chartjs" "CRM_EXCEL" "1" "1"

#Remove-Application "Default Web Site" "testapp2"

