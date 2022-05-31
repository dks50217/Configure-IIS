# Configure-IIS

use powershell cmdlets to configure IIS configuration settings

# How to use

1. set variable in config.ini

    ```ini
    user={user_name}
    password={user_password}
    server={server}
    command={command}
    action={action} # 1/2/3/4 reference below action table
    param={param} #escape strings in JSON like '{"\"appPool"\":"\"michaeltestpool"\"}'
    ``` 

2. call test.bat execute a PowerShell script

or running PowerShell.exe inside command prompt

```bat
powershell.exe -noexit .\Remote-IIS.ps1 -user {user} -password {password} -server {server} -command {command} -action {action} -param {param}
```

# Show all functions

```bat
powershell.exe -noexit .\allFunction.ps1
```

# Action

<table border="1">
  <tr>
    <td align="center">Action/Command</td>
    <td align="center">AppPool</td>
    <td align="center">Site</td>
    <td align="center">Application</td>
  </tr>
  <tr>
    <td colspan="1">0</td>
    <td colspan="3" align="center">Remove</td>
  </tr>
  <tr>
    <td colspan="1">1</td>
    <td colspan="3" align="center">Add</td>
  </tr>
  <tr>
    <td colspan="1">2</td>
    <td colspan="3" align="center">Set</td>
  </tr>
    <tr>
    <td colspan="1">3</td>
    <td colspan="3" align="center">List</td>
  </tr>
  </tr>
    <tr>
    <td colspan="1">4</td>
    <td></td>
    <td>Web Bind</td>
    <td>VirtualDirectory</td>
  </tr>
</table>

# Test

## Local

```bat
cd localtest
powershell -ExecutionPolicy unrestricted -command "& { . .\application.ps1; Create-New-Application 'Default Web Site' 'testapp' 'D:\Demo_Web\Sample' 'demoPool' '1' }"
```

# Command

..Command Table

# Sample

..Sample






