# Configure-IIS

use powershell cmdlets to configure IIS configuration settings

# How to use

1. set variable in config.ini

    ```ini
    user={user_name}
    password={user_password}
    server={server}
    command={command}
    action={action}
    ``` 

2. call test.bat execute a PowerShell script

or running PowerShell.exe inside command prompt

```bat
powershell.exe -noexit .\Remote-IIS.ps1 -user {user} -password {password} -server {server} -command {command} -action {action}
```

# Show all functions

```bat
powershell.exe -noexit .\allFunction.ps1
```

# Test

## Remote


## Local

```bat
cd localtest
powershell -command "& { .\application.ps1;{function} {site} {app} {path} {pool} {anonymous}}"
```

# Command

..Command Table

# Sample

..Sample






