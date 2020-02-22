# vscode-language-aggressor

This is a Visual Studio Code (VSC) extension that aims to provide:

* An implement of the Sleep and Cobalt Strike (CS) Aggressor grammar; and
* The definition of Cobalt Strike functions' prototype

Please note, that everything is based on the documentation provided by [Raphael Mudge](https://www.linkedin.com/in/rsmudge]):

* Official sleep documentation: http://sleep.dashnine.org/manual/
* Official Cobalt Strike Aggressor documentation: https://www.cobaltstrike.com/aggressor-script/index.html

## Features

This extensions offers a series of snippets for helping in building a Cobalt Strike Agressor scripts. The extension is based on the Cobalt Strike 4.0 aggresor script feature set. It also provide automatic closing of element tags for the filter fields.

## Snippets

| Name     | Description     |
|----------|-----------------|
|heartbeat_1m | Fired every minute |
|h3 | Prints a sub-sub-title heading. |
|ssh_tasked | Fired when a task acknowledgement is posted to an SSH console. |
|openScriptConsole | Open the Aggressor Script console |
|listener_delete | Stop and remove a listener |
|sendmail_done | Fired when a phishing campaign completes |
|pref_set | Set a value in Cobalt Strike's preferences |
|event_newsite | Fired when a new site message is posted to the event log. |
|bsetenv | Ask Beacon to set an environment variable |
|listener_describe | Describe a listener. |
|sites | Returns a list of sites tied to Cobalt Strike's web server. |
|agServices | Pull information from the services model |
|beacon_command_describe | Describe a Beacon command |
|openWindowsExecutableStage | Open the dialog to generate a stageless Windows executable |
|elog | Publish a notification to the event log |
|EXECUTABLE_ARTIFACT_GENERATOR | Control the EXE and DLL generation for Cobalt Strike |
|beacon_remote_exec_method_describe | Describe a Beacon remote execute method |
|prompt_file_save | Show a file save dialog. |
|agTokens | Pull information from the phishing tokens model. |
|bdata | Get metadata for a Beacon session |
|POWERSHELL_COMPRESS | A hook used by the resource kit to compress a PowerShell script. The default uses gzip and returns a deflator script. |
|openBeaconBrowser | Open the beacon browser tab |
|bcd | Ask a Beacon to change it's current working directory |
|artifact_payload | Generates a stageless payload artifact (exe, dll) from a Cobalt Strike listener name |
|binject | Ask Beacon to inject a session into a specific process |
|beacon_exploit_register | Register a Beacon privilege escalation exploit with Cobalt Strike. This adds an option to the elevate command |
|PSEXEC_SERVICE | Set the service name used by jump psexec|psexec64|psexec_psh and psexec. |
|-isadmin | Check if a session has admin rights |
|bspawn | Ask Beacon to spawn a new session |
|openWindowsExecutableDialog | Open the dialog to generate a Windows executable |
|downloads | Returns a list of downloads in Cobalt Strike's data model |
|bookmark | Define a bookmark [PDF document only] |
|agApplications | Pull information from the applications model. |
|removeTab | Close the active tab |
|bspawnto | Change the default program Beacon spawns to inject capabilities into |
|bscreenshot | Ask Beacon to take a screenshot |
|keystrokes | Returns a list of keystrokes from Cobalt Strike's data model |
|openPayloadHelper |  Open a payload chooser dialog. |
|p | Prints a paragraph of text. |
|beacon_initial_empty | Fired when a DNS Beacon calls home for the first time. At this point, no metadata has been exchanged. |
|openFileBrowser | Open the file browser for a Beacon |
|brm | Ask Beacon to remove a file or folder |
|berror | Publish an error message to the Beacon transcript |
|blogonpasswords | Ask Beacon to dump in-memory credentials with mimikatz |
|bdllspawn | Spawn a Reflective DLL as a Beacon post-exploitation job |
|listener_create_ext | Create a new listener |
|bpwd | Ask Beacon to print its current working directory |
|targets | Returns a list of host information in Cobalt Strike's data model. |
|web_hit | Fired when there's a new hit on Cobalt Strike's web server. |
|openCloneSiteDialog | Open the dialog for the website clone tool |
|brunu | Ask Beacon to run a process under another process. |
|pivots | Returns a list of SOCKS pivots from Cobalt Strike's data model |
|openBeaconConsole | Open the console to interact with a Beacon |
|bkeylogger | Injects a keystroke logger into a process. |
|say | Post a public chat message to the event log. |
|bexecute | Ask Beacon to execute a command [without a shell]. This provides no output to the user |
|ssh_indicator |  |
|openSOCKSSetup | open the SOCKS proxy server setup dialog |
|bpause | Ask Beacon to pause its execution. This is a one-off sleep. |
|beacon_initial | Fired when a Beacon calls home for the first time. |
|sendmail_post | Fired after a phish is sent to an email address. |
|bgetuid | Ask Beacon to print the User ID of the current token |
|p_formatted | Prints a paragraph of text with some format preservation. |
|menubar | Add a top-level item to the menubar |
|openMakeTokenDialog | open a dialog to help generate an access token |
|dialog_description | Adds a description to a &dialog |
|bspawnas | Ask Beacon to spawn a session as another user |
|iprange | Generate an array of IPv4 addresses based on a string description |
|HTMLAPP_EXE | Controls the content of the HTML Application User-driven (EXE Output) generated by Cobalt Strike |
|beacon_ids | Get the ID of all Beacons calling back to this Cobalt Strike team server |
|barch | Returns the architecture of your Beacon session (e.g., x86 or x64) |
|prompt_confirm | Show a dialog with Yes/No buttons. If the user presses yes, call the specified function. |
|bkerberos_ccache_use | Ask beacon to inject a UNIX kerberos ccache file into the user's kerberos tray |
|str_encode | Convert text to byte string with the specified character encoding. |
|bjump | Ask Beacon to spawn a session on a remote target |
|openCovertVPNSetup | open the Covert VPN setup dialog |
|agC2info | Pull information from the c2info model. |
|gunzip | Decompress a string (GZIP). |
|bhashdump | Ask Beacon to dump local account password hashes |
|POWERSHELL_DOWNLOAD_CRADLE | Change the form of the PowerShell download cradle used in Cobalt Strike's post-ex automation. This includes jump winrm|winrm64, [host] -> Access -> One Liner, and powershell-import. |
|sync_download | Sync a downloaded file (View -> Downloads) to a local path. |
|binfo | Get information from a Beacon session's metadata |
|drow_text | Adds a text field row to a &dialog |
|binjectsh | Inject shellcode into a process |
|dbutton_help | Adds a Help button to a &dialog. When this button is pressed, Cobalt Strike will open the user's browser to the specified URL |
|bppid | Set a parent process for Beacon's child processes |
|-isssh | Check if a session is an SSH session or not. |
|show_error | Shows an error message to the user in a dialog box. Use this function to relay error information. |
|action | Post a public action message to the event log. This is similar to the /me command. |
|beacon_remote_exploit_arch | Get the arch info for this Beacon lateral movement option |
|screenshots | Returns a list of screenshots from Cobalt Strike's data model |
|bmode | Change the data channel for a DNS Beacon |
|showVisualization | Switch Cobalt Strike visualization to a registered visualization. |
|bsocks_stop | Stop SOCKS proxy servers associated with the specified Beacon |
|openPowerShellWebDialog | Open the dialog to setup the PowerShell Web Delivery Attack |
|describe | Set a description for a report. |
|drow_file | Adds a file chooser row to a &dialog |
|localip | Get the IP address associated with the team server. |
|if elsif | if elsif statement |
|listeners | Return a list of listener names (with stagers only!) across all team servers this client is connected to |
|ssh_command_detail | Get the help information for an SSH command. |
|blog2 | Publishes an output message to the Beacon transcript. This function has an alternate format from &blog |
|bpowerpick | Spawn a process, inject Unmanaged PowerShell, and run the specified command |
|attack_name | Maps a MITRE ATT&CK tactic ID to its short name. |
|brportfwd_stop | Ask Beacon to stop a reverse port forward |
|artifact_sign | Sign an EXE or DLL file |
|pref_get | Grabs a string value from Cobalt Strike's preferences |
|dialog | Create a dialog. Use &dialog_show to show it. |
|credentials | Returns a list of application credentials in Cobalt Strike's data model |
|bargue_add | This function adds an option to Beacon's list of commands to spoof arguments for. |
|bssh_key | Ask Beacon to spawn an SSH session |
|brunas | Ask Beacon to run a command as another user |
|beacon_elevator_describe | Describe a Beacon command elevator exploit |
|bremote_exec | Ask Beacon to run a command on a remote target |
|table | Prints a table |
|heartbeat_30s | Fired every thirty seconds |
|nobreak | Group report elements together without a line break. |
|event_private | Fired when a private message is posted to the event log. |
|host_info | Get information about a target |
|SIGNED_APPLET_MAINCLASS | Specify the MAIN class of the Java Signed Applet Attack. |
|openHTMLApplicationDialog | Open the HTML Application Dialog. |
|bsudo | Ask Beacon to run a command via sudo (SSH sessions only) |
|bargue_remove | This function removes an option to Beacon's list of commands to spoof arguments for. |
|bspawnu | Ask Beacon to spawn a session under another process. |
|stager_bind_pipe | Returns a bind_pipe stager for a specific Cobalt Strike listener. This stager is suitable for use in lateral movement actions that benefit from a small named pipe stager. Stage with &beacon_stage_pipe. |
|insert_component | Add a javax.swing.JComponent object to the menu tree |
|bpsexec_command | Ask Beacon to run a command on a remote host. This function creates a service on the remote host, starts it, and cleans it up |
|beacons | Fired when the team server sends over fresh information on all of our Beacons. This occurs about once each second. |
|bconnect | Ask Beacon (or SSH session) to connect to a Beacon peer over a TCP socket |
|brun | Ask Beacon to run a command |
|sendmail_pre | Fired before a phish is sent to an email address. |
|add_to_clipboard | Add text to the clipboard, notify the user |
|heartbeat_15m | Fired every fifteen minutes |
|-isactive | Check if a session is active or not. A session is considered active if (a) it has not acknowledged an exit message AND (b) it is not disconnected from a parent Beacon. |
|bdesktop | Start a VNC session |
|-is64 | Check if a session is on an x64 system or not (Beacon only). |
|SMART_APPLET_MAINCLASS | Specify the MAIN class of the Java Smart Applet Attack. |
|beacon_exploit_describe | Describe a Beacon exploit |
|openSiteManager | Open the site manager |
|event_quit | Fired when someone disconnects from the team server. |
|POWERSHELL_COMMAND | Change the form of the powershell comamnd run by Cobalt Strike's automation. This affects jump psexec_psh, powershell, and [host] -> Access -> One-liner. |
|beacon_command_register | Register help information for a Beacon command |
|str_xor | Walk a string and XOR it with the provided key. |
|beacon_remove | Remove a Beacon from the display |
|listener_info | Get information about a listener |
|format_size | Formats a number into a size (e.g., 1024 => 1kb) |
|bps | Task a Beacon to list processes |
|openServiceBrowser | Open service browser dialog |
|resetData | Reset Cobalt Strike's data model |
|prompt_text | Show a dialog that asks the user for text. |
|drow_checkbox | Adds a checkbox to a &dialog |
|insert_menu | Bring menus associated with a popup hook into the current menu tree. |
|btimestomp | Ask Beacon to change the file modified/accessed/created times to match another file |
|openConnectDialog | Open the connect dialog |
|openBypassUACDialog | Open the dialog for the Bypass UAC feature. |
|nextTab | Activate the tab that is to the right of the current tab |
|beacon_execute_job | Run a command and report its output to the user |
|stager_bind_tcp | Returns a bind_tcp stager for a specific Cobalt Strike listener. This stager is suitable for use in localhost-only actions that require a small stager. Stage with &beacon_stage_tcp. |
|beacon_exploits | Get a list of privilege escalation exploits registered with Cobalt Strike |
|str_chunk | Chunk a string into multiple parts |
|heartbeat_60m | Fired every sixty minutes |
|bpowershell_import_clear | Clear the imported PowerShell script from a Beacon session |
|beacon_elevator_register | Register a Beacon command elevator with Cobalt Strike. This adds an option to the runasadmin command |
|on | Register an event handler. This is an alternate to the on keyword |
|event_action | Fired when a user performs an action in the event log. This is similar to an action on IRC (the /me command) |
|openPreferencesDialog | Open the preferences dialog |
|bdcsync | Use mimikatz's dcsync command to pull a user's password hash from a domain controller |
|event_nouser | Fired when the current Cobalt Strike client tries to interact with a user who is not connected to the team server. |
|bkerberos_ticket_use | Ask beacon to inject a mimikatz kirbi file into the user's kerberos tray |
|beacon_indicator | Fired when an indicator of compromise notice is posted to a Beacon's console. |
|openKeystrokeBrowser | Open the keystroke browser tab |
|bmimikatz | Ask Beacon to run a mimikatz command |
|services | Returns a list of services in Cobalt Strike's data model. |
|belevate_command | Ask Beacon to run a command in a high-integrity context |
|bdllload | Call LoadLibrary() in a remote process with the specified DLL. |
|addVisualization | Register a visualization with Cobalt Strike |
|drow_mailserver | Adds a mail server field to a &dialog. |
|openAboutDialog | Open the "About Cobalt Strike" dialog |
|openJumpDialog | Open Cobalt Strike's lateral movement dialog |
|bdllinject | Inject a Reflective DLL into a process |
|bloginuser | Ask Beacon to create a token from the specified credentials. This is the make_token command |
|beacon_link | This function links to an SMB or TCP listener. If the specified listener is not an SMB or TCP listener, this function does nothing |
|openSpawnAsDialog | Open dialog to spawn a payload as another user |
|event_join | Fired when a user connects to the team server |
|range | Generate an array of numbers based on a string description of ranges. |
|beacon_host_script | Locally host a PowerShell script within Beacon and return a short script that will download and invoke this script. This function is a way to run large scripts when there are constraints on the length of your PowerShell one-liner |
|encode | Obfuscate a position-independent blob of code with an encoder |
|drow_krbtgt | Adds a krbtgt selection row to a &dialog |
|drow_beacon | Adds a beacon selection row to a &dialog |
|agSessions | Pull information from the sessions model |
|breg_queryv | Ask Beacon to query a value within a registry key |
|bupload_raw | Ask a Beacon to upload a file |
|pgraph | Generate the pivot graph GUI component |
|bcancel | Cancel a file download |
|call | Issue a call to the team server |
|bsteal_token | Ask Beacon to steal a token from a process |
|openSystemInformationDialog | Open the system information dialog. |
|blink | Ask Beacon to link to a host over a named pipe |
|drow_text_big | Adds a multi-line text field to a &dialog |
|beacon_output_ps | Fired when ps output is sent to a Beacon's console. |
|ssh_command_register | Register help information for an SSH console command. |
|attack_tactics | An array of MITRE ATT&CK tactics known to Cobalt Strike. |
|transform | Transform shellcode into another format. |
|tstamp | Format a time into a date/time value. This value does not include seconds. |
|bshspawn | Spawn shellcode (from a local file) into another process. This function benefits from Beacon's configuration to spawn post-exploitation jobs (e.g., spawnto, ppid, etc.) |
|drow_listener | Adds a listener selection row to a &dialog. This row only shows listeners with stagers (e.g., windows/beacon_https/reverse_https). |
|attack_mitigate | Maps a MITRE ATT&CK tactic ID to its mitigation strategy |
|attack_url | Maps a MITRE ATT&CK tactic ID to the URL where you can learn more. |
|bcp | Ask Beacon to copy a file or folder |
|ssh_command_describe | Describe an SSH command |
|heartbeat_20m | Fired every twenty minutes |
|data_query | Queries Cobalt Strike's data model |
|applications | Returns a list of application information in Cobalt Strike's data model. These applications are results from the System Profiler |
|beacon_info | Get information from a Beacon session's metadata |
|binput | Report a command was run to the Beacon console and logs. Scripts that execute commands for the user (e.g., events, popup menus) should use this function to assure operator attribution of automated actions in Beacon's logs |
|mynick | Get the nickname associated with the current Cobalt Strike client |
|openJavaSignedAppletDialog | Open the Java Signed Applet dialog |
|beacon_commands | Get a list of Beacon commands |
|prompt_file_open | Show a file open dialog. |
|data_keys | List the query-able keys from Cobalt Strike's data model |
|dbutton_action | Adds an action button to a &dialog. When this button is pressed, the dialog closes and its callback is called. You may add multiple buttons to a dialog. Cobalt Strike will line these buttons up in a row and center them at the bottom of the dialog |
|bnet | Run a command from Beacon's net module |
|gzip | GZIP a string |
|ssh_input | Fired when an input message is posted to an SSH console. |
|alias | Creates an alias command in the Beacon console |
|bsleep | Ask Beacon to change its beaconing interval and jitter factor |
|bgetsystem | Ask Beacon to attempt to get the SYSTEM token. |
|keylogger_hit | Fired when there are new results reported to the web server via the cloned site keystroke logger. |
|beacon_remote_exec_methods | Get a list of remote execute methods registered with Cobalt Strike |
|beacon_error | Fired when an error is posted to a Beacon's console. |
|dialog_show | Shows a &dialog. |
|heartbeat_5m | Fired every five minutes |
|agTargets | Pull information from the targets model. |
|beacon_remote_exploits | Get a list of lateral movement options registered with Cobalt Strike |
|listener_restart | Restart a listener |
|heartbeat_15s | Fired every fifteen seconds |
|drow_combobox | Adds a combobox to a &dialog |
|beacon_stage_pipe | This function handles the staging process for a bind pipe stager. This is an optional stager for lateral movement. You can stage any x86 payload/listener through this stager. Use &stager_bind_pipe to generate this stager |
|bmv | Ask Beacon to move a file or folder |
|bnote | Assign a note to the specified Beacon |
|listeners_stageless | Return a list of listener names across all team servers this client is connected to. External C2 listeners are filtered (as they're not actionable via staging or exporting as a Reflective DLL). |
|openBrowserPivotSetup | open the browser pivot setup dialog |
|colorPanel | Generate a Java component to set accent colors within Cobalt Strike's data model |
|agCredentials | Pull information from the credentials model |
|openScriptManager | Open the tab for the script manager. |
|drow_interface | Adds a VPN interface selection row to a &dialog |
|if else | if else statement |
|openGoldenTicketDialog | open a dialog to help generate a golden ticket |
|ssh_error | Fired when an error is posted to an SSH console. |
|credential_add | Add a credential to the data model |
|drow_exploits | Adds a privilege escalation exploit selection row to a &dialog |
|openElevateDialog | Open the dialog to launch a privilege escalation exploit |
|SIGNED_APPLET_RESOURCE | Specify a Java Applet file to use for the Java Signed Applet Attack. |
|hosts | Returns a list of IP addresses from Cobalt Strike's target model |
|listeners_local | Return a list of listener names. This function limits itself to the current team server only. External C2 listener names are omitted |
|br | Print a line-break. |
|beacon_data | Get metadata for a Beacon session |
|bblockdlls | Launch child processes with binary signature policy that blocks non-Microsoft DLLs from loading in the process space |
|bcovertvpn | Ask Beacon to deploy a Covert VPN client |
|beacon_stage_tcp | This function handles the staging process for a bind TCP stager. This is the preferred stager for localhost-only staging. You can stage any payload/listener through this stager. Use &stager_bind_tcp to generate this stager |
|drow_site | Adds a site/URL field to a &dialog. |
|openSystemProfilerDialog | Open the dialog to setup the system profiler. |
|ssh_output | Fired when output is posted to an SSH console. |
|bpsinject | Inject Unmanaged PowerShell into a specific process and run the specified cmdlet |
|fireEvent | Fire an event |
|profiler_hit | Fired when there are new results reported to the System Profiler. |
|bbrowserpivot_stop | Stop a Browser Pivot |
|event_beacon_initial | Fired when an initial beacon message is posted to the event log. |
|openCredentialManager | Open the credential manager tab |
|ssh_commands | Get a list of SSH commands. |
|pref_set_list | Stores a list value into Cobalt Strike's preferences. |
|stager | Returns the stager for a specific Cobalt Strike listener |
|attack_describe | Maps a MITRE ATT&CK tactic ID to its longer description. |
|beacon_output | Fired when output is posted to a Beacon's console. |
|bgetprivs | Attempts to enable the specified privilege in your Beacon session |
|beacon_host_imported_script | Locally host a previously imported PowerShell script within Beacon and return a short script that will download and invoke this script |
|vpn_tap_delete | Destroy a Covert VPN interface |
|heartbeat_5s | Fired every five seconds |
|openListenerManager | Open the listener manager |
|bpassthehash | Ask Beacon to create a token that passes the specified hash. This is the pth command in Beacon. It uses mimikatz |
|event_public | Fired when a public message is posted to the event log. |
|PYTHON_COMPRESS | Compress a Python script generated by Cobalt Strike. |
|fireAlias | Runs a user-defined alias |
|beacon_output_ls | Fired when ls output is sent to a Beacon's console. |
|beacon_checkin | Fired when a Beacon checkin acknowledgement is posted to a Beacon's console |
|output | Print elements against a grey backdrop. Line-breaks are preserved. |
|beacon_remote_exploit_describe | Describe a Beacon lateral movement option |
|licenseKey | Get the license key for this instance of Cobalt Strike |
|bbrowserpivot | Start a Browser Pivot |
|tbrowser | Generate the target browser GUI component. |
|openPivotListenerSetup | open the pivot listener setup dialog |
|prompt_directory_open | Show a directory open dialog. |
|h1 | Prints a title heading. |
|breg_query | Ask Beacon to query a key within the registry |
|bmkdir | Ask Beacon to make a directory |
|str_decode | Convert a string of bytes to text with the specified encoding. |
|previousTab | Activate the tab that is to the left of the current tab. |
|bpowershell | Ask Beacon to run a PowerShell cmdlet |
|kvtable | Prints a table with key/value pairs. |
|-isbeacon | Check if a session is a Beacon or not. |
|beacon_output_alt | Fired when (alternate) output is posted to a Beacon's console. What makes for alternate output? It's just different presentation from normal output. |
|bdrives | Ask Beacon to list the drives on the compromised system |
|bportscan | Ask Beacon to run its port scanner |
|bls | Task a Beacon to list files |
|openApplicationManager | Open the application manager (system profiler results) tab |
|brev2self | Ask Beacon to drop its current token. This calls the RevertToSelf() Win32 API |
|list_unordered | Prints an unordered list |
|bjobkill | Ask Beacon to kill a running post-exploitation job |
|heartbeat_10m | Fired every ten minutes |
|belevate | Ask Beacon to spawn an elevated session with a registered technique |
|tokenToEmail | Covert a phishing token to an email address. |
|getAggressorClient | Returns the aggressor.AggressorClient Java object. This can reach anything internal within the current Cobalt Strike client context |
|layout | Prints a table with no borders and no column headers. |
|separator | Insert a separator into the current menu tree. |
|host_update | Add or update a host in the targets model |
|script_resource | Returns the full path to a resource that is stored relative to this script file. |
|bdownload | Ask a Beacon to download a file |
|openOfficeMacro | Open the office macro export dialog |
|bupload | Ask a Beacon to upload a file |
|openSpearPhishDialog | Open the dialog for the spear phishing tool. |
|powershell_compress | Compresses a PowerShell script and wraps it in a script to decompress and execute it. |
|beacon_output_jobs | Fired when jobs output is sent to a Beacon's console. |
|openScreenshotBrowser | Open the screenshot browser tab |
|openJavaSmartAppletDialog | Open the Java Smart Applet dialog |
|openOrActivate | If a Beacon console exists, make it active. If a Beacon console does not exist, open it. |
|dispatch_event | Call a function in Java Swing's Event Dispatch Thread. Java's Swing Library is not thread safe. All changes to the user interface should happen from the Event Dispatch Thread |
|ts | Prints a time/date stamp in italics. |
|users | Returns a list of users connected to this team server. |
|h4 | Prints a sub-sub-sub-title heading. |
|disconnect | Fired when this Cobalt Strike becomes disconnected from the team server. |
|vpn_interface_info | Get information about a VPN interface. |
|beacon_remote_exec_method_register | Register a Beacon remote execute method with Cobalt Strike. This adds an option for use with the remote-exec command |
|dstamp | Format a time into a date/time value. This value includes seconds. |
|beacon_command_detail | Get the help information for a Beacon command |
|base64_decode | Unwrap a base64-encoded string |
|bcheckin | Ask a Beacon to checkin. This is basically a no-op for Beacon |
|site_host | Host content on Cobalt Strike's web server |
|btask | Report a task acknowledgement for a Beacon. This task acknowledgement will also contribute to the narrative in Cobalt Strike's Activity Report and Sessions Report |
|pref_get_list | Grabs a list value from Cobalt Strike's preferences. |
|host_delete | Delete a host from the targets model |
|closeClient | Close the current Cobalt Strike team server connection |
|HTMLAPP_POWERSHELL | Controls the content of the HTML Application User-driven (PowerShell Output) generated by Cobalt Strike |
|sendmail_start | Fired when a new phishing campaign kicks off. |
|event_notify | Fired when a message from the team server is posted to the event log. |
|bipconfig | Task a Beacon to list network interfaces |
|bunlink | Ask Beacon to delink a Beacon its connected to over a TCP socket or named pipe |
|RESOURCE_GENERATOR_VBS | Controls the content of the HTML Application User-driven (EXE Output) generated by Cobalt Strike. |
|heartbeat_1s | Fired every second |
|openOneLinerDialog | Open the dialog to generate a PowerShell one-liner for this specific Beacon session |
|openScriptedWebDialog | Open the dialog to setup a Scripted Web Delivery Attack |
|archives | Returns a massive list of archived information about your activity from Cobalt Strike's data model. This information is leaned on heavily to reconstruct your activity timeline in Cobalt Strike's reports. |
|openHostFileDialog | Open the host file dialog |
|url_open | Open a URL in the default browser. |
|bexit | Ask a Beacon to exit |
|bkerberos_ticket_purge | Ask beacon to purge tickets from the user's kerberos tray |
|bexecute_assembly | Spawns a local .NET executable assembly as a Beacon post-exploitation job |
|ssh_checkin | Fired when an SSH client checkin acknowledgement is posted to an SSH console. |
|bshell | Ask Beacon to run a command with cmd.exe |
|SMART_APPLET_RESOURCE | Specify a Java Applet file to use for the Java Smart Applet Attack |
|ssh_initial | Fired when an SSH session is seen for the first time. |
|h2 | Prints a sub-title heading. |
|bpsexec | Ask Beacon to spawn a payload on a remote host. This function generates an Artifact Kit executable, copies it to the target, and creates a service to run it. Clean up is included too |
|RESOURCE_GENERATOR | Control the format of the VBS template used in Cobalt Strike. |
|show_message | Shows a message to the user in a dialog box. Use this function to relay information. |
|artifact_general | Generates a payload artifact from arbitrary shellcode |
|beacon_elevators | Get a list of command elevator exploits registered with Cobalt Strike |
|bkill | Ask Beacon to kill a process |
|openPortScannerLocal | Open the port scanner dialog with options to target a Beacon's local network |
|addTab | Create a tab to display a GUI object |
|attack_detect | Maps a MITRE ATT&CK tactic ID to its detection strategy |
|brportfwd | Ask Beacon to setup a reverse port forward |
|base64_encode | Base64 encode a string |
|heartbeat_30m | Fired every thirty minutes |
|beacon_tasked | Fired when a task acknowledgement is posted to a Beacon's console. |
|try catch | Try Catch statement |
|openDownloadBrowser | Open the download browser tab |
|openProcessBrowser | Open a process browser for one or more Beacons |
|if | if statement |
|openEventLog | Open the event log |
|bbrowser | Generate the beacon browser GUI component. Shows only Beacons. |
|heartbeat_10s | Fired every ten seconds |
|transform_vbs | Transform shellcode into a VBS expression that results in a string |
|beacon_mode | Fired when a mode change acknowledgement is posted to a Beacon's console. |
|openSOCKSBrowser | Open the tab to list SOCKS proxy servers |
|openPayloadGeneratorDialog | Open the Payload Generator dialog. |
|bclear | This is the "oops" command. It clears the queued tasks for the specified beacon |
|APPLET_SHELLCODE_FORMAT | Format shellcode before it's placed on the HTML page generated to serve the Signed or Smart Applet Attacks. |
|blog | Post a message to WordPress.com (just kidding). Publishes an output message to the Beacon transcript |
|bjobs | Ask Beacon to list running post-exploitation jobs |
|landscape | Changes the orientation of this document to landscape. |
|artifact_stager | Generates a stager artifact (exe, dll) from a Cobalt Strike listener |
|bargue_list | List the commands + fake arguments Beacon will spoof arguments for |
|openWebLog | Open the web log tab. |
|openInterfaceManager | Open the tab to manage Covert VPN interfaces |
|privmsg | Post a private message to a user in the event log |
|bpowershell_import | Import a PowerShell script into a Beacon |
|bshinject | Inject shellcode (from a local file) into a specific process |
|listener_pivot_create | Create a new pivot listener |
|ssh_output_alt | Fired when (alternate) output is posted to an SSH console. What makes for alternate output? It's just different presentation from normal output. |
|alias_clear | Removes an alias command (and restores default functionality if it existed) |
|vpn_tap_create | Create a Covert VPN interface on the team server system. |
|drow_listener_stage | Adds a listener selection row to a &dialog. This row shows all Beacon and Foreign listener payloads. |
|bssh | Ask Beacon to spawn an SSH session |
|powershell_command | Returns a one-liner to run a PowerShell expression (e.g., powershell.exe -nop -w hidden -encodedcommand MgAgACsAIAAyAA==) |
|highlight | Insert an accent (color highlight) into Cobalt Strike's data model |
|bsocks | Start a SOCKS proxy server associated with a beacon |
|beacon_input | Fired when an input message is posted to a Beacon's console. |
|vpn_interfaces | Return a list of VPN interface names |
|site_kill | Remove a site from Cobalt Strike's web server |
|beacon_remote_exploit_register | Register a Beacon lateral movement option with Cobalt Strike. This function extends the jump command |
|ready | Fired when this Cobalt Strike client is connected to the team server and ready to act. |
|popup_clear | Remove all popup menus associated with the current menu. This is a way to override Cobalt Strike's default popup menu definitions |
|payload | Exports a raw payload for a specific Cobalt Strike listener |
|sbrowser | Generate the session browser GUI component. Shows Beacon AND SSH sessions. |
|brunasadmin | Ask Beacon to run a command in a high-integrity context (bypasses UAC). |
|openTargetBrowser | Open the targets browser |
|openPortScanner | Open the port scanner dialog |

## Release Notes

### 1.0.0

Initial release.

## Questions, issues, feature requests, and contributions

* If you come across a problem with the extension, please [file an issue](https://github.com/darkoperator/vscode-language-aggressor)
* Contributions are always welcome!
* Any and all feedback is appreciated and welcome!
  * If someone has already [filed an issue](https://github.com/darkoperator/vscode-language-aggressor) that encompasses your feedback, please leave a 👍/👎 reaction on the issue
  * Otherwise please file a new issue