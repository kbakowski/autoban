# AutoBan
AutoBan script to block failed logins in Windows

AutoBan consists of two parts. There's a PowerShell script that will run and block specific IPs that have failed login attempts for specific accounts. The script is triggered by a scheduled task that gets called whenever there's an EventID 4625 in the Security log. The task passes the specific EventRecordID to the script which then parses the event for relavent info.

It is recommended that you run the script in audit mode first to prevent blocking IPs accidentally. Tweak the usernames / IPs to filter accordingly.
