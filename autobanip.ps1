param (
  [Parameter(Mandatory)][int]$recordId,	# the recordID is sent from the triggering event
  $AuditOnly = $false					# run in audit mode only, off by default
)

# Modify the settings below
$SmtpServer = "mail.yourorg.tld"
$FromAddr = "yournamehere@yourorg.tld"
$ToAddr = "criticalalerts@yourorg.tld"
$IPWLCustom = "8.8.4.4", "8.8.8.8"

# # # DO NOT MODIFY BELOW THIS LINE # # #

$servername = $env:COMPUTERNAME

# Pull specific event from event log
$queryStr = "*[System[(EventRecordID=$recordID)]]"
$BadEvent = get-winevent -logname "Security" -maxEvents 1 -FilterXPath $queryStr
$EventXML = [XML] $BadEvent.ToXML()

## Pull information from the Event
$IpAddress = $EventXML.SelectSingleNode("//*[@Name='IpAddress']")."#text"
$TargetUsername = $EventXML.SelectSingleNode("//*[@Name='TargetUserName']")."#text"

# Modify usernames to watch for as desired
$UserBL = "access","adm","adm2","admin","admin$","administrator","administrateur","administrador","alohapos","alohaservice","anyuser","asp.net","ASPNET","backupexec","besadmin","calendar","cashier","console","dashboard","datamax","delphiuser","ecommerce","equipment","flexcomsupport","front","frontdesk","gans","guest","hvx","iomega","intern","IUSR_IIS","logmeinuser","logmeinremoteuser","micros","mssqlserver","netadmin","newmarket","niadmin","nisupport","office","op","opencourse","opentable","owner","pos","postec","pub","reception","register","root","sally","scanner","staff","support","support_388945a0","sys","sys1","sys12","systray","taxi","test","tickets","us","user","user1","uucp","vadmin","visitor","vm","warehouse","webadmin","webmaster","y"
# Add quoted, comma-delimited IPs here

# Exclude self
$IPWL = "0.0.0.0", "-", "127.0.0.1"
$IPWL += $IPWLCustom

# Create eventlog source if doesn't exist (required to be able to write event logs)
If ([System.Diagnostics.EventLog]::SourceExists("AutoBan") -eq $False) {
	New-EventLog -LogName Application -Source "AutoBan"
}

# username in blacklist and not in our IP whitelist
if (($IPWL -notcontains $ipAddress) -and ($UserBL -contains $Targetusername))
{

  if( $AuditOnly )
  {
	# Configure E-mail + eventlog message
	$Subject = "[AutoBan] " + $ServerName + " detected IP: " + $IpAddress
	$Body = $ServerName + " detected the following IP address: " + $IpAddress + "`n`n"
	$Body += "Attempted username : " + $TargetUsername + "`n`n"
	$Body += "AutoBan is running in detect mode only. This was not added to the firewall"
	$EventID = 1000
	$EntryType = "Warning"
  } 
  else {
	  
	# Get firewall object
	$FirewallObj = New-Object -ComObject hnetcfg.fwpolicy2 
	# Select our rule
	$FirewallRule = $FirewallObj.rules | where-object {$_.name -eq 'Auto Block Failed Admin Attempts'} 
  
	# Test if firewall rule exists. If so, add the remote IP. If no, create the rule.
	# NOTE - it's SUPER important to specify a RemoteAddress when creating a default block rule otherwise it will block everything
    if( $FirewallRule ){
      $FirewallRule.remoteaddresses += ',' + $IpAddress + "/255.255.255.255" # add IPs to firewall rule
	} else {
      New-NetFirewallRule -DisplayName "Auto Block Failed Admin Attempts" -Direction Inbound -Action Block -RemoteAddress $IpAddress
	}
	
	# Configure E-mail + eventlog message
	$Subject = "[AutoBan] " + $ServerName + " blocked IP: " + $IpAddress
	$Body = $ServerName + " blocked the following IP address: " + $IpAddress + "`n`n"
	$Body += "Attempted username : " + $TargetUsername + "`n`n"
	$EventID = 2000
	$EntryType = "Error"

  }

  Write-EventLog -LogName Application -EventID $EventID -EntryType $EntryType -Source "AutoBan" -Message $Body

  Send-MailMessage -From $FromAddr -To $ToAddr -Subject $Subject -Body $Body -SmtpServer $SmtpServer
} elseif($UserBL -contains $Targetusername) {
	# username matches and IP _is_ in whitelist
	# Configure eventlog message
	$Subject = "[AutoBan] " + $ServerName + " detected whitelisted IP: " + $IpAddress
	$Body = $ServerName + " detected the following IP address: " + $IpAddress + "`n`n"
	$Body += "Attempted username : " + $TargetUsername + "`n`n"
	$Body += "This IP is whitelisted and was not blocked."
	$EventID = 1100
	$EntryType = "Warning"

	Write-EventLog -LogName Application -EventID $EventID -EntryType $EntryType -Source "AutoBan" -Message $Body	
}