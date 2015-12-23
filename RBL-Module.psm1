
#IPRange function from https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b#content
#Written by Barry Chum https://social.technet.microsoft.com/profile/barry%20chum/
function Get-IPrange
{
<# 
  .SYNOPSIS  
    Get the IP addresses in a range 
  .EXAMPLE 
   Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.3 -cidr 24 
#> 
 
param 
( 
  [string]$start, 
  [string]$end, 
  [string]$ip, 
  [string]$mask, 
  [int]$cidr 
) 
 
function IP-toINT64 () { 
  param ($ip) 
 
  $octets = $ip.split(".") 
  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
} 
 
function INT64-toIP() { 
  param ([int64]$int) 

  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
} 
 
if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
if ($ip) { 
  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
} else { 
  $startaddr = IP-toINT64 -ip $start 
  $endaddr = IP-toINT64 -ip $end 
} 
 
 
for ($i = $startaddr; $i -le $endaddr; $i++) 
{ 
  INT64-toIP -int $i 
}

}
function Get-RBLStatus{
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true)]
        [ValidateScript({If ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
                $True
            } Else {
                Throw "$_ is not an IPV4 Address!"
            }})]
        [String]$IP,
        [ValidateRange(0,32)] 
        [Int]$CIDR

    )
    if ($CIDR){
        if($CIDR -lt 24){
        
            $ans=Read-Host -Prompt 'Large Subnet Detected. Many RBLs will stop responding, do you want to continue? [Y/N]' 
            if ($ans -like 'N'){
                break
            }
            elseif($ans -like 'Y'){
                write-host 'Continuing with Large Subnet....'
            }
            else{
                Write-Error -Message 'Invalid response. Terminating'
                break
            }

        }
        $ips=Get-IPrange -ip $IP -cidr $CIDR
    }
    else{
        $ips=$IP
    }
    foreach ($IPAddr in $IPS){
    
        $IPSplit=$IPAddr.split('.')
        $ReversedIP=$IPSplit[3]+'.'+$IPSplit[2]+'.'+$IPSplit[1]+'.'+$IPSplit[0]
        Write-Verbose -Message "$IPAddr is $ReversedIP when reversed."
        #Blacklists
        $LISTS=@(
            "b.barracudacentral.org",
            "bb.barracudacentral.org",
            "bl.deadbeef.com",
            "bl.emailbasura.org",
            "bl.spamcannibal.org",
            "bl.spamcop.net",
            "blackholes.five-ten-sg.com",
            "blacklist.woody.ch",
            "bogons.cymru.com",
            "cbl.abuseat.org",
            "cdl.anti-spam.org.cn",
            "cidr.bl.mcafee.com",
            "combined.abuse.ch",
            "combined.rbl.msrbl.net",
            "db.wpbl.info",
            "dnsbl-1.uceprotect.net",
            "dnsbl-2.uceprotect.net",
            "dnsbl-3.uceprotect.net",
            "dnsbl.cyberlogic.net",
            "dnsbl.inps.de",
            "dnsbl.njabl.org",
            "dnsbl.sorbs.net",
            "drone.abuse.ch",
            "drone.abuse.ch",
            "duinv.aupads.org",
            "dul.dnsbl.sorbs.net",
            "dul.ru",
            "dyna.spamrats.com",
            "dynip.rothen.com",
            "http.dnsbl.sorbs.net",
            "images.rbl.msrbl.net",
            "ips.backscatterer.org",
            "ix.dnsbl.manitu.net",
            "korea.services.net",
            "misc.dnsbl.sorbs.net",
            "noptr.spamrats.com",
            "ohps.dnsbl.net.au",
            "omrs.dnsbl.net.au",
            "orvedb.aupads.org",
            "osps.dnsbl.net.au",
            "osrs.dnsbl.net.au",
            "owfs.dnsbl.net.au",
            "owps.dnsbl.net.au",
            "pbl.spamhaus.org",
            "phishing.rbl.msrbl.net",
            "probes.dnsbl.net.au",
            "proxy.bl.gweep.ca",
            "proxy.block.transip.nl",
            "psbl.surriel.com",
            "rbl.interserver.net",
            "rbl.megarbl.net",
            "rdts.dnsbl.net.au",
            "relays.bl.gweep.ca",
            "relays.bl.kundenserver.de",
            "relays.nether.net",
            "residential.block.transip.nl",
            "ricn.dnsbl.net.au",
            "rmst.dnsbl.net.au",
            "sbl.spamhaus.org",
            "short.rbl.jp",
            "smtp.dnsbl.sorbs.net",
            "socks.dnsbl.sorbs.net",
            "spam.abuse.ch",
            "spam.dnsbl.sorbs.net",
            "spam.rbl.msrbl.net",
            "spam.spamrats.com",
            "spamlist.or.kr",
            "spamrbl.imp.ch",
            "t3direct.dnsbl.net.au",
            "tor.dnsbl.sectoor.de",
            "torserver.tor.dnsbl.sectoor.de",
            "ubl.lashback.com",
            "ubl.unsubscore.com",
            "virbl.bit.nl",
            "virus.rbl.jp",
            "virus.rbl.msrbl.net",
            "web.dnsbl.sorbs.net",
            "wormrbl.imp.ch",
            "xbl.spamhaus.org",
            "zen.spamhaus.org",
            "zombie.dnsbl.sorbs.net"
        )
        foreach($List in $LISTS){
            Write-Verbose -Message "Checking $IPAddr on $List"
            if(Resolve-DnsName -Name $($ReversedIP+'.'+$List) -ErrorAction SilentlyContinue){
                write-host -ForegroundColor Red "$($IPAddr) Blacklisted on $($List)"
            }
        }
    }
}
