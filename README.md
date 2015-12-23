# Check Blocklists
This idea was originally from https://github.com/rblanchardbell/rblscan

It makes a dns request to this RBLs to see if the specified IP is blocked.

## Example 1
Get-RBLStatus -IP 127.0.0.2

127.0.0.2 Blacklisted on b.barracudacentral.org

127.0.0.2 Blacklisted on bb.barracudacentral.org

127.0.0.2 Blacklisted on bl.emailbasura.org

127.0.0.2 Blacklisted on bl.spamcannibal.org

## Example 2
Get-BlockListStatus -IP 127.0.0.2 -CIDR 31 -Verbose

VERBOSE: 127.0.0.2 is 2.0.0.127 when reversed.

VERBOSE: Checking 127.0.0.2 on b.barracudacentral.org

VERBOSE: 2.0.0.127.b.barracudacentral.org

127.0.0.2 Blacklisted on b.barracudacentral.org

VERBOSE: 127.0.0.3 is 3.0.0.127 when reversed.

VERBOSE: Checking 127.0.0.3 on bl.spamcannibal.org

VERBOSE: 3.0.0.127.bl.spamcannibal.org

127.0.0.3 Blacklisted on bl.spamcannibal.org
