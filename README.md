# Check Blocklists
This idea was originally from https://github.com/rblanchardbell/rblscan

It makes a dns request to this RBLs to see if the specified IP is blocked.

## Example
Get-RBLStatus -IP 127.0.0.2

127.0.0.2 Blacklisted on b.barracudacentral.org

127.0.0.2 Blacklisted on bb.barracudacentral.org

127.0.0.2 Blacklisted on bl.emailbasura.org

127.0.0.2 Blacklisted on bl.spamcannibal.org


