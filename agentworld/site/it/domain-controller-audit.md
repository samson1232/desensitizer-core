# Domain Controller Audit — npp-dc01

Auditor: Tobias Fenwick-Hale (STF-1044), t.fenwick-hale@gwenfawr-npp.example
System: npp-dc01 at 10.20.1.10 (mac 02:ff:01:00:00:10)

## Findings
1. Three stale service accounts with passwords older than 400 days. Owners are
   staff members; account list held in the AD export, not here.
2. Kerberos pre-auth disabled on a legacy account used by the outage scheduling
   team. Owner is Ffion Llewellyn-Pryce (STF-1052).
3. Local administrator password reuse across six workstations. Reuse flagged on
   operations-ws-100 through operations-ws-105.

## Remediation
- Reset all stale accounts. Owner notification via HR, not by direct email.
- Enable Kerberos pre-auth; coordinate with the outage scheduler on
  +44 7700 901482.

## Note
The audit export containing per-user SIDs and staff names lives on
archive01 (10.20.1.40) and must not be copied to the corporate network
without the DPO's approval.
