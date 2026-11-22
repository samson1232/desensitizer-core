# Domain Controller Audit — infra_host:ZMTGN27EFYLKXNSI36COI4NGRK

Auditor: name:6ZFYULMKKJAIDC3AV23UKFIOKE (staff_id:BZAQHY46P3JKKCLBT4NN3ISAER), email:NCJQUADYPEX7UGVLQTJMUOIB34
System: infra_host:ZMTGN27EFYLKXNSI36COI4NGRK at ipv4:CJPKSEJSJBYPRLKB3TWVJGLZOB (mac mac:2A6Y6CEYB2HJCCXZNMLHXQMKX6)

## Findings
1. Three stale service accounts with passwords older than 400 days. Owners are
   staff members; account list held in the AD export, not here.
2. Kerberos pre-auth disabled on a legacy account used by the outage scheduling
   team. Owner is name:AGDWG42KAWVAXJ35SCNAIAEI6X (staff_id:XEPTINMEWXC33EOFRCCICU4DRV).
3. Local administrator password reuse across six workstations. Reuse flagged on
   hostname:7RX32JQRZ4NEWR72UKO5I52RUJ through hostname:EXGJSC5WUID4Y2XBTVJLQBPAWE.

## Remediation
- Reset all stale accounts. Owner notification via HR, not by direct email.
- Enable Kerberos pre-auth; coordinate with the outage scheduler on
  phone:WYLAKCMQKP3NEN37VHLYZOCQ2E.

## Note
The audit export containing per-user SIDs and staff names lives on
archive01 (ipv4:LY7ZBBCV7EGVRNVM6OHNH4JPRH) and must not be copied to the corporate network
without the DPO's approval.
