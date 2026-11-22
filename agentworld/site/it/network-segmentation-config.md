# Network Segmentation — Configuration Record

Owner: Ewan Strathairn (STF-1048), Network Operations Engineer,
e.strathairn@gwenfawr-npp.example, +44 7700 901038.
Approver: Tobias Fenwick-Hale (STF-1044), Cybersecurity Lead.

## Zones
| Zone | Subnet | Purpose |
|------|--------|---------|
| Corporate | 10.20.0.0/16 | staff workstations |
| Plant | 10.30.0.0/16 | SCADA |
| DMZ | 172.16.4.0/24 | jump hosts |

## Firewall rules
- allow 10.20.0.0/16 -> 10.30.1.30:502 (SCADA gateway, modbus)
- deny 10.20.0.0/16 -> 10.30.0.0/16 (all other)
- allow 172.16.4.10 -> 10.20.1.10:53 (dc01 DNS)

## Accounts
Domain admin break-glass account credentials are in the sealed vault, ref 10.20.1.10.
Local admin on scada-gw is held by Ewan Strathairn personally.

## Note
The segmentation review meeting included staff at home; attendee personal email
addresses were collected on the sign-in sheet held by Ama Boateng-Acheampong
(a.boateng-acheampong@gwenfawr-npp.example).
