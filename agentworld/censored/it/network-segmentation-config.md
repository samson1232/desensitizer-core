# Network Segmentation — Configuration Record

Owner: name:YF3KJXGQ6ZPIB4RAUXEBO2SBC2 (staff_id:LCJ5JYUDY3J2JKOFVTR5WYYYCX), Network Operations Engineer,
email:XAVEHRPH3RSXHSDIGKWAMVTITC, phone:AFJJ4RZ2KOR5OF2MXLFGYFNG66.
Approver: name:6ZFYULMKKJAIDC3AV23UKFIOKE (staff_id:BZAQHY46P3JKKCLBT4NN3ISAER), Cybersecurity Lead.

## Zones
| Zone | Subnet | Purpose |
|------|--------|---------|
| Corporate | ipv4:T4SFR3DAVRWCRPGB3EY76DO4EH/16 | staff workstations |
| Plant | ipv4:DXHMHWB525RY6F2KLVWOZLQ466/16 | SCADA |
| DMZ | ipv4:EZDQVY5536RZVGE6SMKXOUOQRK/24 | jump hosts |

## Firewall rules
- allow ipv4:T4SFR3DAVRWCRPGB3EY76DO4EH/16 -> ipv4:23MRLMEWMMT3T2PKFRSML4Q2UB:502 (SCADA gateway, modbus)
- deny ipv4:T4SFR3DAVRWCRPGB3EY76DO4EH/16 -> ipv4:DXHMHWB525RY6F2KLVWOZLQ466/16 (all other)
- allow ipv4:AG3SY55JMWXJBLQJM3PCFQW7PY -> ipv4:CJPKSEJSJBYPRLKB3TWVJGLZOB:53 (dc01 DNS)

## Accounts
Domain admin break-glass account credentials are in the sealed vault, ref ipv4:CJPKSEJSJBYPRLKB3TWVJGLZOB.
Local admin on scada-gw is held by name:YF3KJXGQ6ZPIB4RAUXEBO2SBC2 personally.

## Note
The segmentation review meeting included staff at home; attendee personal email
addresses were collected on the sign-in sheet held by name:DEIWJCLN23UUSECE3NYR5E7CC4
(email:7M62RA34DIR2JZFRY3NSA6MMZI).
