# Pattern Hyperscan che matchano traffico HTTP normale

**Totale pattern problematici: 149**

## Perché Suricata non genera falsi alert

Suricata non genera falsi positivi per questi pattern perché applica **condizioni aggiuntive** rispetto al semplice content match:

1. **Sticky buffer**: restringe la ricerca a uno specifico campo HTTP (es. `http.user_agent` cerca solo nell'header User-Agent, non nel payload raw). XDP scansiona l'intero payload TCP.
2. **startswith / offset / depth**: limitano la posizione del match all'interno del campo.
3. **Più content in AND**: la regola richiede che TUTTI i content siano presenti, non solo uno.
4. **flow direction**: `to_server` / `to_client` limita ulteriormente a request o response.

Nel pre-filtro XDP non abbiamo parsing HTTP — scansiona i byte grezzi del payload TCP.
Per questo molti pattern che in Suricata sono precisi diventano iper-generici in Hyperscan.

---

## Tabella completa

| PatID | SID | Len | Pattern (literal) | Matcha in | Sticky buffer Suricata | Modificatori | Altri content nella regola | flow | Descrizione regola |
|------:|----:|----:|:------------------|:----------|:-----------------------|:-------------|:--------------------------|:-----|:-------------------|
| 13544 | 2002874 | 1 | `z` | GET + POST | `http.user_agent` | startswith | — | established,to_server | ET USER_AGENTS Metafisher/Goldun User-Agent (z) |
| 13548 | 2007880 | 1 | `-` | GET + POST + 200 | `http.user_agent` | startswith | — | established,to_server | ET USER_AGENTS User-Agent (single dash) |
| 13534 | 2006394 | 2 | `ld` | 200 | `http.user_agent` | startswith | — | established,to_server | ET USER_AGENTS Downloader User-Agent Detected (ld) |
| 13541 | 2006388 | 2 | `00` | 200 | `http.user_agent` | startswith | — | established,to_server | ET USER_AGENTS Suspicious User-Agent (006) |
| 14086 | 2017143 | 2 | `\r\n` | GET + POST + 200 | `http.uri` | — | — | established,to_server | ET WEB_SERVER CRLF Injection - Newline Characters in URL |
| 3438 | 2045636 | 3 | `GET` | GET | `http.user_agent` | — | `GET`, `|22 3b|` | established,to_server | ET EXPLOIT Possible Command Injection via User-Agent (PwnAge |
| 4006 | 2015693 | 3 | `/1.` | GET + POST + 200 | `http.uri` | — | — | established,to_server | ET EXPLOIT_KIT NeoSploit - Version Enumerated - Java |
| 14208 | 2049011 | 3 | `200` | 200 | `http.response_body` | startswith | — | established,to_client | ET WEB_SERVER Suspected FOXSHELL Variant Webshell Activity |
| 14209 | 2049012 | 3 | `200` | 200 | `http.response_body` | startswith | — | established,to_client | ET WEB_SERVER Suspected FOXSHELL Variant Webshell Activity |
| 168 | 2030821 | 4 | `POST` | POST | `http.request_body` | startswith | `POST`, `/`, `&fb=` | established,to_server | ET ADWARE_PUP Win32/Zonebac Traffic Redirect |
| 436 | 2007943 | 4 | `HTTP` | GET + POST + 200 | `http.user_agent` | startswith | — | established,to_server | ET ADWARE_PUP User-Agent (HTTP) |
| 490 | 2018368 | 4 | `POST` | POST | `http.uri` | — | `POST` | established,to_server | ET ADWARE_PUP W32/PullUpdate.Adware CnC Beacon |
| 4913 | 2038503 | 4 | `POST` | POST | `http.request_body` | — | `POST`, `PK` | established,to_server | ET HUNTING Outbound POST Request with Zipped Directory Trave |
| 5269 | 2030518 | 4 | `POST` | POST | `http.host` | — | `POST` | established,to_server | ET INFO HTTP POST Request to Suspicious *.ma Domain |
| 5285 | 2014380 | 4 | `post`/i | POST | `http.method` | nocase | — | established,to_server | ET INFO HTTP POST invalid method case outbound |
| 5301 | 2025100 | 4 | `POST` | POST | `http.host` | — | `POST` | established,to_server | ET INFO HTTP POST Request to Suspicious *.gq domain |
| 5302 | 2025101 | 4 | `POST` | POST | `http.host` | — | `POST` | established,to_server | ET INFO HTTP POST Request to Suspicious *.ga Domain |
| 5303 | 2025102 | 4 | `POST` | POST | `http.host` | — | `POST` | established,to_server | ET INFO HTTP POST Request to Suspicious *.ml Domain |
| 5304 | 2025103 | 4 | `POST` | POST | `http.host` | — | `POST` | established,to_server | ET INFO HTTP POST Request to Suspicious *.cf Domain |
| 5540 | 2013926 | 4 | `POST` | POST | `—` | — | `POST` | established,to_server | ET INFO HTTP traffic on port 443 (POST) |
| 6220 | 2018098 | 4 | `POST` | POST | `http.uri` | — | `POST` | established,to_server | ET MALWARE W32/Asprox.ClickFraudBot POST CnC Beacon |
| 6287 | 2030846 | 4 | `POST` | POST | `http.cookie` | — | `POST`, `%3a`, `%2c` | established,to_server | ET MALWARE APT29/Wellness CnC Host Checkin |
| 7626 | 2030691 | 4 | `HTTP` | GET + POST + 200 | `http.user_agent` | — | `POST` | established,to_server | ET MALWARE Possible KONNI CnC Activity |
| 8938 | 2017948 | 4 | `POST`/i | POST | `http.request_body` | startswith | `POST`, `.php`, `&b=`, `&d=` | established,to_server | ET MALWARE LDPinch Checkin Post |
| 9237 | 2025885 | 4 | `POST` | POST | `http.request_body` | — | `POST`, `.php`, `|2f fb|` | established,to_server | ET MALWARE AZORult Variant.4 Checkin M2 |
| 9773 | 2047019 | 4 | `POST` | POST | `http.request_body` | startswith | `POST` | established,to_server | ET MALWARE Earth Preta PUBLOAD Activity M1 |
| 9863 | 2022074 | 4 | `POST` | POST | `http.uri` | — | `POST` | established,to_server | ET MALWARE Bookworm CnC Beacon 2 |
| 10240 | 2030534 | 4 | `POST` | POST | `http.cookie` | — | `POST` | established,to_server | ET MALWARE APT29/WellMess CnC Activity |
| 10245 | 2018204 | 4 | `POST` | POST | `http.request_body` | startswith | `POST`, `.php`, `&c=` | established,to_server | ET MALWARE W32/Qakbot.Bot Version 8 CnC Beacon |
| 10263 | 2017633 | 4 | `POST`/i | POST | `http.request_body` | startswith | `POST`, `&b=`, `&c=` | established,to_server | ET MALWARE Athena DDoS Bot Checkin |
| 10297 | 2024781 | 4 | `POST` | POST | `http.request_body` | — | `POST`, `.php`, `c=`, `&v=` | established,to_server | ET MALWARE Win32/Formgrabber Data Exfil |
| 12390 | 2032177 | 4 | `POST` | POST | `http.request_body` | startswith | `POST`, `save`, `.asp`, `&p=` | established,to_server | ET PHISHING Successful Apple Phishing 2016-03-03 |
| 12485 | 2032377 | 4 | `POST` | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `pass` | established,to_server | ET PHISHING Possible Successful Phish to Hostinger Domains M |
| 12486 | 2032378 | 4 | `user`/i | GET + POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `pass` | established,to_server | ET PHISHING Possible Successful Phish to Hostinger Domains M |
| 12689 | 2032727 | 4 | `POST` | POST | `http.request_body` | startswith, nocase | `POST`, `|25|40`, `&t2=` | established,to_server | ET PHISHING Successful Paypal (DE) Phish 2016-12-19 |
| 12764 | 2101634 | 4 | `PASS`/i | POST | `—` | nocase | — | established,to_server | GPL POP3 POP3 PASS overflow attempt |
| 12960 | 2013235 | 4 | `PASS`/i | POST | `—` | — | `PASS` | established,to_server | ET SCADA Golden FTP Server PASS Command Remote Buffer Overfl |
| 5082 | 2013315 | 5 | `Agent` | GET + POST | `—` | — | `Agent` | established,to_server | ET HUNTING Suspicious User-Agent (Agent and 5 or 6 digits) |
| 9065 | 2021275 | 5 | `.html`/i | GET | `http.cookie` | startswith | `GET`, `/`, `.html` | established,to_server | ET MALWARE Backdoor.Elise CnC Beacon 1 M2 |
| 9563 | 2035309 | 5 | `.html` | GET | `http.user_agent` | — | `GET`, `.html`, `|3a 3a|`, `_` | established,to_server | ET MALWARE Win32/Pterodo CnC Activity (GET) |
| 9850 | 2021276 | 5 | `.html`/i | GET | `http.uri` | nocase | `POST` | established,to_server | ET MALWARE Backdoor.Elise CnC Beacon 2 |
| 12212 | 2031568 | 5 | `&pass`/i | POST | `http.request_body` | startswith, nocase | `POST`, `/wp-`, `.php`, `&pass` | established,to_server | ET PHISHING Terse POST to Wordpress Folder - Probable Succes |
| 15210 | 2056423 | 5 | `GET /` | GET | `http.request_body` | startswith | — | established,to_server | ET WEB_SPECIFIC_APPS Apache 2.4.0 -> 2.4.55 HTTP Smuggling A |
| 8553 | 2018578 | 6 | `POST /` | POST | `http.request_body` | startswith | `POST`, `Wget/` | established,to_server | ET MALWARE Dyreza RAT Ex-filtrating Data |
| 15211 | 2056424 | 6 | `POST /` | POST | `http.request_body` | startswith | — | established,to_server | ET WEB_SPECIFIC_APPS Apache 2.4.0 -> 2.4.55 HTTP Smuggling A |
| 8782 | 2024436 | 7 | `Mozilla` | GET + POST | `http.request_body` | startswith, nocase | `POST`, `Mozilla` | established,to_server | ET MALWARE Formbook 0.3 Checkin |
| 8817 | 2008958 | 7 | `Mozilla`/i | GET + POST | `http.user_agent` | nocase | `POST`, `a=` | established,to_server | ET MALWARE Waledac Beacon Traffic Detected |
| 9833 | 2018604 | 7 | `Mozilla` | GET + POST | `http.uri` | nocase | `GET`, `Mozilla` | established,to_server | ET MALWARE Andromeda Downloading Module |
| 10326 | 2022504 | 7 | `Mozilla` | GET + POST | `http.request_body` | startswith | `POST`, `.php`, `Mozilla` | established,to_server | ET MALWARE Alphacrypt/TeslaCrypt Ransomware CnC Beacon |
| 4291 | 2008975 | 8 | `Accept: ` | GET | `http.accept` | — | — | established,to_server | ET HUNTING Suspicious Malformed Double Accept Header |
| 5830 | 2020209 | 8 | `Windows ` | GET | `—` | — | `Windows `, `|00|Win`, `|00|` | established,to_server | ET MALWARE Win32.ChinaZ.DDoSClient Checkin |
| 9462 | 2035024 | 8 | `Mozilla/` | GET + POST | `http.user_agent` | — | `GET`, `.php`, `Mozilla/`, `|3a 3a|` | established,to_server | ET MALWARE Gamaredon MalDoc CnC Exfil |
| 9887 | 2026641 | 8 | `Windows ` | GET | `http.uri` | — | `.php?a=`, `&b=`, `&c=`, `&d=` | established,to_server | ET MALWARE ArtraDownloader/TeleRAT Checkin |
| 10204 | 2051447 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|HWID|0d 0a|` | established,to_server | ET MALWARE Win32/ObserverStealer CnC Activity M2 (Check-in) |
| 10205 | 2051448 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|SYS|0d 0a|`, `|7b 22|username|22 3a 20 22|` | established,to_server | ET MALWARE Win32/ObserverStealer CnC Activity M2 (System Inf |
| 10206 | 2051449 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|SCR|0d 0a|` | established,to_server | ET MALWARE Win32/ObserverStealer CnC Activity M2 (Screenshot |
| 10207 | 2051450 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|Google_` | established,to_server | ET MALWARE Win32/ObserverStealer Sending Browser Related Inf |
| 10208 | 2051451 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|Firefox_` | established,to_server | ET MALWARE Win32/ObserverStealer Sending Browser Related Inf |
| 10209 | 2051452 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|Thunderbird_` | established,to_server | ET MALWARE Win32/ObserverStealer Sending System Related Info |
| 10210 | 2051453 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST` | established,to_server | ET MALWARE Win32/ObserverStealer Sending System Related Info |
| 10211 | 2051454 | 8 | `HTTP/1.1` | GET + POST + 200 | `http.user_agent` | — | `POST`, `|3a 20|END|0d 0a|` | established,to_server | ET MALWARE Win32/ObserverStealer Related Activity (POST) |
| 11528 | 2025000 | 8 | `username`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `pass` | established,to_server | ET PHISHING Possible Successful Phish to Hostinger Domains A |
| 13954 | 2022028 | 8 | ` HTTP/1.` | GET + POST | `—` | — | ` HTTP/1.` | established,to_server | ET WEB_SERVER Possible CVE-2014-6271 Attempt |
| 3248 | 2034043 | 9 | `password=`/i | POST | `http.request_body` | nocase | `POST`, `/auth`, `username=`, `%3b` | established,to_server | ET EXPLOIT Cisco HyperFlex OS Command Injection M1 (CVE-2021 |
| 3249 | 2034044 | 9 | `password=`/i | POST | `http.request_body` | nocase | `POST`, `/auth`, `username=`, `%3bimport|20|` | established,to_server | ET EXPLOIT Cisco HyperFlex OS Command Injection M2 (CVE-2021 |
| 5078 | 2031523 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST` | established,to_server | ET HUNTING Suspicious HTTP POST Only Containing Password - P |
| 8973 | 2009897 | 9 | `text/html`/i | GET + 200 | `file.data` | — | `text/html`, `MZ` | established,to_client | ET MALWARE Possible Windows executable sent when remote host |
| 11152 | 2034894 | 9 | `username=` | POST | `http.uri` | — | `POST`, `username=`, `&pin=` | established,to_server | ET PHISHING Successful Generic Banking Phish 2022-01-11 |
| 11508 | 2024228 | 9 | `text/html` | GET + 200 | `file.data` | — | `200`, `text/html`, `<title>`, `|26 23|` | established,to_client | ET PHISHING Suspicious HTML Decimal Obfuscated Title - Possi |
| 11513 | 2024432 | 9 | `text/html` | GET + 200 | `file.data` | — | `200`, `text/html`, `<title>`, `|26 23|x` | established,to_client | ET PHISHING Suspicious HTML Hex Obfuscated Title - Possible  |
| 12092 | 2032674 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `pass` | established,to_server | ET PHISHING Successful Dynamic Folder Phishing 2016-02-23 |
| 12107 | 2021296 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&pass`, `&vi=` | established,to_server | ET PHISHING Successful Adobe Phish Jun 17 2015 |
| 12144 | 2032470 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.tk` | established,to_server | ET PHISHING HTTP POST Contains Only Password (tk) 2021-04-05 |
| 12145 | 2032471 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.ml` | established,to_server | ET PHISHING HTTP POST Contains Only Password (ml) 2021-04-05 |
| 12146 | 2032472 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.gq` | established,to_server | ET PHISHING HTTP POST Contains Only Password (gq) 2021-04-05 |
| 12147 | 2032473 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.ga` | established,to_server | ET PHISHING HTTP POST Contains Only Password (ga) 2021-04-05 |
| 12148 | 2032474 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.cf` | established,to_server | ET PHISHING HTTP POST Contains Only Password (cf) 2021-04-05 |
| 12149 | 2032475 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.xyz` | established,to_server | ET PHISHING HTTP POST Contains Only Password (xyz) 2021-04-0 |
| 12217 | 2031730 | 9 | `username=` | POST | `http.request_body` | startswith | `POST`, `.php?`, `&username`, `&password=` | established,to_server | ET PHISHING Successful Vmware/Zimbra Phish 2015-09-28 |
| 12227 | 2031756 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `password=`, `&phone=` | established,to_server | ET PHISHING Possible Successful Generic Phish 2015-07-31 |
| 12233 | 2031764 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `&pass`, `&locale=`, `=Sign+in` | established,to_server | ET PHISHING Successful Adobe Online Account Phish 2015-08-21 |
| 12245 | 2031778 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `&email=`, `&password=`, `&login=Login` | established,to_server | ET PHISHING Successful Blackboard Account Phish 2015-10-08 |
| 12252 | 2031790 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `&password=`, `&remember-me=`, `&identifier=` | established,to_server | ET PHISHING Successful SFR Phishing 2015-11-24 |
| 12255 | 2031794 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&pass`, `&source=` | established,to_server | ET PHISHING Successful Wildblue/CenturyLink Phish 2015-12-08 |
| 12288 | 2031848 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=`, `&email=` | established,to_server | ET PHISHING Successful IBC Bank Phish 2015-10-29 |
| 12304 | 2031890 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=`, `&first_name=` | established,to_server | ET PHISHING Successful Telstra Phish M2 2015-09-05 |
| 12334 | 2032024 | 9 | `password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php?userid=`, `.php?userid=`, `&submit=upgrade+account` | established,to_server | ET PHISHING Successful Mailbox Upgrade Phish 2016-06-27 M2 |
| 12336 | 2032030 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php?src=`, `&username=`, `.php?src=` | established,to_server | ET PHISHING Successful Generic Webmail Account Phish 2016-07 |
| 12426 | 2032242 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `adobe`, `.php`, `adobe` | established,to_server | ET PHISHING Successful Adobe Phish 2016-09-14 |
| 12509 | 2032461 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=`, `&changing=Value` | established,to_server | ET PHISHING Successful Dropbox Phish 2016-09-14 |
| 12649 | 2032685 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=`, `&domain=` | established,to_server | ET PHISHING Successful Webmail Phish M1 2016-06-22 |
| 12650 | 2032687 | 9 | `&Password`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `UserName=`, `&AuthMethod=FormsAuth` | established,to_server | ET PHISHING Successful Docusign/O365 Phish 2016-07-15 |
| 12652 | 2032690 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&epas=`, `&tel=` | established,to_server | ET PHISHING Successful Adobe Shared Document Phish 2016-08-1 |
| 12657 | 2032700 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=`, `&submit=` | established,to_server | ET PHISHING Successful Adobe Shared Document Phish 2016-10-0 |
| 12700 | 2029656 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `/wp-`, `.php`, `&pass` | established,to_server | ET PHISHING Terse POST to Wordpress Folder - Probable Succes |
| 12701 | 2029655 | 9 | `username=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&email=`, `&pass` | established,to_server | ET PHISHING Successful Mailbox Update Phish 2016-02-17 |
| 9045 | 2019545 | 10 | `Windows NT` | GET | `http.uri` | — | `/?`, `Windows NT` | established,to_server | ET MALWARE Sofacy Request Outbound |
| 10490 | 2034692 | 10 | `Keep-Alive`/i | GET + POST | `http.uri` | — | `GET`, `&user=`, `Keep-Alive` | established,to_server | ET MALWARE Kimsuky Related CnC Activity |
| 11303 | 2039509 | 10 | `&password=` | POST | `http.request_body` | — | `POST`, `.php`, `email=`, `&password=` | established,to_server | ET PHISHING Successful Luno Credential Phish 2022-10-20 |
| 11473 | 2022019 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php?Go=_`, `chldr=`, `&ccnum=` | established,to_server | ET PHISHING Successful Paypal Account Phish 2015-10-30 3 |
| 12209 | 2029663 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `location=`, `&loginpage=`, `&username=` | established,to_server | ET PHISHING Successful OX App Suite Phish 2017-10-12 |
| 12311 | 2031900 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `username=`, `&counter=` | established,to_server | ET PHISHING Successful Outlook Webmail Phishing M2 2015-11-2 |
| 12319 | 2031910 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `login=`, `&form6=` | established,to_server | ET PHISHING Successful Halifax Bank Phish M1 2015-12-10 |
| 12489 | 2032399 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `email=`, `&phonenumber=` | established,to_server | ET PHISHING Successful DHL Phish 2016-07-11 |
| 12498 | 2032424 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `appvars=`, `&username=` | established,to_server | ET PHISHING Successful Workspace Phish 2016-01-26 |
| 12499 | 2032425 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `SMENC=`, `&user=` | established,to_server | ET PHISHING Successful Navy Federal Credit Union Phish 2016- |
| 12631 | 2032653 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `type=`, `&email=` | established,to_server | ET PHISHING Successful Google Drive Phish 2016-12-07 |
| 12643 | 2032667 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `first=`, `&last=` | established,to_server | ET PHISHING Successful Discover Phish M3 2016-12-14 |
| 12648 | 2032683 | 10 | `&password=`/i | POST | `http.request_body` | nocase | `POST`, `.php`, `yahoo`, `id=` | established,to_server | ET PHISHING Successful Yahoo Phish M1 2016-06-15 |
| 12692 | 2032719 | 10 | `&password=`/i | POST | `http.request_body` | startswith, nocase | `POST`, `.php`, `&password=` | established,to_server | ET PHISHING Successful Dynamic Folder Phish 2016-11-28 |
| 15184 | 2056181 | 10 | `/api/login` | POST | `http.uri` | startswith | `POST`, `application/json`, `|22|username|22 3a|`, `|22|provider_` | established,to_server | ET WEB_SPECIFIC_APPS F5 BIG-IP Next Central Manager OData In |
| 13479 | 2038507 | 11 | `Hello World`/i | 200 | `http.user_agent` | nocase | — | established,to_server | ET USER_AGENTS Suspicious User-Agent (Hello World) |
| 5010 | 2003626 | 12 | `User-Agent: `/i | GET + POST | `http.user_agent` | startswith, nocase | — | established,to_server | ET HUNTING Double User-Agent (User-Agent User-Agent) |
| 5038 | 2015898 | 12 | `Windows NT 1`/i | GET | `http.user_agent` | nocase | — | established,to_server | ET HUNTING Suspicious Windows NT version 1 User-Agent |
| 8935 | 2018340 | 12 | `\r\nUser-Agent` | GET + POST | `http.uri` | — | `|0d 0a|User-Agent` | established,to_server | ET MALWARE Win32.Sality-GR Checkin |
| 5389 | 1000002 | 17 | `Host: example.com` | GET + POST | `—` | — | — | — | Bypass HTTP to example.com |
| 10564 | 2030123 | 19 | `User-Agent: Mozilla` | GET + POST | `http.user_agent` | startswith | `cookie|3a 20 0d 0a|accept|3a 2`, `GET`, `/check?ver=`, `&os=` | established,to_server | ET MALWARE W32/Agent.XXZBEN Downloader Activity |
| 8411 | 2020078 | 25 | `User-Agent: Mozilla/5.0\r\n` | POST | `http.header` | — | `/index.php?c=`, `&r=` | established,to_server | ET MALWARE RocketKitten APT Checkin |
| 6557 | 2033762 | 29 | `(Windows NT 10.0; Win64; x64)` | GET | `http.uri` | — | `POST`, `?q=`, `|28|Windows|20|NT|20|10.0|3b 2`, `|7b 22|Data|22 3a 5b 22|` | established,to_server | ET MALWARE SiameseKitten/Lyceum/Hexane MSIL/Shark Uploading  |
| 559 | 2025094 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | startswith | `POST`, `q=`, `close`, `application/x-www-form-urlenco` | established,to_server | ET ADWARE_PUP Win32/Adware.Adposhel.A Checkin 5 |
| 6491 | 2032788 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.png`, `application/x-www-form-urlenco`, `&host=` | established,to_server | ET MALWARE Magecart/Skimmer - _try_action Exfil Attempt |
| 7053 | 2045751 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | — | `POST`, `.php`, `application|2f|x|2d|www|2d|for`, `id=` | established,to_server | ET MALWARE Win32/Amadey Bot Activity (POST) M2 |
| 7118 | 2047955 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | startswith | `POST`, `application/x-www-form-urlenco`, `Mozilla/5.0`, `WindowsPowerShell/` | established,to_server | ET MALWARE Red Wolf/RedCurl Payload Retrieval Attempt M1 |
| 7120 | 2047957 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | — | `POST`, `application/x-www-form-urlenco`, `Mozilla/5.0`, `WindowsPowerShell/` | established,to_server | ET MALWARE Red Wolf/RedCurl Payload Retrieval Attempt M3 |
| 7833 | 2032351 | 33 | `application/x-www-form-urlencoded` | POST | `http.user_agent` | — | `GET`, `.php?pub=mix`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE GCleaner Downloader Activity M3 |
| 8324 | 2029739 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco`, `&nk=` | established,to_server | ET MALWARE Win32/Milum CnC |
| 8357 | 2025441 | 33 | `application/x-www-form-urlencoded` | POST | `http.content_len` | — | `POST`, `keep-alive`, `application/x-www-form-urlenco`, `|0d 0a|Content-Type|0d 0a|Host` | established,to_server | ET MALWARE Sharik/Smoke CnC Beacon 10 |
| 8906 | 2022280 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco`, `HTTP/1.0` | established,to_server | ET MALWARE Win32/Nivdort Posting Data 1 |
| 8927 | 2018784 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | — | `POST`, `1=`, `2=`, `3=` | established,to_server | ET MALWARE Win32/Neurevt.A/Betabot Check-in 4 |
| 8969 | 2012627 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `Mozilla/4.0|20|(compatible|3b `, `*/*`, `application/x-www-form-urlenco`, `|0d 0a|Accept|0d 0a|Content-Ty` | established,to_server | ET MALWARE FakeAV Check-in purporting to be MSIE with invali |
| 9222 | 2025178 | 33 | `application/x-www-form-urlencoded` | POST | `http.content_len` | — | `POST`, `/`, `keep-alive`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE Sharik/Smoke CnC Beacon 9 |
| 9376 | 2023471 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | — | `application/x-www-form-urlenco` | established,to_server | ET MALWARE Possible Malicious Tor Module Download |
| 9751 | 2034579 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE AgentTesla Communicating with CnC Server |
| 9765 | 2046881 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco`, `Mozilla/88.0` | established,to_server | ET MALWARE Suspected Andariel RexPot CnC Checkin M1 |
| 9992 | 2030357 | 33 | `application/x-www-form-urlencoded` | POST | `http.accept` | — | `.php`, `Windows NT` | established,to_server | ET MALWARE Win32/Ispen BADNEWS CnC Beacon |
| 10164 | 2043997 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco`, `|0d 0a|accept|0d 0a|content-ty` | established,to_server | ET MALWARE PseudoManuscrypt Activity (POST) |
| 10177 | 2046156 | 33 | `application/x-www-form-urlencoded` | POST | `http.content_len` | — | `POST`, `/`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE Possible MEME#4CHAN Exfil Activity |
| 10192 | 2049416 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | startswith | `POST`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE Suspected ToddyCat APT Curlu Related Activity M1 |
| 10224 | 2033728 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `application/x-www-form-urlenco`, `&data=` | established,to_server | ET MALWARE Stealbit Variant Data Exfil M2 |
| 10378 | 2025598 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | — | `POST`, `/?id=`, `application/x-www-form-urlenco`, `|0d 0a|accept` | established,to_server | ET MALWARE Win32/AutoIt.NU Miner Dropper CnC Checkin |
| 10388 | 2025119 | 33 | `application/x-www-form-urlencoded` | POST | `http.content_len` | — | `POST`, `/`, `/`, `keep-alive` | established,to_server | ET MALWARE Sharik/Smoke CnC Beacon 7 |
| 10465 | 2023815 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco` | established,to_server | ET MALWARE Shafttt MySQL Bruteforce Bot CnC Beacon |
| 10481 | 2020734 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | — | `hl=`, `source=`, `aq=`, `aqi=` | established,to_server | ET MALWARE Fileless infection dropped by EK CnC Beacon |
| 10510 | 2047960 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | — | `POST`, `|0d 0a|Content-type|0d 0a|`, `application/x-www-form-urlenco`, `Mozilla/5.0` | established,to_server | ET MALWARE Red Wolf/RedCurl Payload Retrieval Attempt M6 |
| 10511 | 2047959 | 33 | `application/x-www-form-urlencoded` | POST | `http.uri` | startswith | `POST`, `|0d 0a|Content-type|0d 0a|`, `application/x-www-form-urlenco`, `Mozilla/5.0` | established,to_server | ET MALWARE Red Wolf/RedCurl Payload Retrieval Attempt M5 |
| 10515 | 2022281 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `.php`, `application/x-www-form-urlenco`, `HTTP/1.0` | established,to_server | ET MALWARE Win32/Nivdort Posting Data 2 |
| 10522 | 2052412 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | depth:3 | `POST`, `curl/`, `application/x-www-form-urlenco`, `&` | established,to_server | ET MALWARE Suspected APT42/TA453 TAMECAT Loader Related Acti |
| 10876 | 2026039 | 33 | `application/x-www-form-urlencoded` | POST | `http.request_body` | startswith | `POST`, `backup.php`, `application/x-www-form-urlenco`, `content-length|3a 20|` | established,to_server | ET MOBILE_MALWARE [PTsecurity] Spyware.BondPath (PathCall/Di |
| 7922 | 2038840 | 41 | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | GET | `http.user_agent` | — | — | established,to_server | ET MALWARE Brute Ratel Fake User-Agent |
