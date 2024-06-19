# badmoodle-scan
Сканування системи дистанційного навчання ДУІТЗ за допомогою ПЗ Badmoodle 

$ ./badmoodle.py -u e-learning.suitt.edu.ua -l 2                      

Moodle community-based vulnerability scanner[v0.2] 
by cyberaz0r

Legal disclaimer
Usage of badmoodle for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[*] Starting scan in URL "http://e-learning.suitt.edu.ua"
[+] Moodle version: v3.4
[+] Moodle specific version: v3.4.1

[*] Checking for official vulnerabilities from vulnerability database

[+] Found Vulnerability
MSA-24-0020: ReCAPTCHA can be bypassed on the login page
CVEs: CVE-2024-34009
Versions affected: 4.3 to 4.3.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840925

[+] Found Vulnerability
MSA-24-0019: CSRF risk in analytics management of models
CVEs: CVE-2024-34008
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840924

[+] Found Vulnerability
MSA-24-0018: Logout CSRF in admin/tool/mfa/auth.php
CVEs: CVE-2024-34007
Versions affected: 4.3 to 4.3.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840923

[+] Found Vulnerability
MSA-24-0017: Unsanitized HTML in site log for config_log_created
CVEs: CVE-2024-34006
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840922

[+] Found Vulnerability
MSA-24-0016: Authenticated LFI risk in some misconfigured shared hosting environments via modified mod_data backup
CVEs: CVE-2024-34005
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840921

[+] Found Vulnerability
MSA-24-0015: Authenticated LFI risk in some misconfigured shared hosting environments via modified mod_wiki backup
CVEs: CVE-2024-34004
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840919

[+] Found Vulnerability
MSA-24-0014: Authenticated LFI risk in some misconfigured shared hosting environments via modified mod_workshop backup
CVEs: CVE-2024-34003
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840917

[+] Found Vulnerability
MSA-24-0013: Authenticated LFI risk in some misconfigured shared hosting environments via modified mod_feedback backup
CVEs: CVE-2024-34002
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840916

[+] Found Vulnerability
MSA-24-0012: CSRF risk in admin preset tool management of presets
CVEs: CVE-2024-34001
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840915

[+] Found Vulnerability
MSA-24-0011: Stored XSS in lesson overview report via user ID number
CVEs: CVE-2024-34000
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=0#p1840914

[+] Found Vulnerability
MSA-24-0010: Unsafe direct use of $_SERVER['HTTP_REFERER'] in admin/tool/mfa/index.php
CVEs: CVE-2024-33999
Versions affected: 4.3 to 4.3.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1840913

[+] Found Vulnerability
MSA-24-0009: Stored XSS via user's name on participants page when opening some options
CVEs: CVE-2024-33998
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1840911

[+] Found Vulnerability
MSA-24-0008: Stored XSS risk when editing another user's equation in equation editor
CVEs: CVE-2024-33997
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1840910

[+] Found Vulnerability
MSA-24-0007: Broken access control when setting calendar event type
CVEs: CVE-2024-33996
Versions affected: 4.0 to 4.3.3, 4.2 to 4.2.6, 4.1 to 4.1.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1840909

[+] Found Vulnerability
MSA-24-0006: IDOR on dashboard comments block
CVEs: CVE-2024-25983
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830390

[+] Found Vulnerability
MSA-24-0005: CSRF risk in Language import utility
CVEs: CVE-2024-25982
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830382

[+] Found Vulnerability
MSA-24-0004: Forum export did not respect activity group settings
CVEs: CVE-2024-25981
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830381

[+] Found Vulnerability
MSA-24-0003: H5P attempts report did not respect activity group settings
CVEs: CVE-2024-25980
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830380

[+] Found Vulnerability
MSA-24-0002: Forum search accepted random parameters in its URL
CVEs: CVE-2024-25979
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830378

[+] Found Vulnerability
MSA-24-0001: Denial of service risk in file picker unzip functionality
CVEs: CVE-2024-25978
Versions affected: 4.3 to 4.3.2, 4.2 to 4.2.5, 4.1 to 4.1.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=1#p1830376

[+] Found Vulnerability
MSA-23-0053: Reflected XSS risk on ad-hoc tasks page
CVEs: CVE-2023-6670
Versions affected: 4.3 and 4.2 to 4.2.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823295

[+] Found Vulnerability
MSA-23-0052: XSS risk when manually running a task in the admin UI
CVEs: CVE-2023-6669
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823294

[+] Found Vulnerability
MSA-23-0051: Badge recipients are available to all users
CVEs: CVE-2023-6668
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823293

[+] Found Vulnerability
MSA-23-0050: Survey responses did not respect group settings
CVEs: CVE-2023-6667
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823292

[+] Found Vulnerability
MSA-23-0049: Reflected XSS risk in grader report search
CVEs: CVE-2023-6666
Versions affected: 4.3 and 4.2 to 4.2.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823290

[+] Found Vulnerability
MSA-23-0048: Stored XSS in grader report via user ID number
CVEs: CVE-2023-6665
Versions affected: 4.3 and 4.2 to 4.2.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823289

[+] Found Vulnerability
MSA-23-0047: Logs and Live logs course reports did not respect activity group settings
CVEs: CVE-2023-6664
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823288

[+] Found Vulnerability
MSA-23-0046: Authenticated remote code execution risk in course blocks
CVEs: CVE-2023-6663
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823287

[+] Found Vulnerability
MSA-23-0045: DOS risk in URL downloader
CVEs: CVE-2023-6662
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823286

[+] Found Vulnerability
MSA-23-0044: Authenticated remote code execution risk in logstore as manager
CVEs: CVE-2023-6661
Versions affected: 4.3, 4.2 to 4.2.3, 4.1 to 4.1.6, 4.0 to 4.0.11, 3.11 to 3.11.17, 3.9 to 3.9.24 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=2#p1823285

[+] Found Vulnerability
MSA-23-0043: Forum summary report shows students from other groups when in Separate Groups mode
CVEs: CVE-2023-5551
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814901

[+] Found Vulnerability
MSA-23-0042: RCE due to LFI risk in some misconfigured shared hosting environments
CVEs: CVE-2023-5550
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814899

[+] Found Vulnerability
MSA-23-0041: Insufficient capability checks when updating the parent of a course category
CVEs: CVE-2023-5549
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814898

[+] Found Vulnerability
MSA-23-0040: Make file serving endpoints revision control stricter
CVEs: CVE-2023-5548
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814897

[+] Found Vulnerability
MSA-23-0039: XSS risk when previewing data in course upload tool
CVEs: CVE-2023-5547
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814896

[+] Found Vulnerability
MSA-23-0038: Stored XSS in quiz grading report via user ID number
CVEs: CVE-2023-5546
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5 and 4.0 to 4.0.10
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814895

[+] Found Vulnerability
MSA-23-0037: Auto-populated H5P author name causes a potential information leak
CVEs: CVE-2023-5545
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814894

[+] Found Vulnerability
MSA-23-0036: Stored XSS and potential IDOR risk in Wiki comments
CVEs: CVE-2023-5544
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814893

[+] Found Vulnerability
MSA-23-0035: Duplicating a BigBlueButton activity assigns the same meeting ID
CVEs: CVE-2023-5543
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5 and 4.0 to 4.0.10
Link to advisory: https://moodle.org/security/index.php?o=3&p=3#p1814892

[+] Found Vulnerability
MSA-23-0033: XSS risk when using CSV grade import method
CVEs: CVE-2023-5541
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1814890

[+] Found Vulnerability
MSA-23-0032: Authenticated remote code execution risk in IMSCP
CVEs: CVE-2023-5540
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1814888

[+] Found Vulnerability
MSA-23-0031: Authenticated remote code execution risk in Lesson
CVEs: CVE-2023-5539
Versions affected: 4.2 to 4.2.2, 4.1 to 4.1.5, 4.0 to 4.0.10, 3.11 to 3.11.16, 3.9 to 3.9.23 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1814887

[+] Found Vulnerability
MSA-23-0030: Quiz sequential navigation bypass possible
CVEs: CVE-2023-40325
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807056

[+] Found Vulnerability
MSA-23-0029: Competency framework tools are not restricted as intended
CVEs: CVE-2023-40324
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807055

[+] Found Vulnerability
MSA-23-0028: Open redirect risk on admin view all policies page
CVEs: CVE-2023-40323
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807054

[+] Found Vulnerability
MSA-23-0027: JQuery UI library upgraded to 1.13.2 (upstream)
CVEs: CVE-2022-31160,, CVE-2021-41184,, CVE-2021-41183, CVE-2021-41182
Versions affected: 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807053

[+] Found Vulnerability
MSA-23-0026: IDOR in message processor fragments allows fetching of other users' data
CVEs: CVE-2023-40322
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807051

[+] Found Vulnerability
MSA-23-0025: phpCAS library upgraded to 1.6.0 (upstream)
CVEs: CVE-2022-39369
Versions affected: 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807050

[+] Found Vulnerability
MSA-23-0024: Private course participant data available from external grade report method
CVEs: CVE-2023-40321
Versions affected: 4.2 to 4.2.1
Link to advisory: https://moodle.org/security/index.php?o=3&p=4#p1807049

[+] Found Vulnerability
MSA-23-0023: Stored self-XSS escalated to stored XSS via OAuth 2 login
CVEs: CVE-2023-40320
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1807048

[+] Found Vulnerability
MSA-23-0022: SQL injection risk in grader report sorting
CVEs: CVE-2023-40319
Versions affected: 4.2 to 4.2.1
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1807045

[+] Found Vulnerability
MSA-23-0021: Some block permissions on Dashboard not respected
CVEs: CVE-2023-40318
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1807044

[+] Found Vulnerability
MSA-23-0020: Remote code execution risk when parsing malformed file repository reference
CVEs: CVE-2023-40317
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1807043

[+] Found Vulnerability
MSA-23-0019: Proxy bypass risk due to insufficient validation
CVEs: CVE-2023-40316
Versions affected: 4.2 to 4.2.1, 4.1 to 4.1.4, 4.0 to 4.0.9, 3.11 to 3.11.15, 3.9 to 3.9.22 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1807042

[+] Found Vulnerability
MSA-23-0018: SSRF risk due to insufficient check on the cURL blocked hosts list
CVEs: CVE-2023-35133
Versions affected: 4.2, 4.1 to 4.1.3, 4.0 to 4.0.8, 3.11 to 3.11.14, 3.9 to 3.9.21 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1799656

[+] Found Vulnerability
MSA-23-0017: Minor SQL injection risk on Mnet SSO access control page
CVEs: CVE-2023-35132
Versions affected: 4.2, 4.1 to 4.1.3, 4.0 to 4.0.8, 3.11 to 3.11.14, 3.9 to 3.9.21 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1799654

[+] Found Vulnerability
MSA-23-0016: XSS risk on groups page
CVEs: CVE-2023-35131
Versions affected: 4.2, 4.1 to 4.1.3, 4.0 to 4.0.8 and 3.11 to 3.11.14
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1799653

[+] Found Vulnerability
MSA-23-0015: Minor SQL injection risk in external Wiki method for listing pages
CVEs: CVE-2023-30944
Versions affected: 4.1 to 4.1.2, 4.0 to 4.0.7, 3.11 to 3.11.13, 3.9 to 3.9.20 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1793614

[+] Found Vulnerability
MSA-23-0014: TinyMCE loaders susceptible to Arbitrary Folder Creation
CVEs: CVE-2023-30943
Versions affected: 4.1 to 4.1.2
Link to advisory: https://moodle.org/security/index.php?o=3&p=5#p1793613

[+] Found Vulnerability
MSA-23-0013: XSS risk in TinyMCE alerts (upstream)
CVEs: CVE-2022-23494
Versions affected: 4.1 to 4.1.1
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788903

[+] Found Vulnerability
MSA-23-0012: Course participation report shows roles the user should not see
CVEs: CVE-2023-1402
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788902

[+] Found Vulnerability
MSA-23-0011: Teacher can access names of users they do not have permission to access
CVEs: CVE-2023-28336
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788901

[+] Found Vulnerability
MSA-23-0010: CSRF risk in resetting all templates of a database activity
CVEs: CVE-2023-28335
Versions affected: 4.1 to 4.1.1
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788900

[+] Found Vulnerability
MSA-23-0009: Users' name enumeration possible via IDOR on learning plans page
CVEs: CVE-2023-28334
Versions affected: 4.1 to 4.1.1 and 4.0 to 4.0.6
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788899

[+] Found Vulnerability
MSA-23-0008: Pix helper potential Mustache code injection risk
CVEs: CVE-2023-28333
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788898

[+] Found Vulnerability
MSA-23-0007: Algebra filter XSS when filter is misconfigured
CVEs: CVE-2023-28332
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788897

[+] Found Vulnerability
MSA-23-0006: XSS risk when outputting database activity filter data
CVEs: CVE-2023-28331
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788896

[+] Found Vulnerability
MSA-23-0005: Authenticated arbitrary file read through malformed backup file
CVEs: CVE-2023-28330
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788895

[+] Found Vulnerability
MSA-23-0004: Authenticated SQL injection via availability check
CVEs: CVE-2023-28329
Versions affected: 4.1 to 4.1.1, 4.0 to 4.0.6, 3.11 to 3.11.12, 3.9 to 3.9.19 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=6#p1788894

[+] Found Vulnerability
MSA-23-0003: Possible to set the preferred "start page" of other users
CVEs: CVE-2023-23923
Versions affected: 4.1, 4.0 to 4.0.5, 3.11 to 3.11.11, 3.9 to 3.9.18 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1782023

[+] Found Vulnerability
MSA-23-0002: Reflected XSS risk in blog search
CVEs: CVE-2023-23922
Versions affected: 4.1 and 4.0 to 4.0.5
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1782022

[+] Found Vulnerability
MSA-23-0001: Reflected XSS risk in some returnurl parameters
CVEs: CVE-2023-23921
Versions affected: 4.1, 4.0 to 4.0.5, 3.11 to 3.11.11, 3.9 to 3.9.18 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1782021

[+] Found Vulnerability
MSA-22-0032: Blind SSRF risk in LTI provider library
CVEs: CVE-2022-45152
Versions affected: 4.0 to 4.0.4, 3.11 to 3.11.10, 3.9 to 3.9.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1773540

[+] Found Vulnerability
MSA-22-0031: Stored XSS possible in some "social" user profile fields
CVEs: CVE-2022-45151
Versions affected: 4.0 to 4.0.4 and 3.11 to 3.11.10
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1773539

[+] Found Vulnerability
MSA-22-0030: Reflected XSS risk in policy tool
CVEs: CVE-2022-45150
Versions affected: 4.0 to 4.0.4, 3.11 to 3.11.10, 3.9 to 3.9.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1773538

[+] Found Vulnerability
MSA-22-0029: Course restore - CSRF token passed in course redirect URL
CVEs: CVE-2022-45149
Versions affected: 4.0 to 4.0.4, 3.11 to 3.11.10, 3.9 to 3.9.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1773537

[+] Found Vulnerability
MSA-22-0028: Apply upstream security fix to VideoJS library to remove XSS risk
CVEs: CVE-2021-23414
Versions affected: 3.11 to 3.11.10, 3.9 to 3.9.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1773535

[+] Found Vulnerability
MSA-22-0027: Quiz sequential navigation bypass using web services
CVEs: CVE-2022-40208
Versions affected: 4.0 to 4.0.2, 3.11 to 3.11.8, 3.9 to 3.9.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1766080

[+] Found Vulnerability
MSA-22-0026: No groups filtering in H5P activity attempts report
CVEs: CVE-2022-40316
Versions affected: 4.0 to 4.0.3, 3.11 to 3.11.9, 3.9 to 3.9.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=7#p1764796

[+] Found Vulnerability
MSA-22-0025: Minor SQL injection risk in admin user browsing
CVEs: CVE-2022-40315
Versions affected: 4.0 to 4.0.3, 3.11 to 3.11.9, 3.9 to 3.9.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1764795

[+] Found Vulnerability
MSA-22-0024: Remote code execution risk when restoring malformed backup file from Moodle 1.9
CVEs: CVE-2022-40314
Versions affected: 4.0 to 4.0.3, 3.11 to 3.11.9, 3.9 to 3.9.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1764794

[+] Found Vulnerability
MSA-22-0023: Stored XSS and page denial of service risks due to recursive rendering in Mustache template helpers
CVEs: CVE-2022-40313
Versions affected: 4.0 to 4.0.3, 3.11 to 3.11.9, 3.9 to 3.9.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1764793

[+] Found Vulnerability
MSA-22-0022: CSRF risk in enabling/disabling installed H5P libraries
CVEs: CVE-2022-2986
Versions affected: 4.0 to 4.0.2 and 3.11 to 3.11.8
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1761482

[+] Found Vulnerability
MSA-22-0021: Upgrade Mustache to latest version (upstream)
CVEs: CVE-2022-0323
Versions affected: 4.0 to 4.0.2, 3.11 to 3.11.8, 3.9 to 3.9.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1761481

[+] Found Vulnerability
MSA-22-0020: Upgrade moodle-mlbackend-python and update its reference in /lib/mlbackend/python/classes/processor.php (upstream)
CVEs: N/A
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1756389

[+] Found Vulnerability
MSA-22-0019: LTI module reflected XSS risk - affecting unauthenticated users only
CVEs: CVE-2022-35653
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1756388

[+] Found Vulnerability
MSA-22-0018: Open redirect risk in mobile auto-login feature
CVEs: CVE-2022-35652
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1756387

[+] Found Vulnerability
MSA-22-0017: Stored XSS and blind SSRF possible via SCORM track details
CVEs: CVE-2022-35651
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1756386

[+] Found Vulnerability
MSA-22-0016: Arbitrary file read when importing lesson questions
CVEs: CVE-2022-35650
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=8#p1756385

[+] Found Vulnerability
MSA-22-0015: PostScript Code Injection / Remote code execution risk
CVEs: CVE-2022-35649
Versions affected: 4.0 to 4.0.1, 3.11 to 3.11.7, 3.9 to 3.9.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1756382

[+] Found Vulnerability
MSA-22-0014: Failed login attempts counted incorrectly
CVEs: CVE-2022-30600
Versions affected: 4.0, 3.11 to 3.11.6, 3.10 to 3.10.10, 3.9 to 3.9.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1748726

[+] Found Vulnerability
MSA-22-0013: SQL injection risk in badge award criteria
CVEs: CVE-2022-30599
Versions affected: 4.0, 3.11 to 3.11.6, 3.10 to 3.10.10, 3.9 to 3.9.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1748725

[+] Found Vulnerability
MSA-22-0012: Global search results reveal authors of content unexpectedly for some activities
CVEs: CVE-2022-30598
Versions affected: 4.0, 3.11 to 3.11.6, 3.10 to 3.10.10, 3.9 to 3.9.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1748724

[+] Found Vulnerability
MSA-22-0011: Description field hidden by user policies (hiddenuserfields) is still visible
CVEs: CVE-2022-30597
Versions affected: 4.0, 3.11 to 3.11.6, 3.10 to 3.10.10, 3.9 to 3.9.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1748723

[+] Found Vulnerability
MSA-22-0010: Stored XSS in assignment bulk marker allocation form via user ID number
CVEs: CVE-2022-30596
Versions affected: 4.0, 3.11 to 3.11.6, 3.10 to 3.10.10, 3.9 to 3.9.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1748722

[+] Found Vulnerability
MSA-22-0009: Upgrade CKEditor included in h5p-editor-php-library to latest version (upstream)
CVEs: N/A
Versions affected: 3.11 to 3.11.5, 3.10 to 3.10.9, 3.9 to 3.9.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1742078

[+] Found Vulnerability
MSA-22-0008: Upgrade PHPMailer to latest version (upstream)
CVEs: N/A
Versions affected: 3.11 to 3.11.5, 3.10 to 3.10.9, 3.9 to 3.9.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1742077

[+] Found Vulnerability
MSA-22-0007: Possible to reach the profile field badge criteria on a course page
CVEs: CVE-2022-0984
Versions affected: 3.11 to 3.11.5, 3.10 to 3.10.9, 3.9 to 3.9.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1742075

[+] Found Vulnerability
MSA-22-0006: Users with moodle/site:uploadusers but without moodle/user:delete could delete users
CVEs: CVE-2022-0985
Versions affected: 3.11 to 3.11.5, 3.10 to 3.10.9, 3.9 to 3.9.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=9#p1742074

[+] Found Vulnerability
MSA-22-0005: SQL injection risk in Badges criteria code
CVEs: CVE-2022-0983
Versions affected: 3.11 to 3.11.5, 3.10 to 3.10.9, 3.9 to 3.9.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1742073

[+] Found Vulnerability
MSA-22-0004: CSRF risk in badge alignment deletion
CVEs: CVE-2022-0335
Versions affected: 3.11 to 3.11.4, 3.10 to 3.10.8, 3.9 to 3.9.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1734817

[+] Found Vulnerability
MSA-22-0003: Capability gradereport/user:view not always respected when navigating to a user's course grade report
CVEs: CVE-2022-0334
Versions affected: 3.11 to 3.11.4, 3.10 to 3.10.8, 3.9 to 3.9.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1734816

[+] Found Vulnerability
MSA-22-0002: calendar:manageentries capability allows CRUD access to all calendar events
CVEs: CVE-2022-0333
Versions affected: 3.11 to 3.11.4, 3.10 to 3.10.8, 3.9 to 3.9.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1734814

[+] Found Vulnerability
MSA-22-0001: SQL injection risk in code fetching h5p activity user attempts
CVEs: CVE-2022-0332
Versions affected: 3.11 to 3.11.4
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1734813

[+] Found Vulnerability
MSA-21-0042: IDOR in a calendar web service allows fetching of other users' action events
CVEs: CVE-2021-43560
Versions affected: 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1726807

[+] Found Vulnerability
MSA-21-0041: CSRF risk on delete related badge feature
CVEs: CVE-2021-43559
Versions affected: 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1726805

[+] Found Vulnerability
MSA-21-0040: Reflected XSS in filetype admin tool
CVEs: CVE-2021-43558
Versions affected: 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1726802

[+] Found Vulnerability
MSA-21-0039: Upgrade moodle-mlbackend-python and update its reference in /lib/mlbackend/python/classes/processor.php (upstream)
CVEs: N/A
Versions affected: 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1726799

[+] Found Vulnerability
MSA-21-0038: Remote code execution risk when restoring malformed backup file
CVEs: CVE-2021-3943
Versions affected: 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=10#p1726798

[+] Found Vulnerability
MSA-21-0036: Quiz unreleased grade disclosure via web service
CVEs: CVE-2021-40695
Versions affected: 3.11 to 3.11.2, 3.10 to 3.10.6, 3.9 to 3.9.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1719329

[+] Found Vulnerability
MSA-21-0035: Arbitrary file read by site administrators via LaTeX preamble
CVEs: CVE-2021-40694
Versions affected: 3.11 to 3.11.2, 3.10 to 3.10.6, 3.9 to 3.9.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1719328

[+] Found Vulnerability
MSA-21-0034: Authentication bypass risk when using external database authentication
CVEs: CVE-2021-40693
Versions affected: 3.11 to 3.11.2, 3.10 to 3.10.6, 3.9 to 3.9.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1719327

[+] Found Vulnerability
MSA-21-0033: Course participants download did not restrict which users could be exported
CVEs: CVE-2021-40692
Versions affected: 3.11 to 3.11.2, 3.10 to 3.10.6, 3.9 to 3.9.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1719326

[+] Found Vulnerability
MSA-21-0032: Session Hijack risk when Shibboleth authentication is enabled
CVEs: CVE-2021-40691
Versions affected: 3.11 to 3.11.2, 3.10 to 3.10.6, 3.9 to 3.9.9 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1719325

[+] Found Vulnerability
MSA-21-0031: Messaging email notifications containing HTML may hide the final line of the email
CVEs: CVE-2021-36403
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1710828

[+] Found Vulnerability
MSA-21-0030: Insufficient escaping of users' names in account confirmation email
CVEs: CVE-2021-36402
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1710827

[+] Found Vulnerability
MSA-21-0029: Stored XSS when exporting to data formats supporting HTML via user ID number
CVEs: CVE-2021-36401
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1710826

[+] Found Vulnerability
MSA-21-0028: IDOR allows removal of other users' calendar URL subscriptions
CVEs: CVE-2021-36400
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=11#p1710825

[+] Found Vulnerability
MSA-21-0025: Messaging web service allows deletion of other users' messages
CVEs: CVE-2021-36397
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710822

[+] Found Vulnerability
MSA-21-0024: Blind SSRF possible against cURL blocked hosts via redirect
CVEs: CVE-2021-36396
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710821

[+] Found Vulnerability
MSA-21-0023: Recursion denial of service possible due to recursive cURL in file repository
CVEs: CVE-2021-36395
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710820

[+] Found Vulnerability
MSA-21-0022: Remote code execution risk when Shibboleth authentication is enabled
CVEs: CVE-2021-36394
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710818

[+] Found Vulnerability
MSA-21-0021: SQL injection risk in code fetching recent courses
CVEs: CVE-2021-36393
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710817

[+] Found Vulnerability
MSA-21-0020: SQL injection risk in code fetching enrolled courses
CVEs: CVE-2021-36392
Versions affected: 3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1710816

[+] Found Vulnerability
MSA-21-0019: Upgrade H5P PHP library to latest minor version (upstream)
CVEs: N/A
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6 and 3.8 to 3.8.8
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1701640

[+] Found Vulnerability
MSA-21-0018: Reflected XSS and open redirect in LTI authorization endpoint
CVEs: CVE-2021-32478
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1701639

[+] Found Vulnerability
MSA-21-0017: Last app access time is visible to non-site-admins on user profile page
CVEs: CVE-2021-32477
Versions affected: 3.10 to 3.10.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=12#p1701638

[+] Found Vulnerability
MSA-21-0016: Files API should mitigate denial-of-service risk when adding to the draft file area
CVEs: CVE-2021-32476
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, 3.5 to 3.5.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1701635

[+] Found Vulnerability
MSA-21-0015: Stored XSS in quiz grading report via user ID number
CVEs: CVE-2021-32475
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, 3.5 to 3.5.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1701633

[+] Found Vulnerability
MSA-21-0014: Blind SQL injection possible via MNet authentication
CVEs: CVE-2021-32474
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, 3.5 to 3.5.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1701632

[+] Found Vulnerability
MSA-21-0013: Quiz unreleased grade disclosure via web service
CVEs: CVE-2021-32473
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6, 3.8 to 3.8.8, 3.5 to 3.5.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1701631

[+] Found Vulnerability
MSA-21-0012: Forum CSV export could result in posts from all courses being exported
CVEs: CVE-2021-32472
Versions affected: 3.10 to 3.10.3, 3.9 to 3.9.6 and 3.8 to 3.8.8
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1701629

[+] Found Vulnerability
MSA-21-0011: JQuery versions below 3.5.0 contain some potential vulnerabilities (upstream)
CVEs: CVE-2020-11022, CVE-2020-11023
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1691274

[+] Found Vulnerability
MSA-21-0010: Fetching a user's enrolled courses via web services did not check profile access in each course
CVEs: CVE-2021-20283
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1691273

[+] Found Vulnerability
MSA-21-0009: Bypass email verification secret when confirming account registration
CVEs: CVE-2021-20282
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1691269

[+] Found Vulnerability
MSA-21-0008: User full name disclosure within online users block
CVEs: CVE-2021-20281
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1691268

[+] Found Vulnerability
MSA-21-0007: Stored XSS and blind SSRF possible via feedback answer text
CVEs: CVE-2021-20280
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=13#p1691260

[+] Found Vulnerability
MSA-21-0006: Stored XSS via ID number user profile field
CVEs: CVE-2021-20279
Versions affected: 3.10 to 3.10.1, 3.9 to 3.9.4, 3.8 to 3.8.7, 3.5 to 3.5.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1691259

[+] Found Vulnerability
MSA-21-0005: Arbitrary PHP code execution by site admins via Shibboleth configuration
CVEs: CVE-2021-20187
Versions affected: 3.10, 3.9 to 3.9.3, 3.8 to 3.8.6, 3.5 to 3.5.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1680847

[+] Found Vulnerability
MSA-21-0004: Stored XSS possible via TeX notation filter
CVEs: CVE-2021-20186
Versions affected: 3.10, 3.9 to 3.9.3, 3.8 to 3.8.6, 3.5 to 3.5.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1680845

[+] Found Vulnerability
MSA-21-0003: Client side denial of service via personal message
CVEs: CVE-2021-20185
Versions affected: 3.10, 3.9 to 3.9.3, 3.8 to 3.8.6, 3.5 to 3.5.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1680841

[+] Found Vulnerability
MSA-21-0002: Grade information disclosure in grade's external fetch functions
CVEs: CVE-2021-20184
Versions affected: 3.10, 3.9 to 3.9.3, 3.8 to 3.8.6
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1680839

[+] Found Vulnerability
MSA-20-0021: The participants table download feature did not respect the site's "show user identity" configuration
CVEs: CVE-2020-25703
Versions affected: 3.9 to 3.9.2, 3.8 to 3.8.5 and 3.7 to 3.7.8
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1668777

[+] Found Vulnerability
MSA-20-0020: Stored XSS possible when renaming content bank items
CVEs: CVE-2020-25702
Versions affected: 3.9 to 3.9.2
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1668775

[+] Found Vulnerability
MSA-20-0019: tool_uploadcourse creates new enrol instances unexpectedly in some circumstances
CVEs: CVE-2020-25701
Versions affected: 3.9 to 3.9.2, 3.8 to 3.8.5, 3.7 to 3.7.8 and 3.5 to 3.5.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1668774

[+] Found Vulnerability
MSA-20-0018: Some database module web services did not respect group settings
CVEs: CVE-2020-25700
Versions affected: 3.9 to 3.9.2, 3.8 to 3.8.5, 3.7 to 3.7.8, 3.5 to 3.5.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=14#p1668773

[+] Found Vulnerability
MSA-20-0017: Privilege escalation within a course when restoring role overrides
CVEs: CVE-2020-25699
Versions affected: 3.9 to 3.9.2, 3.8 to 3.8.5, 3.7 to 3.7.8, 3.5 to 3.5.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1668771

[+] Found Vulnerability
MSA-20-0016: Teacher is able to unenrol users without permission using course restore
CVEs: CVE-2020-25698
Versions affected: 3.9 to 3.9.2, 3.8 to 3.8.5, 3.7 to 3.7.8, 3.5 to 3.5.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1668770

[+] Found Vulnerability
MSA-20-0015: Chapter name in book not always escaped with forceclean enabled
CVEs: CVE-2020-25631
Versions affected: 3.9 to 3.9.1, 3.8 to 3.8.4 and 3.7 to 3.7.7
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1657005

[+] Found Vulnerability
MSA-20-0014: Denial of service risk in file picker unzip functionality
CVEs: CVE-2020-25630
Versions affected: 3.9 to 3.9.1, 3.8 to 3.8.4, 3.7 to 3.7.7, 3.5 to 3.5.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1657004

[+] Found Vulnerability
MSA-20-0013: "Log in as" capability in a course context may lead to some privilege escalation
CVEs: CVE-2020-25629
Versions affected: 3.9 to 3.9.1, 3.8 to 3.8.4, 3.7 to 3.7.7, 3.5 to 3.5.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1657003

[+] Found Vulnerability
MSA-20-0012: Reflected XSS in tag manager
CVEs: CVE-2020-25628
Versions affected: 3.9 to 3.9.1, 3.8 to 3.8.4, 3.7 to 3.7.7, 3.5 to 3.5.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1657002

[+] Found Vulnerability
MSA-20-0011: Stored XSS via moodlenetprofile parameter in user profile
CVEs: CVE-2020-25627
Versions affected: 3.9 to 3.9.1
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1657001

[+] Found Vulnerability
MSA-20-0010: yui_combo should mitigate denial of service risk
CVEs: CVE-2020-14322
Versions affected: 3.9, 3.8 to 3.8.3, 3.7 to 3.7.6, 3.5 to 3.5.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1644269

[+] Found Vulnerability
MSA-20-0009: Course enrolments allowed privilege escalation from teacher role into manager role
CVEs: CVE-2020-14321
Versions affected: 3.9, 3.8 to 3.8.3, 3.7 to 3.7.6, 3.5 to 3.5.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1644268

[+] Found Vulnerability
MSA-20-0008: Reflected XSS in admin task logs filter
CVEs: CVE-2020-14320
Versions affected: 3.9, 3.8 to 3.8.3 and 3.7 to 3.7.6
Link to advisory: https://moodle.org/security/index.php?o=3&p=15#p1644267

[+] Found Vulnerability
MSA-20-0007: Vulnerable JavaScript libraries: jQuery 1.9.1 (upstream)
CVEs: CVE-2019-11358
Versions affected: 3.8 to 3.8.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1644266

[+] Found Vulnerability
MSA-20-0006: Remote code execution possible via SCORM packages
CVEs: CVE-2020-10738
Versions affected: 3.8 to 3.8.2, 3.7 to 3.7.5, 3.6 to 3.6.9, 3.5 to 3.5.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1628593

[+] Found Vulnerability
MSA-20-0005: MathJax URL upgraded to later version to remove XSS risk (upstream)
CVEs: CVE-2018-1999024
Versions affected: 3.8 to 3.8.2, 3.7 to 3.7.5, 3.6 to 3.6.9, 3.5 to 3.5.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1628590

[+] Found Vulnerability
MSA-20-0004: Admin PHP unit webrunner tool requires additional input escaping
CVEs: CVE-2020-1756
Versions affected: 3.8 to 3.8.1, 3.7 to 3.7.4, 3.6 to 3.6.8, 3.5 to 3.5.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1606856

[+] Found Vulnerability
MSA-20-0003: IP addresses can be spoofed using X-Forwarded-For
CVEs: CVE-2020-1755
Versions affected: 3.8 to 3.8.1, 3.7 to 3.7.4, 3.6 to 3.6.8, 3.5 to 3.5.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1606855

[+] Found Vulnerability
MSA-20-0002: Grade history report does not respect Separate groups mode in the course settings
CVEs: CVE-2020-1754
Versions affected: 3.8 to 3.8.1, 3.7 to 3.7.4, 3.6 to 3.6.8, 3.5 to 3.5.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1606854

[+] Found Vulnerability
MSA-19-0029: Reflected XSS possible from some fatal error messages
CVEs: CVE-2019-14884
Versions affected: 3.7 to 3.7.2, 3.6 to 3.6.6, 3.5 to 3.5.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1586751

[+] Found Vulnerability
MSA-19-0028: Email media URL tokens were not checking for user status
CVEs: CVE-2019-14883
Versions affected: 3.7 to 3.7.2 and 3.6 to 3.6.6
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1586750

[+] Found Vulnerability
MSA-19-0027: Open redirect in Lesson edit page
CVEs: CVE-2019-14882
Versions affected: 3.7 to 3.7.2, 3.6 to 3.6.6, 3.5 to 3.5.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=16#p1586747

[+] Found Vulnerability
MSA-19-0026: Blind XSS reflected in some locations where user email is displayed
CVEs: CVE-2019-14881
Versions affected: 3.7 to 3.7.2
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1586746

[+] Found Vulnerability
MSA-19-0025: Add additional verification for some OAuth 2 logins to prevent account compromise
CVEs: CVE-2019-14880
Versions affected: 3.7 to 3.7.2, 3.6 to 3.6.6, 3.5 to 3.5.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1586744

[+] Found Vulnerability
MSA-19-0024: Assigned Role in Cohort did not un-assign on removal
CVEs: CVE-2019-14879
Versions affected: 3.7 to 3.7.2, 3.6 to 3.6.6, 3.5 to 3.5.8 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1586743

[+] Found Vulnerability
MSA-19-0023: Forum subscribe link contained an open redirect if forced subscription mode was enabled
CVEs: CVE-2019-14831
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5, 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576215

[+] Found Vulnerability
MSA-19-0022: Open redirect in the mobile launch endpoint could be used to expose mobile access tokens
CVEs: CVE-2019-14830
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5, 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576214

[+] Found Vulnerability
MSA-19-0021: Activity :addinstance capabilities were not respected when creating a course in single activity format
CVEs: CVE-2019-14829
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5, 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576213

[+] Found Vulnerability
MSA-19-0020: Python Machine Learning dependency versions bumped
CVEs: N/A
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5 and 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576208

[+] Found Vulnerability
MSA-19-0019: Course creation did not check the creator's role assignment capability before automatically assigning them as a teacher in the course
CVEs: CVE-2019-14828
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5, 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576205

[+] Found Vulnerability
MSA-19-0018: JavaScript injection possible in some Mustache templates via recursive rendering from contexts
CVEs: CVE-2019-14827
Versions affected: 3.7 to 3.7.1, 3.6 to 3.6.5, 3.5 to 3.5.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1576204

[+] Found Vulnerability
MSA-19-0017: Upgrade TCPDF library for PHP 7.3 and bug fixes (upstream)
CVEs: CVE-2018-17057
Versions affected: 3.7, 3.6 to 3.6.4, 3.5 to 3.5.6 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=17#p1566333

[+] Found Vulnerability
MSA-19-0016: Assignment group overrides did not observe separate groups mode
CVEs: CVE-2019-10189
Versions affected: 3.7, 3.6 to 3.6.4, 3.5 to 3.5.6 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1566332

[+] Found Vulnerability
MSA-19-0015: Quiz group overrides did not observe groups membership or accessallgroups
CVEs: CVE-2019-10188
Versions affected: 3.7, 3.6 to 3.6.4, 3.5 to 3.5.6 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1566331

[+] Found Vulnerability
MSA-19-0014: Ability to delete glossary entries that belong to another glossary
CVEs: CVE-2019-10187
Versions affected: 3.7, 3.6 to 3.6.4, 3.5 to 3.5.6 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1566330

[+] Found Vulnerability
MSA-19-0013: Missing sesskey (CSRF) token in loading/unloading XML files
CVEs: CVE-2019-10186
Versions affected: 3.7, 3.6 to 3.6.4, 3.5 to 3.5.6 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1566329

[+] Found Vulnerability
MSA-19-0012: Private files uploaded via incoming mail processing could bypass quota restrictions
CVEs: CVE-2019-10134
Versions affected: 3.6 to 3.6.3, 3.5 to 3.5.5, 3.4 to 3.4.8, 3.1 to 3.1.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1557998

[+] Found Vulnerability
MSA-19-0011: Open redirect in upload cohorts page
CVEs: CVE-2019-10133
Versions affected: 3.6 to 3.6.3, 3.5 to 3.5.5, 3.4 to 3.4.8, 3.1 to 3.1.17 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1557997

[+] Found Vulnerability
MSA-19-0010: All messaging conversations could be viewed
CVEs: CVE-2019-10154
Versions affected: 3.6 to 3.6.3
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1557995

[+] Found Vulnerability
MSA-19-0009: get_with_capability_join/get_users_by_capability not aware of context freezing
CVEs: CVE-2019-3852
Versions affected: 3.6 to 3.6.2
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1547748

[+] Found Vulnerability
MSA-19-0008: Secure layout contained an insecure link in Boost theme
CVEs: CVE-2019-3851
Versions affected: 3.6 to 3.6.2 and 3.5 to 3.5.4
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1547746

[+] Found Vulnerability
MSA-19-0007: Stored HTML in assignment submission comments allowed links to be opened directly
CVEs: CVE-2019-3850
Versions affected: 3.6 to 3.6.2, 3.5 to 3.5.4, 3.4 to 3.4.7, 3.1 to 3.1.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=18#p1547745

[+] Found Vulnerability
MSA-19-0006: Users could elevate their role when accessing the LTI tool on a provider site
CVEs: CVE-2019-3849
Versions affected: 3.6 to 3.6.2, 3.5 to 3.5.4, 3.4 to 3.4.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1547744

[+] Found Vulnerability
MSA-19-0005: Logged in users could view all calendar events
CVEs: CVE-2019-3848
Versions affected: 3.6 to 3.6.2, 3.5 to 3.5.4 and 3.4 to 3.4.7
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1547743

[+] Found Vulnerability
MSA-19-0004: "Log in as" functionality exposed to JavaScript risk on other users' Dashboards
CVEs: CVE-2019-3847
Versions affected: 3.6 to 3.6.2, 3.5 to 3.5.4, 3.4 to 3.4.7, 3.1 to 3.1.16 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1547742

[+] Found Vulnerability
MSA-19-0003: User full name is not escaped in the un-linked userpix page
CVEs: CVE-2019-3810
Versions affected: 3.6 to 3.6.1, 3.5 to 3.5.3, 3.4 to 3.4.6, 3.1 to 3.1.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1536767

[+] Found Vulnerability
MSA-19-0001: Manage groups capability is missing XSS risk flag
CVEs: CVE-2019-3808
Versions affected: 3.6 to 3.6.1, 3.5 to 3.5.3, 3.4 to 3.4.6, 3.1 to 3.1.15 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1536765

[+] Found Vulnerability
MSA-18-0020: Login CSRF vulnerability in login form
CVEs: CVE-2018-16854
Versions affected: 3.5 to 3.5.2, 3.4 to 3.4.5, 3.3 to 3.3.8, 3.1 to 3.1.14 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1527068

[+] Found Vulnerability
MSA-18-0019: Boost theme - blog search GET parameter insufficiently filtered
CVEs: CVE-2018-14631
Versions affected: 3.5 to 3.5.1, 3.4 to 3.4.4, 3.3 to 3.3.7 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1516120

[+] Found Vulnerability
MSA-18-0018: QuickForm library remote code vulnerability (upstream)
CVEs: CVE-2018-1999022
Versions affected: 3.5 to 3.5.1, 3.4 to 3.4.4, 3.3 to 3.3.7, 3.1 to 3.1.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1516119

[+] Found Vulnerability
MSA-18-0017: Moodle XML import of ddwtos could lead to intentional remote code execution
CVEs: CVE-2018-14630
Versions affected: 3.5 to 3.5.1, 3.4 to 3.4.4, 3.1 to 3.1.13 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=19#p1516118

[+] Found Vulnerability
MSA-18-0016: Quiz question bank import preview could execute JavaScript
CVEs: CVE-2018-10891
Versions affected: 3.5, 3.4 to 3.4.3, 3.3 to 3.3.6, 3.2 to 3.2.9, 3.1 to 3.1.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1505294

[+] Found Vulnerability
MSA-18-0015: Web service core_course_get_categories may return invisible categories
CVEs: CVE-2018-10890
Versions affected: 3.5, 3.4 to 3.4.3, 3.3 to 3.3.6, 3.2 to 3.2.9, 3.1 to 3.1.12 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1505293

[+] Found Vulnerability
MSA-18-0012: Portfolio script allows instantiation of class chosen by user
CVEs: CVE-2018-1137
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496358

[+] Found Vulnerability
MSA-18-0011: User who did not agree to the site policies can see the site homepage as if they had full site access
CVEs: N/A
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496357

[+] Found Vulnerability
MSA-18-0010: User can shift a block from Dashboard to any page
CVEs: CVE-2018-1136
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496356

[+] Found Vulnerability
MSA-18-0009: Portfolio forum caller class allows a user to download any file
CVEs: CVE-2018-1135
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496355

[+] Found Vulnerability
MSA-18-0008: Users can download any file via portfolio assignment caller class
CVEs: CVE-2018-1134
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496354

[+] Found Vulnerability
MSA-18-0007: Calculated question type allows remote code execution by Question authors
CVEs: CVE-2018-1133
Versions affected: 3.4 to 3.4.2, 3.3 to 3.3.5, 3.2 to 3.2.8, 3.1 to 3.1.11 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1496353

[+] Found Vulnerability
MSA-18-0006: Suspended users with OAuth 2 authentication method can still log in to the site
CVEs: CVE-2018-1082
Versions affected: 3.4 to 3.4.1, 3.3 to 3.3.4
Link to advisory: https://moodle.org/security/index.php?o=3&p=20#p1483859

[+] Found Vulnerability
MSA-18-0005: Unauthenticated users can trigger custom messages to admin via paypal enrol script
CVEs: CVE-2018-1081
Versions affected: 3.4 to 3.4.1, 3.3 to 3.3.4, 3.2 to 3.2.7, 3.1 to 3.1.10 and earlier unsupported versions
Link to advisory: https://moodle.org/security/index.php?o=3&p=21#p1483858

[*] Checking for community vulnerabilities from vulnerability modules

[+] Executing module for vulnerability "Atto Editor Stored XSS"
                                                                                                                
[-] Vulnerability "Atto Editor Stored XSS" requires authentication, skipping...

[-] Host not vulnerable to "Atto Editor Stored XSS" vulnerability

[+] Executing module for vulnerability "Open Redirect via Host Header in Bitnami Moodle's Apache"
                                                                                                                

[-] Host not vulnerable to "Open Redirect via Host Header in Bitnami Moodle's Apache" vulnerability

[+] Executing module for vulnerability "Dashboard Stored XSS"
                                                                                                                
[-] Vulnerability "Dashboard Stored XSS" requires authentication, skipping...

[-] Host not vulnerable to "Dashboard Stored XSS" vulnerability

[+] Scan completed
                                                                                                                
[-] No community vulnerabilities have been found in the scanned host

[+] Exiting from badmoodle
