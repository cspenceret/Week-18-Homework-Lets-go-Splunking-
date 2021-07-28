## Unit 18 Homework: Lets go Splunking!

### Scenario

You have just been hired as an SOC Analyst by Vandalay Industries, an importing and exporting company.
 
- Vandalay Industries uses Splunk for their security monitoring and have been experiencing a variety of security issues against their online systems over the past few months. 
 
- You are tasked with developing searches, custom reports and alerts to monitor Vandalay's security environment in order to protect them from future attacks.


### System Requirements 

You will be using the Splunk app located in the Ubuntu VM.


### Your Objective 

Utilize your Splunk skills to design a powerful monitoring solution to protect Vandaly from security attacks.

After you complete the assignment you are asked to provide the following:

- Screen shots where indicated.
- Custom report results where indicated.

### Topics Covered in This Assignment

- Researching and adding new apps
- Installing new apps
- Uploading files
- Splunk searching
- Using fields
- Custom reports
- Custom alerts

Let's get started!

---

## Vandalay Industries Monitoring Activity Instructions


### Step 1: The Need for Speed 

**Background**: As the worldwide leader of importing and exporting, Vandalay Industries has been the target of many adversaries attempting to disrupt their online business. Recently, Vandaly has been experiencing DDOS attacks against their web servers.

Not only were web servers taken offline by a DDOS attack, but upload and download speed were also significantly impacted after the outage. Your networking team provided results of a network speed run around the time of the latest DDOS attack.

**Task:** Create a report to determine the impact that the DDOS attack had on download and upload speed. Additionally, create an additional field to calculate the ratio of the upload speed to the download speed.


1.  Upload the following file of the system speeds around the time of the attack.
    - [Speed Test File](resources/server_speedtest.csv)

2. Using the `eval` command, create a field called `ratio` that shows the ratio between the upload and download speeds.
   - Hint: The format for creating a ratio is: `| eval new_field_name = 'fieldA'  / 'fieldB'`
      
3. Create a report using the Splunk's `table` command to display the following fields in a statistics report:
    - `_time`
    - `IP_ADDRESS`
    - `DOWNLOAD_MEGABITS`
    - `UPLOAD_MEGABITS`
    - `ratio`
  
   Hint: Use the following format when for the `table` command: `| table fieldA  fieldB fieldC`

4. Answer the following questions:

> EVAL Command:

`source="server_speedtest.csv" host="server_speedtest.csv_host" sourcetype="csv" | eval ratio='DOWNLOAD_MEGABITS'/'UPLOAD_MEGABITS'`

![EVAL Image](/Homework/Images/1_Eval-1.PNG)

> Speed Test Reort:

`source="server_speedtest.csv" host="server_speedtest.csv_host" sourcetype="csv" | eval ratio='DOWNLOAD_MEGABITS'/'UPLOAD_MEGABITS' | sort _time | table _time IP_ADDRESS UPLOAD_MEGABITS DOWNLOAD_MEGABITS ratio`

![Speed Test Image](/Homework/Images/1_Speed_Report-1.PNG)  

![Visualization Downtime](/Homework/Images/1_Reduced_speed_of_downloads.PNG)

    - Based on the report created, what is the approximate date and time of the attack?

> Answer: The attack took place on `02/23/2020` at `14:30`, where the download speed dropped dramatically down from `105.91Mbps` to `7.87 Mbps` and it lasted till `02/23/2020` at `23:30`, where the speed returned to normal over `122.91 Mbps`.


    - How long did it take your systems to recover?

> Answer: It took the system a total of `9 hours` to recover.  

---

### Step 2: Are We Vulnerable? 

**Background:**  Due to the frequency of attacks, your manager needs to be sure that sensitive customer data on their servers is not vulnerable. Since Vandalay uses Nessus vulnerability scanners, you have pulled the last 24 hours of scans to see if there are any critical vulnerabilities.

  - For more information on Nessus, read the following link: https://www.tenable.com/products/nessus

**Task:** Create a report determining how many critical vulnerabilities exist on the customer data server. Then, build an alert to notify your team if a critical vulnerability reappears on this server.

1. Upload the following file from the Nessus vulnerability scan.
   - [Nessus Scan Results](resources/nessus_logs.csv)

2. Create a report that shows the `count` of critical vulnerabilities from the customer database server.
   - The database server IP is `10.11.36.23`.
   - The field that identifies the level of vulnerabilities is `severity`.

> Answer: The Query Command:

- `source="nessus_logs.csv" host="nessus_logs_host" dest_ip="10.11.36.23" | eval CRITICAL=IF(severity="critical", "Critical", "Non-Critical") | stats count by CRITICAL`

![Database Critical Query](/Homework/Images/2_Database_Critical_Query.PNG)

> It appears that there are 49 critical database server vulnerabilities, and 194 Non-Critical as per the screenshot above (Database_Critical_Alert).  

      
3. Build an alert that monitors every day to see if this server has any critical vulnerabilities. If a vulnerability exists, have an alert emailed to `soc@vandalay.com`.

![Setting an Alert](/Homework/Images/2_Set_an_alert-1.PNG)
![Setting an Alert-2](/Homework/Images/2_Set_an_alert-2.PNG)  

![Database Critical Alert](/Homework/Images/2_Critical_Database_Server_Vulnerabilities_Alert.PNG)

---

### Step 3: Drawing the (base)line

**Background:**  A Vandaly server is also experiencing brute force attacks into their administrator account. Management would like you to set up monitoring to notify the SOC team if a brute force attack occurs again.


**Task:** Analyze administrator logs that document a brute force attack. Then, create a baseline of the ordinary amount of administrator bad logins and determine a threshold to indicate if a brute force attack is occurring.

1. Upload the administrator login logs.
   - [Admin Logins](resources/Administrator_logs.csv)

2. When did the brute force attack occur?
   - Hints:
     - Look for the `name` field to find failed logins.
     - Note the attack lasted several hours.

      
3. Determine a baseline of normal activity and a threshold that would alert if a brute force attack is occurring.

> By examining the `'name'` field for `"An account failed to log on"` I was able to determine the time of the attack, the baseline and the threshold...

> The brute force attack occurred from `9:00 a.m. until 2:00 p.m. on 2/21/2020` for a total of `5 hours`.

> Based on the logs, the the baseline is `5 to 35` logs an hour. The threshold will be set at `40 or more login attempts` in an hour and the alert will be sent to `SOC@vandalay.com` when triggered.

> The Query Command:

`source="Administrator_logs.csv" host="Administrator_logs_host" | stats count by name | sort -count | eval Bruteforce=if(name="An account failed to log on" AND count>5, "Potential Brute Force", "Not Brute Force")`

![Brute Force Failed Logins](/Homework/Images/3_Failed_Logins_Query.PNG)  
![Bar Chart Brute Forec Failed Logins](/Homework/Images/3_Bar_Chart_Failed_Logins_Query.PNG)  
![Baseline & Thershold](/Homework/Images/3_Baseline_and_threshold.PNG)

4. Design an alert to check the threshold every hour and email the SOC team at SOC@vandalay.com if triggered. 

![Brute Force Failed Logins Alert](/Homework/Images/3_Brute_Force_Failed_Logins_Alert.PNG)
 
---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.

---
  
## :sunglasses: `Ketan Vithal Patel` :sunglasses:  


### `July 12, 2021 -- UofT Cybersecurity - Boot Camp`
#### :rose::rose:`Jai Shri Swaminarayan`:rose::rose:
```
હરે કૃષ્ણ હરે કૃષ્ણ, કૃષ્ણ કૃષ્ણ હરે હરે |  Hare Krishna Hare Krishna, Krishna Krishna Hare Hare |
હરે રામ હરે રામ, રામ રામ હરે હરે ||   Hare Ram Hare Ram, Ram Ram Hare Hare ||
```
---  
