<h1>LimaCharlieEDR & Sliver C2 Lab</h1>

<h2>Description</h2>
Project consists of a simple PowerShell script that walks the user through "zeroing out" (wiping) any drives that are connected to the system. The utility allows you to select the target disk and choose the number of passes that are performed. The PowerShell script will configure a diskpart script file based on the user's selections and then launch Diskpart to perform the disk sanitization.
<br />

<h2>Languages and Utilities Used</h2>

- <b>Powershell</b> 
- <b>CMD</b>
- <b>Oracle VM VirtualBox</b>

<h2>Environments Used </h2>

- <b>Windows 11</b> (23H2)

<h2>Lab walk-through:</h2>

<p align="left">
1. Downloaded and installed a Windows VM. <br/>
2. Turned off Windows Defender permanently under Windows Settings. I used this guide to help turn it off permanently: https://windowsreport.com/disable-windows-defender-windows-11/ <br/>
<img src="https://github.com/user-attachments/assets/1f94c45e-e1ac-48db-a118-2cfb7cc0f008" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br />
<br />
<img src="https://github.com/user-attachments/assets/8f665669-653d-49b9-966c-d6c817caf100" height="80%" width="80%" alt="LimaCharlieEDR_Lab Steps"/> 
<br />
<br />
3.	Next, I went into the registry to update the Windows boot settings. I changed the start value of all these to ‘4’ (Disabled State):


Select the disk:  <br/>
<img src="https://i.imgur.com/tcTyMUE.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Enter the number of passes: <br/>
<img src="https://i.imgur.com/nCIbXbg.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Confirm your selection:  <br/>
<img src="https://i.imgur.com/cdFHBiU.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Wait for process to complete (may take some time):  <br/>
<img src="https://i.imgur.com/JL945Ga.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Sanitization complete:  <br/>
<img src="https://i.imgur.com/K71yaM2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Observe the wiped disk:  <br/>
<img src="https://i.imgur.com/AeZkvFQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
