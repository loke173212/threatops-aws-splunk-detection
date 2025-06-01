# ThreatOps Lab: Real-Time Detection Pipeline using AWS and Splunk

A hands-on cybersecurity project to simulate and detect SSH brute-force attacks in real time using AWS infrastructure and Splunk. This lab demonstrates a complete pipeline from cloud resource setup to log analysis and threat detection.

---

## 🛠 Phase 1: Infrastructure Setup (with Commands)

### ✅ EC2 Instance Setup (Amazon Linux 2023)

#### 1. Create Key Pair
```bash
aws ec2 create-key-pair   --key-name threatops-key   --query 'KeyMaterial'   --output text > threatops-key.pem

chmod 400 threatops-key.pem
```

#### 2. Create Security Group and Allow SSH
```bash
aws ec2 create-security-group   --group-name allow-ssh   --description "Allow SSH"

aws ec2 authorize-security-group-ingress   --group-name allow-ssh   --protocol tcp   --port 22   --cidr 0.0.0.0/0
```

#### 3. Launch EC2 Instance
```bash
aws ec2 run-instances   --image-id ami-0a0f1259dd1c90938 \  # Amazon Linux 2023 (ap-south-1)
  --count 1   --instance-type t2.micro   --key-name threatops-key   --security-groups allow-ssh
```

#### 4. SSH into the Instance
```bash
ssh -i "threatops-key.pem" ec2-user@<EC2_PUBLIC_IP>
```

---

### ✅ CloudWatch Agent Setup (Amazon Linux)

#### 1. Install and Enable rsyslog (if not available)
```bash
sudo yum install -y rsyslog
sudo systemctl enable --now rsyslog
```

#### 2. Install CloudWatch Agent
```bash
sudo yum install -y amazon-cloudwatch-agent
```

#### 3. Create Config File
Path: `/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json`
```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/secure",
            "log_group_name": "ThreatOpsEC2Logs",
            "log_stream_name": "{instance_id}/secure",
            "timestamp_format": "%b %d %H:%M:%S"
          }
        ]
      }
    }
  }
}
```

#### 4. Start CloudWatch Agent
```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl   -a fetch-config   -m ec2   -c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-config.json   -s
```

---

### ✅ Splunk HEC Configuration (Windows)

#### 1. Login to Splunk Web at `http://localhost:8000`

#### 2. Go to:
**Settings** → **Data Inputs** → **HTTP Event Collector**

#### 3. Steps:
- Click **New Token**
- **Name:** `ThreatOpsCloudWatch`
- Source type: `linux_secure`
- Index: `project` (or `main`)
- Leave port: `8088`
- Enable SSL if needed

#### 4. Save the **Token Value** (e.g., `cdcf73ab-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

---

### ✅ Tunneling Splunk HEC to the Internet (Cloudflared)

```powershell
cloudflared tunnel --url http://localhost:8088
```

Tunnel URL (example):
```
https://<cloudflare_link>
```

Use the HEC endpoint in Lambda:
```
https://<cloudflare_link>/services/collector
```

---

## 🧨 Phase 2: Attack Simulation

- Performed Hydra SSH brute-force attack from Kali Linux targeting EC2 public IP.

```bash
hydra -l <username> -P <path to password list> ssh://<ec2-public-ip>
```

- Simultaneously ran Nmap port scans to simulate noisy malicious behavior.

---

## 📦 Phase 3: Log Flow Architecture

### Architecture Diagram
![Architecture](screenshots/architecture.png)

### 🔹 EC2 Log Generation
- SSH attempts are logged in `/var/log/secure`.

### 🔹 CloudWatch Agent
- Installed via `.rpm` with custom `cloudwatch-config.json`.
- Streams logs from EC2 to CloudWatch log group in real time.

### 🔹 Lambda → Splunk
- Lambda triggered on new CloudWatch logs.
- Parses and forwards logs to Splunk via the tunneled HEC endpoint.
- Format used: `linux_secure` sourcetype for easy parsing in Splunk.

---

## 🔍 Phase 4: Log Analysis & Brute Force Detection in Splunk

### ✅ SPL Commands Used

#### Extracting High-Frequency IPs
```spl
index="project" sourcetype="linux_secure" action=REJECT
| stats count by srcaddr
| sort -count
```

#### Detecting Port Scanning (More than 20 unique ports)
```spl
index="project" sourcetype="_json" action=REJECT
| rex field=message "(?<dstport>\d{2,5})"
| stats dc(dstport) as unique_ports by srcaddr
| where unique_ports > 20
```

---

## 📸 Screenshots

### SSH Brute Force Source IP Detection
![Attack Detection](screenshots/attack%20detection.png)

### Login Outcome Pie Chart
![Pie Chart](screenshots/pie%20chart.png)

### Sample Log Events in Splunk
![Search Results](screenshots/Search.png)


## ✅ Results

- Identified the attacker's source IP address.
- Detected multiple failed attempts to SSH on port 22.
- Confirmed successful log ingestion and near real-time pipeline.

---

## 📌 Key Technologies

- AWS EC2, CloudWatch, Lambda
- Splunk HEC, Cloudflared
- Hydra, Nmap, Kali Linux

---

## 💡 Takeaways

- Built an end-to-end detection pipeline from scratch.
- Gained practical experience with log forwarding, real-time alerting, and SPL analysis.
- Simulated real-world brute-force attacks and validated detection effectiveness.

---

## ✅ Project Completion Summary

- ✅ Real-time SSH Attack Detection Implemented
- ✅ Logs Flowing from EC2 → CloudWatch → Lambda → Splunk
