# AWS Security Hub Insights for Amazon Inspector ECR Findings

## Problem Statement

### What Customer Challenge Does This Solve?

Organizations using Amazon Inspector to scan ECR container images face a critical challenge: **thousands of vulnerability findings with no efficient way to prioritize, track, or remediate them at scale**.

**Common Customer Pain Points:**

1. **Overwhelming Volume** - Production environments can generate 10,000+ vulnerability findings across hundreds of container images, making it impossible to know where to start

2. **No Prioritization Framework** - Without pre-built insights, security teams manually filter findings to identify:
   - Which images have the most critical vulnerabilities?
   - Which vulnerabilities are actively exploitable?
   - Which findings have been sitting unresolved for 30+ days?
   - Which production systems are at highest risk?

3. **Compliance Blind Spots** - Organizations struggle to demonstrate compliance posture (PCI-DSS, HIPAA, SOC2) without aggregated views of failed compliance checks

4. **Workflow Inefficiency** - Security teams lack visibility into remediation progress across NEW → NOTIFIED → RESOLVED workflow states

5. **Multi-Account/Multi-Region Complexity** - Enterprises with distributed architectures cannot easily aggregate vulnerability data across AWS accounts and regions

6. **Manual Insight Creation** - Creating custom Security Hub Insights manually is time-consuming, error-prone, and requires deep knowledge of Security Hub filter syntax

### How This Script Solves It

This automation **eliminates weeks of manual configuration** by instantly deploying 15 production-ready Security Hub Insights that provide:

- **Instant Risk Prioritization** - Immediately identify your highest-risk container images and exploitable vulnerabilities
- **Compliance Visibility** - Track compliance violations across regulatory frameworks in a single view
- **Remediation Tracking** - Monitor vulnerability aging and workflow progression to measure security team effectiveness
- **Executive Reporting** - Pre-built dashboards for CISO-level visibility into container security posture
- **Zero Configuration** - Works out-of-the-box with Amazon Inspector and Security Hub integration

**Time Savings:** What typically takes 4-6 hours of manual insight creation is reduced to a 2-minute automated deployment.

---

## Overview

This automated script creates 15 pre-configured Security Hub Insights for Amazon Inspector ECR container vulnerability findings. It provides comprehensive visibility into your container security posture across severity levels, compliance status, workflow states, and temporal patterns.

## Prerequisites

Before running this script, ensure the following services are enabled in your AWS account:

- ✅ **AWS Security Hub** - Must be enabled in the target region
- ✅ **Amazon Inspector** - Must be enabled with ECR scanning active
- ✅ **ECR Repositories** - Must contain container images being scanned
- ✅ **IAM Permissions** - Required permissions:
  - `securityhub:GetInsights`
  - `securityhub:CreateInsight`
  - `securityhub:DeleteInsight` (for cleanup on errors)

## Which AWS Account to Use

Run this script in the AWS account where:

- Amazon Inspector is actively scanning ECR repositories
- AWS Security Hub is enabled and receiving Inspector findings
- You want to create custom insights for vulnerability analysis

**Common Scenarios:**
- Production account with ECR repositories
- Security account aggregating findings from multiple accounts
- Development/staging account for testing Inspector integration

⚠️ **Do not run in accounts without Inspector ECR scanning enabled.**

## Installation & Execution

### Option 1: AWS CloudShell (Recommended)

AWS CloudShell provides a pre-configured environment with AWS CLI and automatically detects your region.

1. Log into the AWS Console in your target account
2. Open AWS CloudShell (top-right toolbar icon)
3. Upload the script:
   - Click **Actions** → **Upload file**
   - Select `sh_insight_inspector.sh`
4. Make the script executable:
   ```bash
   chmod +x sh_insight_inspector.sh
   ```
5. Run the script:
   ```bash
   ./sh_insight_inspector.sh
   ```

### Option 2: Local Terminal with AWS CLI

For local execution with AWS CLI configured:

1. Configure AWS CLI credentials:
   ```bash
   aws configure
   ```
   Or use a named profile:
   ```bash
   export AWS_PROFILE=your-profile-name
   ```

2. Make the script executable:
   ```bash
   chmod +x sh_insight_inspector.sh
   ```

3. Run the script:
   ```bash
   ./sh_insight_inspector.sh
   ```

4. Override region (optional):
   ```bash
   ./sh_insight_inspector.sh us-west-2
   ```

### Option 3: Direct Bash Execution

```bash
bash sh_insight_inspector.sh [optional-region]
```

## Region Detection

The script automatically detects the AWS region using the following priority:

1. **Script parameter** - Explicit region override: `./sh_insight_inspector.sh us-west-2`
2. **AWS_REGION environment variable** - Auto-set in CloudShell
3. **AWS CLI configuration** - From `aws configure get region`
4. **Default fallback** - `us-east-1`

## Script Execution Flow

1. **Display Prerequisites** - Shows red banners with account and prerequisite requirements
2. **Confirmation Prompt** - Requires typing `YES` (capital letters) to proceed
3. **Prerequisite Validation** - Verifies AWS CLI, credentials, Security Hub, Inspector, and IAM permissions
4. **Insight Creation** - Creates 15 insights with duplicate detection
5. **Summary Report** - Displays success/failure status and console links

## Created Insights

The script creates 15 insights organized into 7 categories:

### Severity Analysis
- **#1** - Findings by Severity: Overall risk distribution
- **#10** - HIGH Severity Findings: High-risk vulnerabilities
- **#11** - MEDIUM Severity Findings: Medium-risk vulnerabilities
- **#15** - CRITICAL + HIGH Combined: Priority remediation view

### Risk Prioritization
- **#2** - Images with Most Vulnerabilities: Identify worst offenders
- **#3** - Critical in Production: Business-critical systems (requires `Environment` tag)
- **#4** - Exploitable Vulnerabilities: Active threats with public exploits

### Workflow & Remediation Tracking
- **#5** - By Workflow Status: Monitor NEW → NOTIFIED → RESOLVED progression
- **#7** - Aging Findings (30+ days): Stale vulnerabilities needing escalation
- **#12** - Suppressed Findings: Accepted risks for audit purposes

### Environment Segmentation
- **#9** - By AWS Account: Multi-account visibility
- **#13** - By Region: Multi-region deployment tracking

### Compliance & Governance
- **#6** - Compliance Violations: Track PCI-DSS, HIPAA, SOC2 failures

### Temporal Analysis
- **#7** - Aging Findings: Vulnerabilities unresolved for 30+ days
- **#14** - Recently Updated: Findings updated in last 7 days

### Coverage Verification
- **#8** - By Resource Type: Ensure all ECR images are scanned

## Important Notes

### Tagging Requirements

**Insight #3** (Critical in Production) requires ECR repositories to be tagged with `Environment=production`:

```bash
aws ecr tag-resource \
  --resource-arn arn:aws:ecr:REGION:ACCOUNT:repository/REPO_NAME \
  --tags Key=Environment,Value=production
```

### Multi-Region Visibility

**Insight #13** (By Region) requires Security Hub aggregation to be enabled for cross-region visibility.

### Security Hub Limitations

The following filters are **NOT available** in Security Hub Insights and require direct Inspector API calls:

- **Network Reachability** - Cannot filter by network exposure
  ```bash
  aws inspector2 list-findings --filter-criteria \
    '{"networkReachability":[{"comparison":"EQUALS","value":"INTERNET"}]}'
  ```

- **Fix Available** - Cannot filter by fixable vulnerabilities
  ```bash
  aws inspector2 list-findings --filter-criteria \
    '{"fixAvailable":[{"comparison":"EQUALS","value":"YES"}]}'
  ```

## Script Features

- ✅ **Idempotent** - Safe to re-run; skips existing insights
- ✅ **Automatic Cleanup** - Rolls back created insights if script fails
- ✅ **Duplicate Detection** - Checks for existing insights before creation
- ✅ **Comprehensive Validation** - Verifies all prerequisites before execution
- ✅ **Error Handling** - Detailed error messages with remediation guidance
- ✅ **Region Auto-Detection** - Works seamlessly in CloudShell

## Viewing Insights

After successful execution, view your insights in the AWS Console:

```
https://console.aws.amazon.com/securityhub/home?region=REGION#/insights
```

Replace `REGION` with your AWS region (e.g., `us-east-1`).

## Troubleshooting

### Security Hub Not Enabled

**Error:** `Security Hub is not enabled in region: REGION`

**Solution:**
```bash
aws securityhub enable-security-hub --region REGION
```

Or enable via Console: [Security Hub Getting Started](https://console.aws.amazon.com/securityhub/home#/get-started)

### Inspector Not Enabled

**Error:** `Inspector may not be fully enabled`

**Solution:**
```bash
aws inspector2 enable --resource-types ECR --region REGION
```

### Missing IAM Permissions

**Error:** `Missing permission: securityhub:GetInsights`

**Solution:** Attach the following IAM policy to your user/role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetInsights",
        "securityhub:CreateInsight",
        "securityhub:DeleteInsight"
      ],
      "Resource": "*"
    }
  ]
}
```

### Insight Already Exists

**Warning:** `Insight already exists: INSIGHT_NAME`

This is expected behavior. The script skips existing insights and displays their ARN. No action required.

### Maximum Insights Reached

**Error:** `Maximum number of insights reached (limit: 100)`

**Solution:** Delete unused insights via the Security Hub console or AWS CLI:

```bash
aws securityhub delete-insight --insight-arn INSIGHT_ARN --region REGION
```


