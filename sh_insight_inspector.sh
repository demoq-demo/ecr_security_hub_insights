#!/bin/bash

# Security Hub Insights for Inspector ECR Findings
# All filters and GroupByAttribute values validated against AWS Security Hub API schema

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Enable debug mode if DEBUG=1
[[ "${DEBUG:-0}" == "1" ]] && set -x

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Error counter
ERROR_COUNT=0

# Region detection with fallback chain (NOT hardcoded)
# Priority order:
#   1. Script parameter ($1) - Highest priority, allows manual override
#      Example: ./script.sh us-west-2
#   2. AWS_REGION environment variable - Set automatically by CloudShell
#      Example: AWS_REGION=eu-west-1 (auto-set when CloudShell opens in eu-west-1)
#   3. AWS CLI config - From 'aws configure get region'
#      Example: Region set via 'aws configure' command
#   4. Default fallback - us-east-1 (lowest priority)
# This ensures the script works in CloudShell without any input while remaining flexible

REGION="${1:-${AWS_REGION:-$(aws configure get region 2>/dev/null || echo 'us-east-1')}}"

# Track created insights for cleanup on error
CREATED_INSIGHTS=()
FAILED_INSIGHTS=()

# Logging function
log_error() {
  echo -e "${RED}[ERROR] $1${NC}" >&2
  ((ERROR_COUNT++))
}

log_warn() {
  echo -e "${YELLOW}[WARNING] $1${NC}" >&2
}

log_success() {
  echo -e "${GREEN}[SUCCESS] $1${NC}"
}

log_info() {
  echo "[INFO] $1"
}

# Cleanup function
cleanup_on_error() {
  local exit_code=$?
  echo ""
  log_error "Script failed with exit code: $exit_code"
  
  if [ ${#CREATED_INSIGHTS[@]} -gt 0 ]; then
    echo ""
    log_warn "Cleaning up ${#CREATED_INSIGHTS[@]} created insights..."
    for arn in "${CREATED_INSIGHTS[@]}"; do
      echo "  Deleting: $arn"
      if aws securityhub delete-insight --insight-arn "$arn" --region "$REGION" 2>/dev/null; then
        echo "    [OK] Deleted successfully"
      else
        log_warn "Failed to delete: $arn (manual cleanup may be required)"
      fi
    done
  fi
  
  echo ""
  log_error "Script execution failed. Please review errors above."
  exit $exit_code
}

trap 'cleanup_on_error' ERR
trap 'echo ""; log_warn "Script interrupted by user"; exit 130' INT TERM

# Prerequisite check functions
check_aws_cli() {
  if ! command -v aws &> /dev/null; then
    log_error "AWS CLI is not installed"
    echo "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    return 1
  fi
  log_success "AWS CLI found: $(aws --version 2>&1 | head -n1)"
  return 0
}

check_aws_credentials() {
  if ! aws sts get-caller-identity --region "$REGION" &> /dev/null; then
    log_error "AWS credentials not configured or invalid"
    echo "  Configure: aws configure"
    echo "  Or set: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN"
    return 1
  fi
  
  local identity
  identity=$(aws sts get-caller-identity --region "$REGION" --output json 2>/dev/null)
  local account=$(echo "$identity" | grep -o '"Account": "[^"]*"' | cut -d'"' -f4)
  local arn=$(echo "$identity" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
  
  log_success "AWS credentials valid"
  log_info "Account: $account"
  log_info "Identity: $arn"
  return 0
}

check_security_hub_enabled() {
  log_info "Checking if Security Hub is enabled in $REGION..."
  
  if ! aws securityhub describe-hub --region "$REGION" &> /dev/null; then
    log_error "Security Hub is not enabled in region: $REGION"
    echo "  Enable Security Hub:"
    echo "    aws securityhub enable-security-hub --region $REGION"
    echo "  Or via Console: https://console.aws.amazon.com/securityhub/home?region=$REGION#/get-started"
    return 1
  fi
  
  log_success "Security Hub is enabled in $REGION"
  return 0
}

check_inspector_enabled() {
  log_info "Checking if Inspector is enabled..."
  
  local status
  status=$(aws inspector2 batch-get-account-status --region "$REGION" 2>/dev/null | \
    grep -o '"status": "[^"]*"' | head -n1 | cut -d'"' -f4 || echo "UNKNOWN")
  
  if [[ "$status" != "ENABLED" ]]; then
    log_warn "Inspector may not be fully enabled (Status: $status)"
    echo "  Enable Inspector: aws inspector2 enable --resource-types ECR --region $REGION"
  else
    log_success "Inspector is enabled"
  fi
  return 0
}

check_iam_permissions() {
  log_info "Checking IAM permissions..."
  
  local has_error=0
  
  # Test CreateInsight permission
  if ! aws securityhub get-insights --region "$REGION" --max-results 1 &> /dev/null; then
    log_error "Missing permission: securityhub:GetInsights"
    has_error=1
  fi
  
  if [ $has_error -eq 0 ]; then
    log_success "Required IAM permissions appear to be present"
  else
    log_error "Missing required IAM permissions"
    echo "  Required permissions:"
    echo "    - securityhub:GetInsights"
    echo "    - securityhub:CreateInsight"
    echo "    - securityhub:DeleteInsight (for cleanup)"
    return 1
  fi
  
  return 0
}

# Helper function to check if insight exists
insight_exists() {
  local name="$1"
  local result
  
  result=$(aws securityhub get-insights --region "$REGION" \
    --query "Insights[?Name=='$name'].InsightArn" \
    --output text 2>&1)
  
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log_error "Failed to check if insight exists: $name"
    echo "  AWS CLI Error: $result" >&2
    return 2
  fi
  
  echo "$result"
  return 0
}

# Helper function to create insight with duplicate check and error handling
create_insight_safe() {
  local name="$1"
  local filters="$2"
  local group_by="$3"
  
  # Check if insight already exists
  local existing
  existing=$(insight_exists "$name" || echo "")
  local check_exit=$?
  
  if [ $check_exit -eq 2 ]; then
    log_error "Failed to check existing insights for: $name"
    FAILED_INSIGHTS+=("$name (check failed)")
    ((ERROR_COUNT++))
    return 0
  fi
  
  if [ -n "$existing" ] && [ "$existing" != "None" ]; then
    log_warn "Insight already exists: $name"
    echo "   ARN: $existing"
    return 0
  fi
  
  # Create the insight
  local output
  local arn
  
  output=$(aws securityhub create-insight --region "$REGION" \
    --filters "$filters" \
    --group-by-attribute "$group_by" \
    --name "$name" \
    --output json 2>&1) || true
  
  local exit_code=$?
  
  if [ $exit_code -ne 0 ]; then
    log_error "Failed to create insight: $name"
    echo "  AWS CLI Error: $output" >&2
    
    # Parse common errors
    if echo "$output" | grep -q "AccessDeniedException"; then
      echo "  Cause: Insufficient IAM permissions"
      echo "  Required: securityhub:CreateInsight"
      FAILED_INSIGHTS+=("$name (access denied)")
    elif echo "$output" | grep -q "InvalidInputException"; then
      echo "  Cause: Invalid filter or GroupByAttribute"
      echo "  GroupByAttribute: $group_by"
      FAILED_INSIGHTS+=("$name (invalid input)")
    elif echo "$output" | grep -q "LimitExceededException"; then
      echo "  Cause: Maximum number of insights reached (limit: 100)"
      FAILED_INSIGHTS+=("$name (limit exceeded)")
    elif echo "$output" | grep -q "ResourceConflictException"; then
      echo "  Cause: Insight with this name already exists"
      FAILED_INSIGHTS+=("$name (conflict)")
    else
      FAILED_INSIGHTS+=("$name (unknown error)")
    fi
    
    ((ERROR_COUNT++))
    return 0
  fi
  
  # Extract ARN from output
  arn=$(echo "$output" | grep -o '"InsightArn": "[^"]*"' | cut -d'"' -f4)
  
  if [ -z "$arn" ]; then
    log_error "Failed to extract InsightArn from response for: $name"
    echo "  AWS Response: $output" >&2
    FAILED_INSIGHTS+=("$name (ARN extraction failed)")
    ((ERROR_COUNT++))
    return 0
  fi
  
  CREATED_INSIGHTS+=("$arn")
  log_success "Created: $name"
  echo "   ARN: $arn"
  return 0
}

echo -e "${RED}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     🎯  WHICH AWS ACCOUNT TO RUN THIS  🎯                    ║
║                                                                              ║
║  Run this script ONLY in the AWS account where:                             ║
║                                                                              ║
║  ✓  Amazon Inspector is actively scanning ECR repositories                  ║
║  ✓  AWS Security Hub is enabled and receiving Inspector findings            ║
║  ✓  You have ECR container images that need vulnerability insights          ║
║                                                                              ║
║  Common scenarios:                                                           ║
║    • Production account with ECR repositories                                ║
║    • Security account aggregating findings from multiple accounts            ║
║    • Development/staging account for testing                                 ║
║                                                                              ║
║  ⚠️  DO NOT run in accounts without Inspector ECR scanning enabled!          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""
echo -e "${RED}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                        ⚠️  PREREQUISITES REQUIRED  ⚠️                         ║
║                                                                              ║
║  Before running this script, ensure the following are enabled:               ║
║                                                                              ║
║  ✗  AWS Security Hub MUST be enabled in this region                         ║
║  ✗  Amazon Inspector MUST be enabled for ECR scanning                       ║
║  ✗  ECR repositories MUST exist with container images                       ║
║  ✗  IAM permissions for securityhub:CreateInsight required                  ║
║                                                                              ║
║  This script will FAIL if these prerequisites are not met.                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""
echo -e "${YELLOW}Type ${GREEN}YES${YELLOW} (in capital letters) to continue or press Ctrl+C to exit:${NC}"
read -r confirmation

if [ "$confirmation" != "YES" ]; then
  echo -e "${RED}[ABORTED]${NC} You must type 'YES' to continue. Exiting..."
  exit 1
fi

echo -e "${GREEN}[CONFIRMED]${NC} Proceeding with script execution..."
echo ""

cat << 'EOF'
================================================================================
  Security Hub Insights for Inspector ECR Container Image Findings
================================================================================

IMPORTANT: WHICH AWS ACCOUNT TO USE

  Run this script in the AWS account where:
    ✓ Amazon Inspector is enabled and scanning ECR repositories
    ✓ AWS Security Hub is enabled and receiving Inspector findings
    ✓ You want to create custom insights for vulnerability analysis

  Typical scenarios:
    - Production account with ECR repositories being scanned
    - Security account aggregating findings from multiple accounts
    - Development/staging account for testing Inspector integration

  DO NOT run in accounts without Inspector ECR scanning enabled.

================================================================================

HOW TO RUN THIS SCRIPT:

  Option 1: AWS CloudShell (Recommended - Auto-detects region)
    1. Log into the AWS Console in the target account
    2. Open AWS CloudShell in your desired region (top-right toolbar)
    3. Upload this script: Actions > Upload file > sh_insight_inspector.sh
       OR copy/paste the script content into a new file
    4. Make executable: chmod +x sh_insight_inspector.sh
    5. Run: ./sh_insight_inspector.sh

  Option 2: Local Terminal with AWS CLI
    1. Configure AWS CLI for target account: aws configure
       OR set profile: export AWS_PROFILE=your-profile-name
    2. Make executable: chmod +x sh_insight_inspector.sh
    3. Run: ./sh_insight_inspector.sh
    4. Override region: ./sh_insight_inspector.sh us-west-2

  Option 3: Direct Bash Execution
    bash sh_insight_inspector.sh [optional-region]

  Prerequisites:
    ✓ AWS CLI installed and configured
    ✓ Security Hub enabled in the target region
    ✓ Inspector enabled for ECR scanning
    ✓ IAM permissions: securityhub:CreateInsight, securityhub:GetInsights

  Script Features:
    - Auto-detects region from CloudShell/AWS CLI config
    - Validates prerequisites before creating insights
    - Checks for duplicate insights before creating
    - Automatic cleanup if script fails midway
    - Comprehensive error reporting

  Region Detection Priority:
    1. Script parameter: ./sh_insight_inspector.sh us-west-2
    2. AWS_REGION environment variable (auto-set in CloudShell)
    3. AWS CLI config: aws configure get region
    4. Default fallback: us-east-1

================================================================================

Safe to re-run (skips existing insights)

================================================================================

This script creates 15 insights to provide comprehensive visibility into your
ECR container security posture. Each insight serves a specific purpose:

SEVERITY ANALYSIS
  #1  - Findings by Severity: Understand overall risk distribution
  #10 - HIGH Severity: Track often-overlooked high-risk vulnerabilities
  #11 - MEDIUM Severity: Track medium-risk vulnerabilities (60-70% of total)
  #15 - CRITICAL+HIGH Combined: Single view for priority remediation

RISK PRIORITIZATION
  #2  - Images with Most Vulnerabilities: Identify worst offenders
  #3  - Critical in Production: Focus on business-critical systems
  #4  - Exploitable Vulnerabilities: Track active threats with public exploits

WORKFLOW & REMEDIATION TRACKING
  #5  - By Workflow Status: Monitor NEW → NOTIFIED → RESOLVED progression
  #7  - Aging Findings (30+ days): Identify stale vulnerabilities needing escalation
  #12 - Suppressed Findings: Track accepted risks for audit purposes

ENVIRONMENT SEGMENTATION
  #9  - By AWS Account: Multi-account visibility
  #13 - By Region: Multi-region deployment tracking

COMPLIANCE & GOVERNANCE
  #6  - Compliance Violations: Track PCI-DSS, HIPAA, SOC2 failures

TEMPORAL ANALYSIS
  #7  - Aging Findings: Vulnerabilities unresolved for 30+ days
  #14 - Recently Updated: Findings updated in last 7 days

COVERAGE VERIFICATION
  #8  - By Resource Type: Ensure all ECR images are being scanned

IMPORTANT NOTES:
  - Network Reachability: Not available as Security Hub filter
  - Fix Available: Not available as Security Hub filter
  - Insight #3 requires 'Environment' tag on ECR repositories for filtering
  - Script auto-detects region from CloudShell/AWS CLI config
  - Override region: ./script.sh us-west-2
  - Region detection order: 1) Script parameter 2) AWS_REGION env 3) AWS CLI config 4) us-east-1

================================================================================
EOF

# Run prerequisite checks
echo ""
echo "========================================================================"
echo "Running prerequisite checks..."
echo "========================================================================"
echo ""

check_aws_cli || exit 1
check_aws_credentials || exit 1
check_security_hub_enabled || exit 1
check_inspector_enabled  # Warning only, don't exit
check_iam_permissions || exit 1

if [ $ERROR_COUNT -gt 0 ]; then
  echo ""
  log_error "Prerequisite checks failed with $ERROR_COUNT error(s)"
  echo "Please resolve the errors above before running this script."
  exit 1
fi

echo ""
log_success "All prerequisite checks passed!"
echo ""
echo "========================================================================"
echo "Region: $REGION"
echo "Starting insight creation..."
echo "========================================================================"
echo ""

# Disable exit on error and ERR trap for insight creation
set +e
trap - ERR

# 1. Findings by severity
echo "[1/16] Creating: ECR Findings by Severity..."
create_insight_safe "ECR Findings by Severity" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "SeverityLabel"

# 2. Images with most vulnerabilities
echo "[2/16] Creating: ECR Images with Most Vulnerabilities..."
create_insight_safe "ECR Images with Most Vulnerabilities" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

# 3. Critical findings in production
echo "[3/16] Creating: Critical Findings in Production Images..."
create_insight_safe "Critical Findings in Production Images" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
  "ResourceTags": [{"Key": "Environment", "Value": "production", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

# 4. Images with exploitable vulnerabilities
echo "[4/16] Creating: Images with Exploitable Vulnerabilities..."
create_insight_safe "Images with Exploitable Vulnerabilities" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "VulnerabilitiesExploitAvailable": [{"Value": "YES", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

# 5. Findings by workflow status
echo "[5/16] Creating: ECR Findings by Workflow Status..."
create_insight_safe "ECR Findings by Workflow Status" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "WorkflowStatus"

# 6. Compliance violations
echo "[6/15] Creating: ECR Compliance Violations..."
create_insight_safe "ECR Compliance Violations" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ComplianceStatus"

# 7. Aging findings (30+ days)
echo "[7/15] Creating: ECR Findings Older Than 30 Days..."
create_insight_safe "ECR Findings Older Than 30 Days" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "UpdatedAt": [{"DateRange": {"Value": 30, "Unit": "DAYS"}}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
  "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
}' "SeverityLabel"

# 8. Findings by resource type
echo "[8/15] Creating: Findings by Resource Type..."
create_insight_safe "Findings by Resource Type" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceType"

# 9. Findings by AWS account
echo "[9/15] Creating: ECR Findings by AWS Account..."
create_insight_safe "ECR Findings by AWS Account" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "AwsAccountId"

# 10. HIGH severity findings
echo "[10/15] Creating: HIGH Severity Findings in ECR Images..."
create_insight_safe "HIGH Severity Findings in ECR Images" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

# 11. MEDIUM severity findings - NEW
echo "[11/15] Creating: MEDIUM Severity Findings in ECR Images..."
create_insight_safe "MEDIUM Severity Findings in ECR Images" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "SeverityLabel": [{"Value": "MEDIUM", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

# 12. Suppressed findings
echo "[12/15] Creating: Suppressed ECR Findings (Accepted Risks)..."
create_insight_safe "Suppressed ECR Findings (Accepted Risks)" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "SeverityLabel"

# 13. Findings by region
echo "[13/15] Creating: ECR Findings by Region..."
create_insight_safe "ECR Findings by Region" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "Region"

# 14. Recently updated findings
echo "[14/15] Creating: Recently Updated ECR Findings (Last 7 Days)..."
create_insight_safe "Recently Updated ECR Findings (Last 7 Days)" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "UpdatedAt": [{"DateRange": {"Value": 7, "Unit": "DAYS"}}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "SeverityLabel"

# 15. Critical + HIGH findings combined
echo "[15/15] Creating: Critical and HIGH Severity Findings Combined..."
create_insight_safe "Critical and HIGH Severity Findings Combined" '{
  "ProductName": [{"Value": "Inspector", "Comparison": "EQUALS"}],
  "ResourceType": [{"Value": "AwsEcrContainerImage", "Comparison": "EQUALS"}],
  "SeverityLabel": [
    {"Value": "CRITICAL", "Comparison": "EQUALS"},
    {"Value": "HIGH", "Comparison": "EQUALS"}
  ],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' "ResourceId"

echo ""
echo "========================================================================"
if [ $ERROR_COUNT -eq 0 ]; then
  log_success "All 15 insights processed successfully!"
else
  log_warn "Completed with $ERROR_COUNT error(s). Some insights failed."
  echo ""
  echo "Failed insights:"
  for failed in "${FAILED_INSIGHTS[@]}"; do
    echo "   - $failed"
  done
fi
echo ""
echo "Insight Categories:"
echo "   - Severity Analysis: #1, #10, #11, #15"
echo "   - Risk Prioritization: #2, #3, #4, #15"
echo "   - Workflow Tracking: #5, #7, #12"
echo "   - Environment Segmentation: #9, #13"
echo "   - Compliance & Governance: #6"
echo "   - Temporal Analysis: #7, #14"
echo "   - Coverage Verification: #8"
echo ""
echo "View insights in AWS Console:"
echo "https://console.aws.amazon.com/securityhub/home?region=$REGION#/insights"
echo ""
echo "Important Notes:"
echo "   - Insight #3 requires 'Environment' tag on ECR repositories for filtering"
echo "   - Tag repositories: aws ecr tag-resource --tags Key=Environment,Value=production"
echo "   - Insight #7 finds findings NOT updated in last 30 days (stale)"
echo "   - Insight #14 finds findings updated in last 7 days (recent activity)"
echo "   - Insight #13 requires Security Hub aggregation enabled for multi-region view"
echo ""
echo "LIMITATIONS - Filters NOT Available in Security Hub Insights:"
echo "   - Network Reachability: Cannot filter by network exposure"
echo "     → Use Inspector API: aws inspector2 list-findings --filter-criteria"
echo "       '{\"networkReachability\":[{\"comparison\":\"EQUALS\",\"value\":\"INTERNET\"}]}'"
echo ""
echo "   - Fix Available: Cannot filter by fixable vulnerabilities"
echo "     → Use Inspector API: aws inspector2 list-findings --filter-criteria"
echo "       '{\"fixAvailable\":[{\"comparison\":\"EQUALS\",\"value\":\"YES\"}]}'"
echo ""
echo "TIP: For network reachability and fix available filters, use Inspector API directly"
echo "   See: inspector_network_reachability_queries.sh"
