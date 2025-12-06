import json
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

class ZeroTrustIAMEngine:
    """Zero Trust IAM Condition Engine for AWS Services"""
    
    def __init__(self):
        # Predefined Zero Trust rules
        self.zero_trust_rules = {
            "must_have_tags": True,
            "must_have_owner": True,
            "enforce_principal_arn_rules": True,
            "enforce_scp": True,
            "default_deny": True
        }
        
        # Service-specific rules
        self.service_rules = {
            "kms": {
                "principal_arn_must_be_role": True,
                "source_ip_cidr": "10.0.0.0/16",
                "mfa_required": True
            },
            "s3": {
                "vpc_endpoint": "vpce-1122334455",
                "called_from_lambda": True
            },
            "ec2": {
                "tag_matching": {
                    "Environment": {
                        "request_tag": "aws:RequestTag/Environment",
                        "principal_tag": "aws:PrincipalTag/Environment"
                    }
                }
            }
        }
        
        # System Control Policies (SCPs)
        self.scps = [
            {
                "effect": "Deny",
                "actions": ["kms:*"],
                "conditions": {
                    "StringNotEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::*:role/*"
                    }
                }
            },
            {
                "effect": "Deny",
                "actions": ["s3:*"],
                "conditions": {
                    "StringNotEquals": {
                        "aws:SourceVpc": "vpce-1122334455"
                    }
                }
            }
        ]
    
    def load_identity_policy(self, policy_path: str) -> Dict:
        """Load IAM identity policy from JSON file"""
        try:
            with open(policy_path, 'r') as f:
                policy = json.load(f)
            print(f"✓ Policy loaded from {policy_path}")
            return policy
        except FileNotFoundError:
            print(f"✗ Policy file not found: {policy_path}")
            return {}
        except json.JSONDecodeError:
            print(f"✗ Invalid JSON in policy file: {policy_path}")
            return {}
    
    def evaluate_conditions(self, request: Dict, conditions: Dict) -> Tuple[bool, Optional[str]]:
        """Evaluate IAM conditions against the request"""
        
        # StringEquals condition
        if "StringEquals" in conditions:
            for key, expected_value in conditions["StringEquals"].items():
                actual_value = request.get(key)
                if actual_value != expected_value:
                    return False, f"StringEquals condition failed: {key}"
        
        # StringNotEquals condition
        if "StringNotEquals" in conditions:
            for key, not_value in conditions["StringNotEquals"].items():
                actual_value = request.get(key)
                if actual_value == not_value:
                    return False, f"StringNotEquals condition failed: {key}"
        
        # IpAddress condition
        if "IpAddress" in conditions:
            cidr = conditions["IpAddress"]["aws:SourceIp"]
            source_ip = request.get("aws:SourceIp")
            if source_ip and not self._check_ip_in_cidr(source_ip, cidr):
                return False, f"IpAddress condition failed: {source_ip} not in {cidr}"
        
        # NotIpAddress condition
        if "NotIpAddress" in conditions:
            cidr = conditions["NotIpAddress"]["aws:SourceIp"]
            source_ip = request.get("aws:SourceIp")
            if source_ip and self._check_ip_in_cidr(source_ip, cidr):
                return False, f"NotIpAddress condition failed: {source_ip} in {cidr}"
        
        # Null condition
        if "Null" in conditions:
            for key in conditions["Null"]:
                if request.get(key) is not None:
                    return False, f"Null condition failed: {key} is not null"
        
        # CalledVia condition
        if "CalledVia" in conditions:
            called_via_services = conditions["CalledVia"]
            caller_source = request.get("aws:CalledVia")
            if not any(service in str(caller_source) for service in called_via_services):
                return False, "CalledVia condition failed"
        
        return True, None
    
    def apply_zero_trust_rules(self, request: Dict) -> Tuple[bool, Optional[str]]:
        """Apply predefined Zero Trust rules"""
        
        # Rule 1: All resources must contain tags
        if self.zero_trust_rules["must_have_tags"]:
            if "aws:RequestTag" not in request or not request["aws:RequestTag"]:
                return False, "Resource must have tags"
        
        # Rule 2: All resources must have owner tag
        if self.zero_trust_rules["must_have_owner"]:
            tags = request.get("aws:RequestTag", {})
            if "Owner" not in tags and "owner" not in tags:
                return False, "Resource must have Owner tag"
        
        return True, None
    
    def apply_service_specific_rules(self, service: str, request: Dict) -> Tuple[bool, Optional[str]]:
        """Apply service-specific rules for S3, EC2, KMS"""
        
        if service == "kms":
            # Rule 1: Principal ARN must be a role
            if self.service_rules["kms"]["principal_arn_must_be_role"]:
                principal_arn = request.get("aws:PrincipalArn", "")
                if ":role/" not in principal_arn:
                    return False, "Principal ARN must be a role"
            
            # Rule 2: Source IP must be in CIDR
            cidr = self.service_rules["kms"]["source_ip_cidr"]
            source_ip = request.get("aws:SourceIp")
            if source_ip and not self._check_ip_in_cidr(source_ip, cidr):
                return False, f"Source IP {source_ip} outside allowed CIDR {cidr}"
            
            # Rule 3: MFA must be true
            if self.service_rules["kms"]["mfa_required"]:
                mfa_present = request.get("aws:MultiFactorAuthPresent", "false")
                if mfa_present.lower() != "true":
                    return False, "MFA authentication required"
        
        elif service == "s3":
            # Rule 1: VPC Endpoint must match
            expected_vpce = self.service_rules["s3"]["vpc_endpoint"]
            source_vpc = request.get("aws:SourceVpc")
            if source_vpc != expected_vpce:
                return False, f"VPC Endpoint mismatch. Expected: {expected_vpce}"
            
            # Rule 2: Must be called from Lambda
            if self.service_rules["s3"]["called_from_lambda"]:
                caller = request.get("aws:CalledVia", "")
                if "lambda" not in str(caller).lower():
                    return False, "S3 must be called from Lambda"
        
        elif service == "ec2":
            # Rule: Environment tags must match
            tag_rules = self.service_rules["ec2"]["tag_matching"]
            for tag_key, rule in tag_rules.items():
                request_tag = request.get(rule["request_tag"])
                principal_tag = request.get(rule["principal_tag"])
                
                if request_tag != principal_tag:
                    return False, f"Tag mismatch for {tag_key}. Request: {request_tag}, Principal: {principal_tag}"
        
        return True, None
    
    def apply_scps(self, request: Dict) -> Tuple[bool, Optional[str]]:
        """Apply System Control Policies"""
        for scp in self.scps:
            # Check if SCP applies to this request
            if self._scp_applies(scp, request):
                effect = scp.get("effect", "Deny")
                if effect == "Deny":
                    return False, "SCP denies this action"
        
        return True, None
    
    def evaluate_request(self, policy: Dict, request: Dict) -> str:
        """Main evaluation function that runs all checks"""
        
        service = request.get("aws:Service", "").lower()
        
        # Step 1: Apply Zero Trust rules
        zt_result, zt_reason = self.apply_zero_trust_rules(request)
        if not zt_result:
            return f"DENIED (reason: {zt_reason})"
        
        # Step 2: Apply service-specific rules
        if service in self.service_rules:
            service_result, service_reason = self.apply_service_specific_rules(service, request)
            if not service_result:
                return f"DENIED (reason: {service_reason})"
        
        # Step 3: Apply SCPs
        scp_result, scp_reason = self.apply_scps(request)
        if not scp_result:
            return f"DENIED (reason: SCP - {scp_reason})"
        
        # Step 4: Evaluate policy conditions
        if "Statement" in policy:
            for statement in policy["Statement"]:
                if self._statement_applies(statement, request):
                    effect = statement.get("Effect", "Deny")
                    
                    if effect == "Deny":
                        return "DENIED (reason: explicit deny in policy)"
                    
                    # Check conditions
                    conditions = statement.get("Condition", {})
                    condition_result, condition_reason = self.evaluate_conditions(request, conditions)
                    
                    if not condition_result:
                        return f"DENIED (reason: {condition_reason})"
                    
                    # If we reach here, the statement allows the request
                    return "ALLOWED"
        
        # Default deny
        return "DENIED (reason: no matching allow statement)"
    
    def _check_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is within CIDR range"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False
    
    def _statement_applies(self, statement: Dict, request: Dict) -> bool:
        """Check if a policy statement applies to the request"""
        # Check resource match (simplified)
        resources = statement.get("Resource", [])
        request_resource = request.get("aws:Resource")
        
        if resources and request_resource:
            if isinstance(resources, list):
                if not any(request_resource.startswith(resource.rstrip('*')) for resource in resources):
                    return False
            elif not request_resource.startswith(resources.rstrip('*')):
                return False
        
        # Check action match (simplified)
        actions = statement.get("Action", [])
        request_action = request.get("aws:Action")
        
        if actions and request_action:
            action_list = actions if isinstance(actions, list) else [actions]
            if not any(request_action.startswith(action.rstrip('*')) for action in action_list):
                return False
        
        return True
    
    def _scp_applies(self, scp: Dict, request: Dict) -> bool:
        """Check if SCP applies to the request"""
        scp_actions = scp.get("actions", [])
        request_action = request.get("aws:Action", "")
        
        # Check if action matches
        for scp_action in scp_actions:
            if request_action.startswith(scp_action.rstrip('*')):
                return True
        
        return False

# Example usage and test function
def test_engine():
    """Test the IAM Condition Engine with various scenarios"""
    
    engine = ZeroTrustIAMEngine()
    
    # Load a sample policy (you would replace this with actual policy file)
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kms:Encrypt", "kms:Decrypt"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole"
                    },
                    "IpAddress": {
                        "aws:SourceIp": "10.0.0.0/16"
                    }
                }
            }
        ]
    }
    
    # Test Case 1: Valid KMS request
    print("\n" + "="*60)
    print("Test Case 1: Valid KMS Request")
    print("="*60)
    
    valid_kms_request = {
        "aws:Service": "kms",
        "aws:Action": "kms:Encrypt",
        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/MyRole",
        "aws:SourceIp": "10.0.1.100",
        "aws:MultiFactorAuthPresent": "true",
        "aws:RequestTag": {
            "Environment": "production",
            "Owner": "team-a"
        },
        "aws:Resource": "arn:aws:kms:us-east-1:123456789012:key/12345"
    }
    
    result = engine.evaluate_request(sample_policy, valid_kms_request)
    print(f"Result: {result}")
    
    # Test Case 2: KMS without MFA
    print("\n" + "="*60)
    print("Test Case 2: KMS without MFA")
    print("="*60)
    
    no_mfa_request = valid_kms_request.copy()
    no_mfa_request["aws:MultiFactorAuthPresent"] = "false"
    
    result = engine.evaluate_request(sample_policy, no_mfa_request)
    print(f"Result: {result}")
    
    # Test Case 3: S3 with wrong VPC Endpoint
    print("\n" + "="*60)
    print("Test Case 3: S3 with wrong VPC Endpoint")
    print("="*60)
    
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }
    
    s3_request = {
        "aws:Service": "s3",
        "aws:Action": "s3:GetObject",
        "aws:SourceVpc": "vpce-wrongid",
        "aws:CalledVia": "lambda.amazonaws.com",
        "aws:RequestTag": {
            "Environment": "production",
            "Owner": "team-b"
        }
    }
    
    result = engine.evaluate_request(s3_policy, s3_request)
    print(f"Result: {result}")
    
    # Test Case 4: EC2 with tag mismatch
    print("\n" + "="*60)
    print("Test Case 4: EC2 with tag mismatch")
    print("="*60)
    
    ec2_request = {
        "aws:Service": "ec2",
        "aws:Action": "ec2:RunInstances",
        "aws:RequestTag/Environment": "production",
        "aws:PrincipalTag/Environment": "development",
        "aws:RequestTag": {
            "Environment": "production",
            "Owner": "team-c"
        }
    }
    
    result = engine.evaluate_request({}, ec2_request)  # Empty policy
    print(f"Result: {result}")
    
    # Test Case 5: IP outside allowed range
    print("\n" + "="*60)
    print("Test Case 5: IP outside allowed range")
    print("="*60)
    
    invalid_ip_request = valid_kms_request.copy()
    invalid_ip_request["aws:SourceIp"] = "192.168.1.100"
    
    result = engine.evaluate_request(sample_policy, invalid_ip_request)
    print(f"Result: {result}")
    
    # Test Case 6: Valid request without Owner tag
    print("\n" + "="*60)
    print("Test Case 6: Missing Owner tag")
    print("="*60)
    
    no_owner_request = valid_kms_request.copy()
    no_owner_request["aws:RequestTag"] = {"Environment": "production"}
    
    result = engine.evaluate_request(sample_policy, no_owner_request)
    print(f"Result: {result}")

if __name__ == "__main__":
    print("🔐 Zero Trust IAM Condition Engine")
    print("="*40)
    print("Services: S3, EC2, KMS")
    print("Enforcing: Tags, MFA, CIDR, VPC Endpoints, SCPs")
    print("="*40 + "\n")
    
    # Run tests
    test_engine()
    
    # Example of using with actual policy file
    print("\n" + "="*60)
    print("Usage Example with Policy File")
    print("="*60)
    
    engine = ZeroTrustIAMEngine()
    
    # Create a sample request
    sample_request = {
        "aws:Service": "kms",
        "aws:Action": "kms:Decrypt",
        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/AdminRole",
        "aws:SourceIp": "10.0.10.50",
        "aws:MultiFactorAuthPresent": "true",
        "aws:RequestTag": {
            "Environment": "prod",
            "Owner": "security-team",
            "CostCenter": "12345"
        },
        "aws:Resource": "arn:aws:kms:us-east-1:123456789012:key/my-key"
    }
    
    # Load policy from file (create a sample file first)
    policy = engine.load_identity_policy("sample_policy.json")
    if not policy:
        print("Using default policy for demonstration")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "kms:*",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:MultiFactorAuthPresent": "true"
                        }
                    }
                }
            ]
        }
    
    result = engine.evaluate_request(policy, sample_request)
    print(f"Final Result: {result}")
