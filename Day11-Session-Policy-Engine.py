#!/usr/bin/env python3
"""
AWS IAM Policy Simulator - Multi-Layer Policy Evaluation
Simulates Identity, Session, Boundary, and SCP policy evaluation
"""

import json
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import re

class Effect(Enum):
    ALLOW = "Allow"
    DENY = "Deny"

class PolicyType(Enum):
    IDENTITY = "IdentityPolicy"
    SESSION = "SessionPolicy"
    BOUNDARY = "PermissionsBoundary"
    SCP = "ServiceControlPolicy"

class IAMPolicySimulator:
    def __init__(self):
        self.policies = {}
        self.evaluation_path = []
        self.final_allows = set()
        self.final_denies = set()
        
    def add_policy(self, policy_type: PolicyType, policy_doc: Dict):
        """Add a policy document to the simulator"""
        try:
            if 'Statement' not in policy_doc:
                raise ValueError(f"Invalid policy: No Statement section")
            
            self.policies[policy_type] = policy_doc
            print(f"✅ Added {policy_type.value}: {len(policy_doc['Statement'])} statement(s)")
            
        except Exception as e:
            print(f"❌ Failed to add {policy_type.value}: {e}")
    
    def parse_arn(self, arn: str) -> Dict:
        """Parse AWS ARN into components"""
        # Format: arn:partition:service:region:account:resource
        pattern = r'^arn:([^:]+):([^:]+):([^:]*):([^:]*):(.+)$'
        match = re.match(pattern, arn)
        if match:
            return {
                'partition': match.group(1),
                'service': match.group(2),
                'region': match.group(3),
                'account': match.group(4),
                'resource': match.group(5)
            }
        return {}
    
    def arn_match(self, pattern_arn: str, test_arn: str) -> bool:
        """Check if ARN matches pattern (with wildcards)"""
        if pattern_arn == "*":
            return True
        
        # Escape regex special chars, then replace * with .*
        regex_pattern = re.escape(pattern_arn).replace(r'\*', '.*')
        return bool(re.match(f"^{regex_pattern}$", test_arn))
    
    def evaluate_statement(self, statement: Dict, action: str, resource: str) -> Optional[Effect]:
        """Evaluate a single policy statement"""
        try:
            # Check effect
            effect = Effect(statement.get('Effect', 'Deny'))
            
            # Check Action match
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            action_matched = False
            for action_pattern in actions:
                # Simple wildcard matching for actions
                if action_pattern == "*" or action == action_pattern:
                    action_matched = True
                    break
            
            if not action_matched:
                return None
            
            # Check Resource match
            resources = statement.get('Resource', ["*"])
            if isinstance(resources, str):
                resources = [resources]
            
            resource_matched = False
            for resource_pattern in resources:
                if self.arn_match(resource_pattern, resource):
                    resource_matched = True
                    break
            
            if not resource_matched:
                return None
            
            # Check conditions if present
            if 'Condition' in statement:
                # Simplified condition check - in reality this is complex
                # We'll just assume conditions are met for this simulation
                pass
            
            return effect
            
        except Exception as e:
            print(f"Statement evaluation error: {e}")
            return None
    
    def evaluate_policy_layer(self, policy_type: PolicyType, action: str, resource: str) -> Optional[Effect]:
        """Evaluate a specific policy layer"""
        if policy_type not in self.policies:
            return None
        
        policy = self.policies[policy_type]
        statements = policy.get('Statement', [])
        
        # Default deny for empty policy
        if not statements:
            return Effect.DENY
        
        # Track explicit denies first
        for statement in statements:
            result = self.evaluate_statement(statement, action, resource)
            if result == Effect.DENY:
                self.evaluation_path.append(f"{policy_type.value}: Explicit DENY")
                return Effect.DENY
        
        # Check for allows
        for statement in statements:
            result = self.evaluate_statement(statement, action, resource)
            if result == Effect.ALLOW:
                self.evaluation_path.append(f"{policy_type.value}: Explicit ALLOW")
                return Effect.ALLOW
        
        # Implicit deny
        self.evaluation_path.append(f"{policy_type.value}: Implicit DENY")
        return Effect.DENY
    
    def simulate_request(self, action: str, resource: str, 
                        principal_arn: str = "arn:aws:iam::123456789012:user/alice") -> Tuple[Set, Set, List]:
        """
        Simulate AWS policy evaluation order:
        1. SCP (DENY only)
        2. Boundary (if present)
        3. Session policy (if present)  
        4. Identity policy
        """
        print(f"\n🔍 Simulating: {action} on {resource}")
        print(f"   Principal: {principal_arn}")
        print("-" * 60)
        
        self.evaluation_path = []
        self.final_allows = set()
        self.final_denies = set()
        
        # AWS Evaluation Order
        
        # 1. SCP Evaluation (Organization Level)
        if PolicyType.SCP in self.policies:
            scp_result = self.evaluate_policy_layer(PolicyType.SCP, action, resource)
            if scp_result == Effect.DENY:
                self.final_denies.add(f"{action}:{resource}")
                print(f"🚫 SCP DENY overrides everything")
                return self.final_allows, self.final_denies, self.evaluation_path
        
        # 2. Boundary Policy (if attached)
        if PolicyType.BOUNDARY in self.policies:
            boundary_result = self.evaluate_policy_layer(PolicyType.BOUNDARY, action, resource)
            if boundary_result == Effect.DENY:
                self.final_denies.add(f"{action}:{resource}")
                print(f"🚫 Boundary DENY")
                return self.final_allows, self.final_denies, self.evaluation_path
        
        # 3. Session Policy (for temporary credentials)
        session_allow = False
        if PolicyType.SESSION in self.policies:
            session_result = self.evaluate_policy_layer(PolicyType.SESSION, action, resource)
            if session_result == Effect.ALLOW:
                session_allow = True
                self.evaluation_path.append("Session policy allows (but identity must also allow)")
        
        # 4. Identity Policy
        identity_result = self.evaluate_policy_layer(PolicyType.IDENTITY, action, resource)
        
        # Final decision logic
        if identity_result == Effect.ALLOW:
            if PolicyType.SESSION in self.policies:
                # Both must allow when session policy exists
                if session_allow:
                    self.final_allows.add(f"{action}:{resource}")
                    print(f"✅ FINAL: ALLOWED")
                else:
                    self.final_denies.add(f"{action}:{resource}")
                    print(f"🚫 FINAL: DENIED (Session policy doesn't allow)")
            else:
                self.final_allows.add(f"{action}:{resource}")
                print(f"✅ FINAL: ALLOWED")
        else:
            self.final_denies.add(f"{action}:{resource}")
            print(f"🚫 FINAL: DENIED")
        
        print("-" * 60)
        return self.final_allows, self.final_denies, self.evaluation_path
    
    def generate_sample_policies(self):
        """Generate sample policies for demonstration"""
        
        # Sample Identity Policy (attached to user)
        identity_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAllS3",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Sid": "AllowSpecificEC2",
                    "Effect": "Allow",
                    "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                    "Resource": "arn:aws:ec2:*:123456789012:instance/i-*"
                },
                {
                    "Sid": "DenyTerminateProduction",
                    "Effect": "Deny",
                    "Action": "ec2:TerminateInstances",
                    "Resource": "arn:aws:ec2:*:123456789012:instance/i-prod-*"
                }
            ]
        }
        
        # Sample Session Policy (for AssumeRole)
        session_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SessionRestriction",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::dev-bucket/*"
                },
                {
                    "Sid": "SessionDenyDelete",
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }
        
        # Sample Permissions Boundary
        boundary_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BoundaryLimit",
                    "Effect": "Allow",
                    "Action": [
                        "s3:*",
                        "ec2:Describe*",
                        "ec2:StartInstances",
                        "ec2:StopInstances"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "BoundaryDenyIAM",
                    "Effect": "Deny",
                    "Action": "iam:*",
                    "Resource": "*"
                }
            ]
        }
        
        # Sample SCP (Organization Level)
        scp_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyOutsideUS",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:RequestedRegion": "us-east-1"
                        }
                    }
                },
                {
                    "Sid": "DenyRootActions",
                    "Effect": "Deny",
                    "Action": [
                        "iam:DeleteAccountPasswordPolicy",
                        "organizations:LeaveOrganization"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        return {
            PolicyType.IDENTITY: identity_policy,
            PolicyType.SESSION: session_policy,
            PolicyType.BOUNDARY: boundary_policy,
            PolicyType.SCP: scp_policy
        }

def main():
    """Main execution function"""
    print("=" * 70)
    print("AWS IAM POLICY SIMULATOR")
    print("Simulates Identity + Session + Boundary + SCP evaluation")
    print("=" * 70)
    
    # Create simulator
    simulator = IAMPolicySimulator()
    
    # Generate and load sample policies
    sample_policies = simulator.generate_sample_policies()
    
    for policy_type, policy_doc in sample_policies.items():
        simulator.add_policy(policy_type, policy_doc)
    
    print("\n" + "=" * 70)
    print("TEST SCENARIOS")
    print("=" * 70)
    
    # Test scenarios
    test_cases = [
        # (action, resource, description)
        ("s3:GetObject", "arn:aws:s3:::dev-bucket/file.txt", "Read from dev bucket"),
        ("s3:DeleteObject", "arn:aws:s3:::dev-bucket/file.txt", "Delete from dev bucket"),
        ("s3:PutObject", "arn:aws:s3:::prod-bucket/file.txt", "Write to prod bucket"),
        ("ec2:StartInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-12345", "Start EC2 instance"),
        ("ec2:TerminateInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-prod-001", "Terminate prod instance"),
        ("iam:CreateUser", "arn:aws:iam::123456789012:user/*", "Create IAM user"),
        ("ec2:DescribeInstances", "arn:aws:ec2:*:123456789012:instance/*", "Describe instances"),
    ]
    
    all_allows = set()
    all_denies = set()
    all_paths = []
    
    for i, (action, resource, description) in enumerate(test_cases, 1):
        print(f"\n📋 Test #{i}: {description}")
        allows, denies, path = simulator.simulate_request(action, resource)
        all_allows.update(allows)
        all_denies.update(denies)
        all_paths.append((description, path))
    
    # Final Summary
    print("\n" + "=" * 70)
    print("FINAL EVALUATION SUMMARY")
    print("=" * 70)
    
    print(f"\n✅ FINAL ALLOW SET ({len(all_allows)}):")
    for item in sorted(all_allows):
        print(f"   {item}")
    
    print(f"\n🚫 FINAL DENY SET ({len(all_denies)}):")
    for item in sorted(all_denies):
        print(f"   {item}")
    
    print(f"\n📊 EVALUATION PATHS:")
    for desc, path in all_paths:
        print(f"\n   {desc}:")
        for step in path:
            print(f"     • {step}")
    
    print("\n" + "=" * 70)
    print("POLICY INTERACTION RULES:")
    print("=" * 70)
    print("""
    1. DENY always wins over ALLOW
    2. SCP evaluation happens first (org level)
    3. Boundary acts as maximum permissions
    4. Session + Identity must BOTH allow (when session exists)
    5. Missing policy = implicit deny
    6. Order: SCP → Boundary → Session → Identity
    """)
    
    # Export capability
    print("\n💾 Exporting results to JSON...")
    export_data = {
        "final_allows": list(all_allows),
        "final_denies": list(all_denies),
        "evaluation_paths": [
            {"test": desc, "path": path} 
            for desc, path in all_paths
        ],
        "policy_counts": {
            policy_type.value: len(policy_doc.get("Statement", []))
            for policy_type, policy_doc in sample_policies.items()
        }
    }
    
    with open("iam_policy_simulation.json", "w") as f:
        json.dump(export_data, f, indent=2)
    
    print("✅ Results exported to iam_policy_simulation.json")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
