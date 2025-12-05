AWS IAM Policy Simulator - Summary:

📋 Overview:

A Python-based AWS IAM policy evaluation simulator that accurately models AWS's multi-layer policy evaluation logic. The tool simulates how AWS evaluates permissions across four policy layers.

📝 Learning Note: I'm still learning and improving this tool! This represents my current understanding of AWS IAM policies at age 14. Feedback and corrections are welcome!

🏗️ Architecture:

Policy Layers (Evaluated in Order):

Service Control Policy (SCP) - Organization-level guardrails
Permissions Boundary - Maximum permission limits
Session Policy - Temporary credential restrictions
Identity Policy - User/Role attached policies

🔧 Key Features
Core Functionality:

✅ Multi-layer policy evaluation with correct AWS hierarchy
✅ ARN pattern matching with wildcard support
✅ DENY precedence enforcement (DENY always wins)
✅ Step-by-step evaluation tracking
✅ JSON import/export for policy documents
