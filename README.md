\# AEGISGATE



\### Runtime Security Firewall and Digital Forensics Platform for AI Agents



\*\*AEGISGATE\*\* is a cybersecurity prototype that demonstrates how tool-using AI agents can be monitored and protected through a centralized runtime security gateway.



It evaluates agent tool requests against security policies, controls tool execution, records security events, verifies audit-log integrity, and displays security activity through a web dashboard.



\*\*Project status:\*\* Working prototype — actively under development.



\---



\## Table of Contents



\- \[Overview](#overview)

\- \[Key Features](#key-features)

\- \[System Architecture](#system-architecture)

\- \[Security Decision Model](#security-decision-model)

\- \[Agent Demonstration](#agent-demonstration)

\- \[Audit Logging and Integrity Verification](#audit-logging-and-integrity-verification)

\- \[Behavior Analysis](#behavior-analysis)

\- \[Technology Stack](#technology-stack)

\- \[Project Structure](#project-structure)

\- \[Getting Started](#getting-started)

\- \[API Endpoints](#api-endpoints)

\- \[Testing](#testing)

\- \[Current Limitations](#current-limitations)

\- \[Future Improvements](#future-improvements)



\## Overview



AI agents can use tools to perform tasks such as reading files, performing calculations, and carrying out other operations.



However, allowing agents to interact with tools without appropriate security controls can introduce risks such as unauthorized actions, misuse of resources, and insufficient activity tracking.



AEGISGATE addresses this challenge by introducing a security gateway between an agent and its available tools.



Each supported tool request is evaluated by a policy engine before execution. Security decisions and execution outcomes are recorded in an audit log for monitoring and investigation.



\## Key Features



\- \*\*Runtime Policy Enforcement:\*\* Evaluates agent tool requests and assigns `ALLOW`, `BLOCK`, or `REQUIRE\_APPROVAL` decisions.

\- \*\*Controlled Tool Execution:\*\* Executes permitted operations through a simulated tool environment.

\- \*\*Agent Demonstration:\*\* Uses task-driven, deterministic tool selection to demonstrate secure agent interactions.

\- \*\*Security Audit Logging:\*\* Records security decisions and execution outcomes in an SQLite database.

\- \*\*Hash-Chain Integrity Verification:\*\* Uses SHA-256 hashes to verify the integrity of covered audit records.

\- \*\*Behavior Analysis:\*\* Identifies potentially suspicious activity using predefined detection rules.

\- \*\*Security Dashboard:\*\* Provides a React and TypeScript interface for monitoring agent activity, security events, anomalies, and audit integrity.

\- \*\*API Integration:\*\* Exposes security functionality through a FastAPI backend.



\## System Architecture



```text

&#x20;            User Task

&#x20;                |

&#x20;                v

&#x20;         Agent Runner

&#x20;                |

&#x20;                v

&#x20;         Tool Request

&#x20;                |

&#x20;                v

&#x20;        Security Gateway

&#x20;                |

&#x20;                v

&#x20;          Policy Engine

&#x20;                |

&#x20;      +---------+----------+

&#x20;      |         |          |

&#x20;      v         v          v

&#x20;    ALLOW     BLOCK     REQUIRE

&#x20;                        APPROVAL

&#x20;      |

&#x20;      v

&#x20;   Tool Simulator

&#x20;      |

&#x20;      v

&#x20; Execution Result





&#x20; Security Decisions and Execution Outcomes

&#x20;                   |

&#x20;                   v

&#x20;              Audit Logger

&#x20;                   |

&#x20;                   v

&#x20;            SQLite Database

&#x20;                   |

&#x20;                   v

&#x20;            SHA-256 Hash Chain

&#x20;                   |

&#x20;                   v

&#x20;         Integrity Verification





&#x20;         Security Events

&#x20;                |

&#x20;                v

&#x20;         Behavior Analyzer

&#x20;                |

&#x20;                v

&#x20;          FastAPI Backend

&#x20;                |

&#x20;                v

&#x20;         React Dashboard

```



\## Security Decision Model



AEGISGATE currently supports three security decisions.



| Decision | Description |

|---|---|

| `ALLOW` | The request satisfies the configured security policy and can proceed to execution. |

| `BLOCK` | The request violates the security policy and is prevented from executing. |

| `REQUIRE\_APPROVAL` | The request is withheld and requires approval before it could proceed. |



These decisions help demonstrate how security policies can control agent interactions with tools.



\*\*Important:\*\* A complete human approval workflow is not implemented yet. `REQUIRE\_APPROVAL` currently prevents execution.



\## Agent Demonstration



AEGISGATE includes a lightweight, deterministic agent runner that recognizes supported tasks and selects an appropriate tool request.



The selected request is passed through the same security policy engine used by the direct tool execution endpoint.



Example tasks:



| Agent Task | Selected Tool | Security Decision |

|---|---|---|

| Add 15 and 25 | Calculator | `ALLOW` |

| Read a sample file | File Reader | `ALLOW` |

| Write a file | File Writer | `REQUIRE\_APPROVAL` |

| Execute a shell command | File Reader | `BLOCK` |



The current agent is rule-based. It is not yet integrated with an external large language model (LLM).



\## Audit Logging and Integrity Verification



AEGISGATE records security events in an SQLite database.



The audit logging system uses SHA-256 hash chaining to connect covered records. Each hashed event contains information linked to the preceding event.



The integrity verification process checks the hash chain and reports whether covered records have been modified or whether the chain has been broken.



The verification report includes:



\- Hash-chain validity.

\- Number of events checked.

\- Number of legacy events.

\- Whether legacy events are covered by cryptographic verification.

\- Failed event identification, when applicable.



\*\*Legacy records:\*\* Events recorded before hash-chain protection was introduced are excluded from cryptographic verification. They are reported separately and should not be considered cryptographically verified.



\## Behavior Analysis



AEGISGATE includes a rule-based behavior analyzer that examines recent security events to identify potentially suspicious activity.



Current detection rules include:



\- Excessive activity within a short time window.

\- Repeated blocked requests.

\- Unusual tool diversity.

\- Repeated sensitive operations requiring approval.



The analyzer uses predefined demonstration thresholds. It is not currently a machine-learning-based detection system or an agent-specific behavioral baseline.



\## Technology Stack



| Component | Technology |

|---|---|

| Backend | Python 3.12 (tested environment) |

| API Framework | FastAPI |

| Data Validation | Pydantic |

| Frontend | React |

| Frontend Language | TypeScript |

| Database | SQLite |

| Cryptographic Hashing | SHA-256 |

| Data Visualization | Recharts |

| Icons | Lucide React |

| Backend Testing | Pytest |

| Frontend Build Tool | Vite |



\## Project Structure



```text

AEGISGATE/

│

├── backend/

│   ├── app/

│   │   ├── core/

│   │   ├── models/

│   │   │   └── security.py

│   │   ├── services/

│   │   │   ├── agent\_runner.py

│   │   │   ├── audit\_logger.py

│   │   │   ├── behavior\_analyzer.py

│   │   │   └── policy\_engine.py

│   │   ├── tools/

│   │   │   └── simulator.py

│   │   └── main.py

│   │

│   ├── tests/

│   │   ├── test\_agent\_runner.py

│   │   ├── test\_audit\_logger.py

│   │   ├── test\_behavior\_analyzer.py

│   │   ├── test\_policy\_engine.py

│   │   ├── test\_security\_api.py

│   │   └── test\_tool\_gateway.py

│   │

│   └── requirements.txt

│

└── frontend/

&#x20;   ├── src/

&#x20;   │   ├── components/

&#x20;   │   │   └── SecurityActivityChart.tsx

&#x20;   │   ├── services/

&#x20;   │   │   └── api.ts

&#x20;   │   ├── App.tsx

&#x20;   │   ├── App.css

&#x20;   │   ├── index.css

&#x20;   │   └── main.tsx

&#x20;   │

&#x20;   ├── package.json

&#x20;   └── ...

```



\## Getting Started



\### Prerequisites



\- Python 3.12 (tested environment)

\- Node.js and npm

\- Git



\### 1. Clone the Repository



```bash

git clone https://github.com/Shanthoshika-S/AEGISGATE.git

cd AEGISGATE

```



\### 2. Set Up the Backend



```bash

cd backend



python3 -m venv venv

source venv/bin/activate



pip install -r requirements.txt

```



Start the backend server:



```bash

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

```



The backend API will be available at:



\- API: http://localhost:8000

\- Interactive API documentation: http://localhost:8000/docs

\- Health check: http://localhost:8000/health



\### 3. Set Up the Frontend



Open another terminal:



```bash

cd AEGISGATE/frontend

npm install

npm run dev -- --host 0.0.0.0

```



Open the dashboard:



http://localhost:5173



Keep both development servers running while using the dashboard.



\## API Endpoints



| Method | Endpoint | Description |

|---|---|---|

| GET | `/` | Project information |

| GET | `/health` | Backend health check |

| POST | `/security/evaluate` | Evaluate a security request |

| POST | `/tools/execute` | Submit a tool execution request |

| POST | `/agent/run` | Run a task through the demonstration agent |

| GET | `/security/events` | Retrieve security audit events |

| GET | `/security/verify` | Verify audit hash-chain integrity |

| GET | `/security/anomalies` | Retrieve behavior analysis results |



\## Testing



AEGISGATE uses Pytest for backend testing.



From the backend directory, activate the virtual environment and run:



```bash

python -m pytest -v

```



The backend test suite has previously passed \*\*30 tests\*\*.



The tests cover the agent runner, audit logger, behavior analyzer, policy engine, security API, and tool gateway.



\## Current Limitations



AEGISGATE is an educational cybersecurity prototype and is not yet a production-ready security platform.



Current limitations include:



\- The demonstration agent uses deterministic rules rather than a real LLM.

\- Tool execution uses a simulated environment rather than unrestricted real-world tools.

\- A complete human approval workflow is not implemented.

\- Behavior analysis uses predefined rules rather than machine learning.

\- Authentication and production deployment hardening remain future improvements.

\- Legacy audit records created before hash-chain protection are excluded from cryptographic verification.



\## Future Improvements



\- Integrate a real LLM-powered agent.

\- Implement a human-in-the-loop approval workflow.

\- Improve agent behavior monitoring and anomaly detection.

\- Introduce authentication and role-based access control.

\- Expand tool monitoring and security policies.

\- Improve deployment security and production readiness.



\## Author



\*\*Shanthoshika S.\*\*



Third-Year Cyber Security Undergraduate

Sri Lanka Institute of Information Technology (SLIIT)



\## Repository



\[AEGISGATE on GitHub](https://github.com/Shanthoshika-S/AEGISGATE)



\---



\*AEGISGATE is an educational cybersecurity project exploring runtime security controls, policy enforcement, and digital forensics for AI agent systems.\*
