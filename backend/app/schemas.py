from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "security_analyst"
    full_name: str
    email: str

class AgentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    owner: str = Field(default="Security Team", max_length=100)
    model: str = Field(default="GPT-4o Enterprise", max_length=100)
    purpose: str = Field(default="General assistant", max_length=240)
    tools: List[str] = Field(default_factory=list)
    permissions: Optional[Dict[str, List[str]]] = None
    baseline_instructions: Optional[str] = None

class AgentUpdate(BaseModel):
    name: Optional[str] = None
    owner: Optional[str] = None
    model: Optional[str] = None
    purpose: Optional[str] = None
    tools: Optional[List[str]] = None
    permissions: Optional[Dict[str, List[str]]] = None
    current_instructions: Optional[str] = None

class AgentStatus(BaseModel):
    status: str

class ActionRequest(BaseModel):
    agent_id: str
    action: str = Field(min_length=2, max_length=40)
    target: str = Field(min_length=1, max_length=200)
    payload: str = Field(default="", max_length=20000)
    declared_intent: Optional[str] = None
    tool_id: Optional[str] = None

class ApprovalDecision(BaseModel):
    decision: str  # APPROVE or REJECT
    reason: Optional[str] = None

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    action: str
    target_pattern: str
    effect: str = "BLOCK"
    risk_threshold: int = 70
    priority: int = 10
    enabled: int = 1

class PolicyVersionDeploy(BaseModel):
    version: str
    policy_yaml: str
    change_summary: str

class CanaryCreate(BaseModel):
    token_type: str = "AWS_KEY"
    location_tag: str = "custom_env_var"

class DelegationRequest(BaseModel):
    source_agent_id: str
    target_agent_id: str
    task_intent: str
    hop_count: int = 1

class RedTeamRunRequest(BaseModel):
    scenario_id: str
    agent_id: str

class ReplayRequest(BaseModel):
    agent_id: str
    alternative_policy_mode: str = "STRICT"
