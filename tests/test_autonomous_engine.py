import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from recon_cli.engine.hypothesis import Hypothesis, HypothesisType, Observation, EvidenceLevel
from recon_cli.engine.planner import Planner
from recon_cli.engine.executor import Executor
from recon_cli.engine.judge import Judge
from recon_cli.pipeline.context import PipelineContext, TargetGraph
from recon_cli.utils.async_http import HTTPResponse

@pytest.fixture
def mock_context():
    mock = MagicMock(spec=PipelineContext)
    mock.target_graph = TargetGraph()
    mock.logger = MagicMock()
    mock._auth_manager = MagicMock()
    return mock

def test_planner_generates_idor_hypothesis(mock_context):
    planner = Planner(mock_context)
    
    # Setup Target Graph
    mock_context.target_graph.add_entity("object_id", "123", host="api.example.com")
    mock_context.target_graph.add_entity("api_endpoint", "get:https://api.example.com/users/{id}", 
                                       url="https://api.example.com/users/{id}", host="api.example.com")
    
    hypotheses = planner.generate_hypotheses()
    
    assert len(hypotheses) >= 1
    idor_hyp = next(h for h in hypotheses if h.type == HypothesisType.IDOR)
    assert idor_hyp.target_url == "https://api.example.com/users/123"
    assert idor_hyp.priority > 0

@pytest.mark.asyncio
async def test_executor_collects_observations(mock_context):
    executor = Executor(mock_context)
    hyp = Hypothesis(type=HypothesisType.IDOR, target_url="https://api.example.com/users/123", priority=0.8)
    
    # Mock identities
    mock_context._auth_manager.get_identities_by_role.return_value = []
    mock_context._auth_manager.get_all_identities.return_value = []

    mock_response = HTTPResponse(url=hyp.target_url, status=200, headers={}, body="user data", elapsed=0.1)
    
    with patch("recon_cli.utils.async_http.AsyncHTTPClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        observations = await executor.execute(hyp)
        
    assert len(observations) >= 1
    assert observations[0].body == "user data"
    assert observations[0].status == 200

def test_judge_confirms_idor():
    judge = Judge()
    hyp = Hypothesis(type=HypothesisType.IDOR, target_url="https://api.example.com/users/123", priority=0.8)
    
    observations = [
        Observation(url=hyp.target_url, method="GET", status=200, headers={}, body="secret data", identity_id="admin"),
        Observation(url=hyp.target_url, method="GET", status=200, headers={}, body="secret data", identity_id="user")
    ]
    
    result = judge.evaluate(hyp, observations)
    
    assert result.level == EvidenceLevel.CONFIRMED
    assert result.confidence >= 0.7
    assert "user" in result.finding_data["role_or_identity_used"]
