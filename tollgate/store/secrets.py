import os


async def resolve_api_key(ref: str) -> str:
    """
    TODO: AWS Secrets Manager via boto3, with an in-process cache.
    Never log the resolved value. Never put upstream keys in plain env vars on
    Fargate — use ECS task-definition secrets or a Secrets Manager lookup.
    """
    if ref.startswith("secretsmanager:"):
        raise NotImplementedError("TODO: Secrets Manager lookup")
    return os.environ.get("UPSTREAM_API_KEY", "")
