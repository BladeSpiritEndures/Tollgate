import os

from tollgate.models import Channel, Classification


async def load_channels() -> list[Channel]:
    """
    TODO: replace with DynamoDB (boto3 — you used it in CITS5503 Lab 3).
    Table `tollgate-channels`, PK `channel_id`. Cache in-process with a short
    TTL — this is on the hot path for every request.
    """
    fake_upstream = os.getenv("TOLLGATE_UPSTREAM_BASE_URL")
    channels = [
        Channel(
            id="bedrock-syd",
            name="Bedrock ap-southeast-2",
            adaptor="bedrock",
            base_url=fake_upstream or "https://bedrock-runtime.ap-southeast-2.amazonaws.com",
            api_key_ref="sigv4",
            priority=100,
            residency="ap-southeast-2",
            max_classification=Classification.RESTRICTED,
            zero_retention=True,
        ),
        Channel(
            id="openai-us",
            name="OpenAI",
            adaptor="openai",
            base_url="https://api.openai.com/v1",
            api_key_ref="secretsmanager:tollgate/openai",
            models=["gpt-4o", "gpt-4o-mini"],
            priority=50,
            residency="us",
            max_classification=Classification.INTERNAL,
            zero_retention=False,
        ),
    ]
    return channels[:1] if fake_upstream else channels
