from datetime import datetime
from fastapi import HTTPException, status

from app.core.config import get_settings

settings = get_settings()


class RateLimitService:
    """
    Redis-backed fixed-window rate limiter.

    Key format:
    - rl:user:{user_id}:{window}
    - rl:api_key:{api_key_id}:{window}
    - rl:ip:{ip}:{window}
    """

    def __init__(self, redis):
        self.redis = redis

    async def check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return

        now = int(datetime.utcnow().timestamp())
        window = now // window_seconds
        redis_key = f"rl:{identifier}:{window}"

        current = await self.redis.incr(redis_key)

        if current == 1:
            await self.redis.expire(redis_key, window_seconds)

        if current > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )